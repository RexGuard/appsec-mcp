"""Runs a scan end to end: walk, scanners in parallel, normalise, diff, map, persist."""

import logging
import threading
import time
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from appsec_mcp.errors import AppSecError, ErrorCode, ScannerError
from appsec_mcp.mapper.builder import build_map
from appsec_mcp.models.finding import NormalizedFinding
from appsec_mcp.models.ledger import RuleApplied
from appsec_mcp.models.scan import ScannerRun, ScanRequest, ScanResult, SkippedScanner
from appsec_mcp.scan.ledger import LedgerCollector
from appsec_mcp.scan.walker import SourceFile, walk
from appsec_mcp.scanners.base import AdapterResult, ScannerAdapter
from appsec_mcp.scanners.normalize import normalize
from appsec_mcp.scoring import count_severities, score
from appsec_mcp.security.paths import resolve_scan_root
from appsec_mcp.services.repositories import Repositories
from appsec_mcp.storage.finding_repo import FindingRow

logger = logging.getLogger(__name__)

_BYTES_PER_KB = 1024


@dataclass
class _AdapterOutcome:
    name: str
    result: AdapterResult | None = None
    run: ScannerRun | None = None
    skipped: SkippedScanner | None = None
    failed: bool = False


@dataclass
class _ScanOutputs:
    findings: list[NormalizedFinding] = field(default_factory=list)
    rules: list[RuleApplied] = field(default_factory=list)
    runs: list[ScannerRun] = field(default_factory=list)
    skipped: list[SkippedScanner] = field(default_factory=list)
    partial: bool = False


class ScanService:
    """Orchestrates scans. One scan per root at a time."""

    def __init__(self, repos: Repositories, adapters: Sequence[ScannerAdapter]) -> None:
        self._repos = repos
        self._adapters = list(adapters)
        self._active: set[Path] = set()
        self._lock = threading.Lock()

    @contextmanager
    def _guard(self, root: Path) -> Iterator[None]:
        with self._lock:
            if root in self._active:
                raise AppSecError(
                    ErrorCode.SCAN_IN_PROGRESS,
                    f"A scan of '{root}' is already running. Try again when it ends.",
                )
            self._active.add(root)
        try:
            yield
        finally:
            with self._lock:
                self._active.discard(root)

    def scan(self, request: ScanRequest) -> ScanResult:
        """Scan a folder and return a compact summary."""
        root = resolve_scan_root(request.path)
        with self._guard(root):
            return self._scan(root, request)

    def _scan(self, root: Path, request: ScanRequest) -> ScanResult:
        started = time.perf_counter()
        project = self._repos.projects.get_or_create(str(root), root.name)
        scan_id = self._repos.scans.create(project.id)
        try:
            ledger = LedgerCollector().consume(walk(root, request.max_file_kb * _BYTES_PER_KB))
            self._repos.scans.add_files(scan_id, ledger.entries)
            outputs = self._run_adapters(root, ledger.sources, request.scanners)
            new, fixed_rows = self._diff(project.id, scan_id, outputs.findings)
            graph = build_map(project.name, ledger.sources, outputs.findings)
            self._repos.findings.add_many(scan_id, [*outputs.findings, *fixed_rows])
            self._repos.scans.add_rules(scan_id, outputs.rules)
            self._repos.maps.save(scan_id, graph)
        except (AppSecError, OSError, ValueError) as exc:
            logger.exception("Scan %d failed", scan_id)
            self._repos.scans.finish(scan_id, "failed", None, {"error": str(exc)})
            raise
        counts = count_severities(f.severity for f in outputs.findings)
        result = ScanResult(
            scan_id=scan_id,
            project=project.name,
            status="partial" if outputs.partial else "completed",
            score=score(counts),
            counts=counts,
            new=new,
            fixed=len(fixed_rows),
            scanners_run=[r.name for r in outputs.runs],
            scanners_skipped=outputs.skipped,
            files_read=ledger.read_count,
            files_skipped=ledger.skipped_count,
            duration_s=round(time.perf_counter() - started, 3),
        )
        summary = result.model_dump(exclude={"scan_id", "project", "status", "score"})
        summary["scanner_runs"] = [r.model_dump() for r in outputs.runs]
        self._repos.scans.finish(scan_id, result.status, result.score, summary)
        logger.info("Scan %d of %s finished: score %d", scan_id, root, result.score)
        return result

    def _selected(self, names: Sequence[str] | None) -> list[ScannerAdapter]:
        if not names:
            return self._adapters
        return [a for a in self._adapters if a.name in set(names)]

    def _run_adapters(
        self, root: Path, sources: list[SourceFile], names: Sequence[str] | None
    ) -> _ScanOutputs:
        adapters = self._selected(names)
        outputs = _ScanOutputs()
        if not adapters:
            return outputs
        with ThreadPoolExecutor(max_workers=len(adapters)) as pool:
            outcomes = list(pool.map(lambda a: _run_one(a, root, sources), adapters))
        raw = []
        for outcome in outcomes:
            if outcome.skipped:
                outputs.skipped.append(outcome.skipped)
            outputs.partial = outputs.partial or outcome.failed
            if outcome.result and outcome.run:
                raw.extend(outcome.result.findings)
                outputs.rules.extend(outcome.result.rules)
                outputs.runs.append(outcome.run)
        outputs.findings = normalize(raw)
        return outputs

    def _diff(
        self, project_id: int, scan_id: int, findings: list[NormalizedFinding]
    ) -> tuple[int, list[NormalizedFinding]]:
        """Mark findings new/existing and return (new count, findings now fixed)."""
        previous = self._repos.scans.previous_completed(project_id, scan_id)
        if previous is None:
            return len(findings), []
        old = {r.fingerprint: r for r in self._repos.findings.for_scan(previous.id)}
        current = set()
        new = 0
        for index, finding in enumerate(findings):
            current.add(finding.fingerprint)
            status = "existing" if finding.fingerprint in old else "new"
            new += status == "new"
            findings[index] = finding.model_copy(update={"status": status})
        fixed = [_as_fixed(row) for fp, row in old.items() if fp not in current]
        return new, fixed


def _run_one(adapter: ScannerAdapter, root: Path, sources: list[SourceFile]) -> _AdapterOutcome:
    if not adapter.is_available():
        reason = f"{adapter.name} is not installed on this machine."
        return _AdapterOutcome(
            adapter.name,
            skipped=SkippedScanner(
                name=adapter.name, reason=reason, install_hint=adapter.install_hint
            ),
        )
    started = time.perf_counter()
    try:
        result = adapter.run(root, sources)
    except (ScannerError, OSError, ValueError, ValidationError) as exc:
        logger.error("Scanner %s failed: %s", adapter.name, exc)
        return _AdapterOutcome(
            adapter.name,
            failed=True,
            skipped=SkippedScanner(
                name=adapter.name,
                reason=f"{adapter.name} failed: {exc}",
                install_hint=adapter.install_hint,
            ),
        )
    run = ScannerRun(
        name=adapter.name,
        version=adapter.version(),
        duration_s=round(time.perf_counter() - started, 3),
        findings=len(result.findings),
    )
    return _AdapterOutcome(adapter.name, result=result, run=run)


def _as_fixed(row: FindingRow) -> NormalizedFinding:
    return NormalizedFinding(
        fingerprint=row.fingerprint,
        scanner=row.scanner,
        rule_id=row.rule_id,  # type: ignore[arg-type]
        severity=row.severity,
        cwe=row.cwe,
        rel_path=row.rel_path,  # type: ignore[arg-type]
        line_start=row.line_start,
        line_end=row.line_end,
        snippet_redacted=row.snippet_redacted,
        title=row.title,
        plain_explanation=row.plain_explanation,
        fix_hint=row.fix_hint,
        fix_kind=None,
        status="fixed",
    )

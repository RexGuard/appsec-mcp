"""Read-only queries over stored scans: findings, explanations, map, ledger, history."""

from pathlib import Path

from appsec_mcp.analysis.chains import build_chains
from appsec_mcp.errors import ErrorCode, NotFoundError
from appsec_mcp.explain.templates import load_catalog, truncate_words
from appsec_mcp.mapper.builder import summarize
from appsec_mcp.models.chain import AttackChainList
from appsec_mcp.models.finding import FindingDetail, FindingItem, FindingList
from appsec_mcp.models.ledger import Ledger, LedgerFiles
from appsec_mcp.models.scan import ScanList, ScannerRun, ScanSummary, SeverityCounts, SkippedScanner
from appsec_mcp.models.system_map import SystemGraph, SystemSummary
from appsec_mcp.services.repositories import Repositories
from appsec_mcp.storage.finding_repo import FindingRow
from appsec_mcp.storage.scan_repo import ScanRow


def _summary(row: ScanRow) -> ScanSummary:
    counts = row.summary.get("counts") or {}
    return ScanSummary(
        scan_id=row.id,
        project=row.project_name,
        root_path=row.root_path,
        started_at=row.started_at,
        status=row.status,  # type: ignore[arg-type]
        score=row.score,
        counts=SeverityCounts(**counts),
    )


def _item(row: FindingRow) -> FindingItem:
    return FindingItem(
        id=row.id,
        severity=row.severity,
        title=row.title,
        rel_path=row.rel_path,  # type: ignore[arg-type]
        line_start=row.line_start,
        plain_explanation=row.plain_explanation,
        patchable=row.patchable and row.status != "fixed",
        status=row.status,  # type: ignore[arg-type]
        scanner=row.scanner,
        cwe=row.cwe,  # type: ignore[arg-type]
        evidence_tier=row.evidence_tier,  # type: ignore[arg-type]
    )


class QueryService:
    """Answers the read-only MCP tools and the viewer API."""

    def __init__(self, repos: Repositories) -> None:
        self._repos = repos

    def scan_row(self, scan_id: int) -> ScanRow:
        """Return a scan or raise SCAN_NOT_FOUND."""
        row = self._repos.scans.get(scan_id)
        if row is None:
            raise NotFoundError(ErrorCode.SCAN_NOT_FOUND, f"There is no scan with id {scan_id}.")
        return row

    def finding_row(self, finding_id: int) -> FindingRow:
        """Return a finding or raise FINDING_NOT_FOUND."""
        row = self._repos.findings.get(finding_id)
        if row is None:
            raise NotFoundError(
                ErrorCode.FINDING_NOT_FOUND, f"There is no finding with id {finding_id}."
            )
        return row

    def scan_summary(self, scan_id: int) -> ScanSummary:
        """One scan's summary."""
        return _summary(self.scan_row(scan_id))

    def list_scans(self, project_path: str | None, limit: int) -> ScanList:
        """Newest scans first, optionally filtered to one project folder."""
        project_id = None
        if project_path:
            project = self._repos.projects.find_by_path(str(Path(project_path).resolve()))
            if project is None:
                return ScanList(items=[])
            project_id = project.id
        return ScanList(
            items=[_summary(r) for r in self._repos.scans.list_recent(project_id, limit)]
        )

    def findings(
        self, scan_id: int, min_severity: str, limit: int, offset: int, include_fixed: bool = False
    ) -> FindingList:
        """A page of findings, worst first."""
        self.scan_row(scan_id)
        total, rows = self._repos.findings.page(scan_id, min_severity, include_fixed, limit, offset)
        return FindingList(total=total, items=[_item(r) for r in rows])

    def explain(self, finding_id: int) -> FindingDetail:
        """Full plain-language explanation of one finding."""
        row = self.finding_row(finding_id)
        catalog = load_catalog()
        entry = catalog.get(row.cwe or "", catalog["default"])
        return FindingDetail(
            id=row.id,
            title=row.title,
            severity=row.severity,
            cwe=row.cwe,  # type: ignore[arg-type]
            rel_path=row.rel_path,
            line_start=row.line_start,
            scanner=row.scanner,  # type: ignore[arg-type]
            rule_id=row.rule_id,
            what=truncate_words(row.plain_explanation),
            why_it_matters=entry.why,
            how_to_fix=row.fix_hint or entry.fix,
            snippet_redacted=row.snippet_redacted,
            patchable=row.patchable and row.status != "fixed",
            references=list(entry.references),
            evidence_tier=row.evidence_tier,  # type: ignore[arg-type]
            reported_severity=row.reported_severity,  # type: ignore[arg-type]
            evidence=row.evidence,
        )

    def graph(self, scan_id: int) -> SystemGraph:
        """The full system map."""
        self.scan_row(scan_id)
        return self._repos.maps.load(scan_id)

    def attack_chains(self, scan_id: int) -> AttackChainList:
        """Attack paths that link entry points, findings and the assets they reach."""
        graph = self.graph(scan_id)
        chains = build_chains(graph, self._repos.findings.for_scan(scan_id))
        return AttackChainList(total=len(chains), items=chains)

    def map_summary(self, scan_id: int) -> SystemSummary:
        """The system map as lists."""
        return summarize(self.graph(scan_id))

    def ledger(self, scan_id: int, section: str, limit: int, offset: int) -> Ledger:
        """What was read, skipped and applied in a scan."""
        row = self.scan_row(scan_id)
        files = None
        rules = None
        if section in ("files", "all"):
            read, skipped = self._repos.scans.file_counts(scan_id)
            files = LedgerFiles(
                read=read, skipped=skipped, items=self._repos.scans.files(scan_id, limit, offset)
            )
        if section in ("rules", "all"):
            rules = self._repos.scans.rules(scan_id)
        runs = [ScannerRun(**r) for r in row.summary.get("scanner_runs", [])]
        skipped_scanners = [SkippedScanner(**s) for s in row.summary.get("scanners_skipped", [])]
        return Ledger(files=files, rules=rules, scanners=runs, scanners_skipped=skipped_scanners)

"""The evidence gate: severity is decided by code from the evidence, not by a scanner's guess.

Every finding gets an evidence tier, weakest first:

- ``pattern``: one heuristic (regex or rule) matched, nothing else backs it up.
- ``reachable``: the match sits in a file that serves routes or is an entry point, so outside
  input can plausibly reach it.
- ``corroborated``: two or more independent scanners flagged the same file, line and CWE.
- ``confirmed``: a precise detector reported a fact (a known-vulnerable package version, a
  provider-format secret, a committed ``.env``), which needs no further proof.

In precision mode (the default) the gate then caps severity:

- ``critical`` needs at least ``reachable``; a bare pattern match is demoted to ``high``.
- Anything below ``confirmed`` that lives only in test, example or fixture code is capped at
  ``low``, because it does not ship.

The scanner's own severity is kept in ``reported_severity`` and every decision is written to
``evidence`` in plain language, so a user can always see why a finding is ranked where it is.
"""

import os
import re
from collections.abc import Iterable, Sequence
from pathlib import PurePosixPath

from appsec_mcp.models.base import EVIDENCE_RANK, SEVERITY_RANK, EvidenceTier, Severity
from appsec_mcp.models.finding import NormalizedFinding
from appsec_mcp.models.system_map import SystemGraph

PRECISION_ENV_VAR = "APPSEC_MCP_PRECISION"

_CONFIRMED_SCANNERS = frozenset({"gitleaks", "osv"})
_CONFIRMED_BUILTIN_RULES = frozenset({"builtin.config.env-committed"})
_PROVIDER_SECRET_PREFIX = "builtin.secret."  # noqa: S105 - a rule id prefix, not a secret
_GENERIC_SECRET_RULE = "builtin.secret.generic-assignment"  # noqa: S105 - a rule id, not a secret
_MAX_ROUTES_LISTED = 3

_TEST_DIRS = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "fixtures", "examples", "example", "e2e"}
)
_TEST_FILE = re.compile(r"(?:^test_.*\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[cm]?[jt]sx?$)")


def precision_mode_enabled() -> bool:
    """Precision mode is on unless APPSEC_MCP_PRECISION is set to 0, false or off."""
    value = os.environ.get(PRECISION_ENV_VAR, "1").strip().lower()
    return value not in {"0", "false", "off", "no"}


def is_test_code(rel_path: str | None) -> bool:
    """True for files under test/example/fixture folders or named like tests."""
    if not rel_path:
        return False
    path = PurePosixPath(rel_path)
    if any(part.lower() in _TEST_DIRS for part in path.parts[:-1]):
        return True
    return bool(_TEST_FILE.search(path.name))


def exposed_files(graph: SystemGraph) -> dict[str, list[str]]:
    """Map each file that serves routes or is an entry point to what it exposes."""
    exposed: dict[str, list[str]] = {}
    for node in graph.nodes:
        if node.kind in ("route", "entry_point") and node.rel_path:
            label = node.label if node.kind == "route" else "entry point"
            exposed.setdefault(node.rel_path, []).append(label)
    return exposed


def _is_confirmed(finding: NormalizedFinding) -> bool:
    if finding.scanner in _CONFIRMED_SCANNERS or finding.rule_id in _CONFIRMED_BUILTIN_RULES:
        return True
    return (
        finding.rule_id.startswith(_PROVIDER_SECRET_PREFIX)
        and finding.rule_id != _GENERIC_SECRET_RULE
    )


def _assess(
    finding: NormalizedFinding, exposed: dict[str, list[str]]
) -> tuple[EvidenceTier, list[str]]:
    """Pick the strongest tier the evidence supports and say why."""
    reasons: list[str] = []
    sources = sorted(set(finding.sources) or {finding.scanner})
    tier: EvidenceTier = "pattern"
    if _is_confirmed(finding):
        tier = "confirmed"
        reasons.append(
            f"Confirmed: {finding.scanner} reports this as a precise match, not a guess."
        )
    if len(sources) >= 2:
        tier = tier if tier == "confirmed" else "corroborated"
        reasons.append(f"Corroborated: {' and '.join(sources)} each found this independently.")
    routes = exposed.get(finding.rel_path or "")
    if routes:
        if EVIDENCE_RANK[tier] < EVIDENCE_RANK["reachable"]:
            tier = "reachable"
        shown = ", ".join(routes[:_MAX_ROUTES_LISTED])
        more = len(routes) - _MAX_ROUTES_LISTED
        reasons.append(
            f"Reachable: this file handles outside input ({shown}"
            + (f" and {more} more" if more > 0 else "")
            + ")."
        )
    if tier == "pattern":
        reasons.append(f"Pattern only: one {finding.scanner} rule matched; nothing else backs it.")
    return tier, reasons


def _cap(severity: Severity, ceiling: Severity) -> Severity:
    return ceiling if SEVERITY_RANK[severity] > SEVERITY_RANK[ceiling] else severity


def _gated_severity(finding: NormalizedFinding, tier: EvidenceTier, reasons: list[str]) -> Severity:
    severity: Severity = finding.severity
    if severity == "critical" and EVIDENCE_RANK[tier] < EVIDENCE_RANK["reachable"]:
        severity = "high"
        reasons.append(
            "Ranked high, not critical: critical needs more than a single pattern match "
            "(a reachable file, a second scanner, or a precise detector)."
        )
    if tier != "confirmed" and is_test_code(finding.rel_path):
        capped = _cap(severity, "low")
        if capped != severity:
            reasons.append("Ranked low: this code is only in tests, examples or fixtures.")
        severity = capped
    return severity


def apply_gate(
    findings: Iterable[NormalizedFinding], graph: SystemGraph, precision: bool | None = None
) -> list[NormalizedFinding]:
    """Return the findings with evidence tiers set and, in precision mode, severities gated."""
    precise = precision_mode_enabled() if precision is None else precision
    exposed = exposed_files(graph)
    gated: list[NormalizedFinding] = []
    for finding in findings:
        tier, reasons = _assess(finding, exposed)
        severity = _gated_severity(finding, tier, reasons) if precise else finding.severity
        gated.append(
            finding.model_copy(
                update={
                    "evidence_tier": tier,
                    "evidence": reasons,
                    "severity": severity,
                    "reported_severity": finding.severity if severity != finding.severity else None,
                }
            )
        )
    return gated


def gate_summary(findings: Sequence[NormalizedFinding]) -> dict[str, int]:
    """How many findings sit in each tier and how many the gate demoted."""
    summary = dict.fromkeys(EVIDENCE_RANK, 0)
    for finding in findings:
        summary[finding.evidence_tier] += 1
    summary["demoted"] = sum(1 for f in findings if f.reported_severity is not None)
    return summary

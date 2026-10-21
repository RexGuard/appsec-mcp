"""Attack chains: link findings to the system map so the user sees whole attack paths.

Single findings say "this line is risky". A chain says "a request to GET /users/:id reaches this
SQL injection, which talks to MySQL". Chains are built from facts already stored for a scan (the
map and the gated findings), so they cost no extra scanning.

A chain is only as strong as its weakest link. Its confidence comes from the evidence tiers of
its findings, and a chain that is only a hypothesis is capped at medium severity: putting two
unproven guesses side by side does not make a critical.
"""

from collections import defaultdict
from collections.abc import Sequence

from appsec_mcp.mapper.builder import component_of
from appsec_mcp.models.base import EVIDENCE_RANK, SEVERITY_RANK, Severity
from appsec_mcp.models.chain import AttackChain, ChainConfidence, ChainKind, ChainStep
from appsec_mcp.models.system_map import SystemGraph
from appsec_mcp.storage.finding_repo import FindingRow

MAX_CHAINS = 50
_MAX_ENTRIES_PER_CHAIN = 3
_CONFIDENCE_RANK = {"hypothesis": 0, "likely": 1, "verified": 2}

_SECRET_CWES = frozenset({"CWE-798"})
_HEADERS_CWE = "CWE-693"
# What each injection class lets an attacker reach. None means "the stores/services the code
# talks to", taken from the map.
_INJECTION_IMPACT: dict[str, str | None] = {
    "CWE-89": None,
    "CWE-918": None,
    "CWE-78": "Commands run on the server as the app",
    "CWE-94": "Code run on the server as the app",
    "CWE-95": "Code run on the server as the app",
    "CWE-502": "Code run on the server as the app",
    "CWE-22": "Files on the server",
    "CWE-611": "Files on the server",
    "CWE-79": "Your users' browsers and sessions",
    "CWE-120": "Memory of the running program",
    "CWE-134": "Memory of the running program",
}
_GENERIC_SECRET_WORDS = frozenset(
    {"generic", "secret", "private", "key", "token", "api", "access", "assignment", "password"}
)


class _MapIndex:
    """Fast lookups over a scan's map."""

    def __init__(self, graph: SystemGraph) -> None:
        by_id = {n.id: n for n in graph.nodes}
        self.entries: dict[str, list[str]] = defaultdict(list)
        self.stores: dict[str, set[str]] = defaultdict(set)
        self.services: dict[str, set[str]] = defaultdict(set)
        for node in graph.nodes:
            if node.kind == "route" and node.rel_path:
                self.entries[node.rel_path].append(node.label)
            elif node.kind == "entry_point" and node.rel_path:
                self.entries[node.rel_path].append(f"Program start ({node.rel_path})")
        for edge in graph.edges:
            source, target = by_id.get(edge.source), by_id.get(edge.target)
            if source is None or target is None or source.kind != "component":
                continue
            if target.kind == "data_store":
                self.stores[source.label].add(target.label)
            elif target.kind == "external_service":
                self.services[source.label].add(target.label)
        self.all_routes = sorted({r for routes in self.entries.values() for r in routes})


def _confidence(findings: Sequence[FindingRow]) -> ChainConfidence:
    weakest = min(EVIDENCE_RANK[f.evidence_tier] for f in findings)
    if weakest >= EVIDENCE_RANK["corroborated"]:
        return "verified"
    if weakest >= EVIDENCE_RANK["reachable"]:
        return "likely"
    return "hypothesis"


def _chain_severity(findings: Sequence[FindingRow], confidence: ChainConfidence) -> Severity:
    worst: Severity = max(findings, key=lambda f: SEVERITY_RANK[f.severity]).severity  # type: ignore[assignment]
    if confidence == "hypothesis" and SEVERITY_RANK[worst] > SEVERITY_RANK["medium"]:
        return "medium"
    return worst


def _weakness(finding: FindingRow) -> ChainStep:
    where = f"{finding.rel_path}:{finding.line_start}" if finding.line_start else finding.rel_path
    return ChainStep(
        kind="weakness",
        label=f"{finding.title} ({where})" if where else finding.title,
        rel_path=finding.rel_path,
        finding_id=finding.id,
        evidence_tier=finding.evidence_tier,  # type: ignore[arg-type]
    )


def _entries(labels: Sequence[str], rel_path: str | None) -> list[ChainStep]:
    shown = list(labels[:_MAX_ENTRIES_PER_CHAIN])
    if len(labels) > _MAX_ENTRIES_PER_CHAIN:
        shown[-1] += f" (+{len(labels) - _MAX_ENTRIES_PER_CHAIN} more)"
    return [ChainStep(kind="entry", label=label, rel_path=rel_path) for label in shown]


def _injection_chains(
    findings: Sequence[FindingRow], index: _MapIndex, headers_missing: FindingRow | None
) -> list[tuple[ChainKind, list[FindingRow], list[ChainStep], str]]:
    chains = []
    for finding in findings:
        if finding.cwe not in _INJECTION_IMPACT or not finding.rel_path:
            continue
        entries = index.entries.get(finding.rel_path)
        if not entries:
            continue
        component = component_of(finding.rel_path)
        impact = _INJECTION_IMPACT[finding.cwe]
        if impact is None:
            targets = (
                index.stores[component] if finding.cwe == "CWE-89" else index.services[component]
            )
            impact = ", ".join(sorted(targets)) or (
                "The database" if finding.cwe == "CWE-89" else "Internal network services"
            )
        used = [finding]
        steps = [*_entries(entries, finding.rel_path), _weakness(finding)]
        if finding.cwe == "CWE-79" and headers_missing is not None:
            used.append(headers_missing)
            steps.append(_weakness(headers_missing))
        steps.append(ChainStep(kind="asset", label=impact))
        narrative = (
            f"Outside input arrives through {entries[0]} in {finding.rel_path}, where "
            f"{finding.title.lower()} lets an attacker reach: {impact}."
        )
        if len(used) > 1:
            narrative += " No security headers (such as a Content-Security-Policy) limit it."
        chains.append(("input_to_injection", used, steps, narrative))
    return chains


def _provider(rule_id: str) -> str | None:
    words = rule_id.split(".")[-1].replace("_", "-").split("-")
    named = [w for w in words if len(w) >= 3 and w.lower() not in _GENERIC_SECRET_WORDS]
    return named[0].lower() if named else None


def _secret_chains(
    findings: Sequence[FindingRow], index: _MapIndex
) -> list[tuple[ChainKind, list[FindingRow], list[ChainStep], str]]:
    chains = []
    for finding in findings:
        if finding.cwe not in _SECRET_CWES or not finding.rel_path:
            continue
        services = sorted(index.services[component_of(finding.rel_path)])
        if not services:
            continue
        provider = _provider(finding.rule_id)
        matching = [s for s in services if provider and provider in s.lower()]
        targets = matching or services
        steps = [
            ChainStep(kind="entry", label="Anyone who can read the code or its history"),
            _weakness(finding),
            *[ChainStep(kind="asset", label=service) for service in targets],
        ]
        narrative = (
            f"The key in {finding.rel_path} is in plain text, and the same code calls "
            f"{', '.join(targets)}. Whoever sees the code can use the key as your app."
        )
        chains.append(("secret_to_service", [finding], steps, narrative))
    return chains


def _dependency_chains(
    findings: Sequence[FindingRow], index: _MapIndex
) -> list[tuple[ChainKind, list[FindingRow], list[ChainStep], str]]:
    if not index.all_routes:
        return []
    chains = []
    for finding in findings:
        if finding.scanner != "osv" or SEVERITY_RANK[finding.severity] < SEVERITY_RANK["high"]:
            continue
        steps = [
            *_entries(index.all_routes, None),
            _weakness(finding),
            ChainStep(kind="asset", label="Whatever the vulnerable package can touch"),
        ]
        narrative = (
            f"The app serves {len(index.all_routes)} route(s) and ships "
            f"{finding.snippet_redacted.strip() or 'a package'} with a known vulnerability. "
            "Whether a request reaches the vulnerable code is not proven."
        )
        chains.append(("vulnerable_dependency", [finding], steps, narrative))
    return chains


def build_chains(graph: SystemGraph, findings: Sequence[FindingRow]) -> list[AttackChain]:
    """Every attack chain for one scan, worst and most certain first."""
    open_findings = [f for f in findings if f.status != "fixed"]
    index = _MapIndex(graph)
    headers_missing = next((f for f in open_findings if f.cwe == _HEADERS_CWE), None)
    raw = [
        *_injection_chains(open_findings, index, headers_missing),
        *_secret_chains(open_findings, index),
        *_dependency_chains(open_findings, index),
    ]
    chains = []
    for kind, used, steps, narrative in raw:
        confidence = _confidence(used)
        if kind == "secret_to_service" and confidence == "verified":
            # The link from key to service is inferred from the code layout, not proven.
            provider = _provider(used[0].rule_id)
            if not (provider and any(provider in s.label.lower() for s in steps[2:])):
                confidence = "likely"
        if kind == "vulnerable_dependency":
            confidence = "hypothesis"
        lead = used[0]
        chains.append(
            AttackChain(
                id=1,
                kind=kind,
                title=f"{lead.title} reachable from outside"
                if kind != "secret_to_service"
                else f"Leaked key gives access to {steps[-1].label}",
                severity=_chain_severity(used, confidence),
                confidence=confidence,
                narrative=narrative,
                steps=steps,
            )
        )
    chains.sort(key=lambda c: (-SEVERITY_RANK[c.severity], -_CONFIDENCE_RANK[c.confidence]))
    return [c.model_copy(update={"id": i}) for i, c in enumerate(chains[:MAX_CHAINS], start=1)]

"""Builds the system map (nodes and edges) from file facts and findings."""

import logging
from collections import Counter
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Any

from appsec_mcp.mapper.extractors import extractor_for
from appsec_mcp.mapper.facts import FileFacts
from appsec_mcp.models.finding import NormalizedFinding
from appsec_mcp.models.system_map import (
    EdgeKind,
    Hotspot,
    MapEdge,
    MapNode,
    NodeKind,
    SystemGraph,
    SystemSummary,
)
from appsec_mcp.scan.language import SOURCE_LANGUAGES
from appsec_mcp.scan.walker import SourceFile

logger = logging.getLogger(__name__)

MAX_DEPENDENCY_NODES = 1000
MAX_HOTSPOTS = 10
_ROOT_LABEL = "(project root)"
_SECRET_CWES = frozenset({"CWE-798", "CWE-538"})


def _component_of(rel_path: str) -> str:
    parent = PurePosixPath(rel_path).parent.as_posix()
    return _ROOT_LABEL if parent == "." else parent


class _GraphBuilder:
    """Deduplicating node/edge accumulator."""

    def __init__(self) -> None:
        self.nodes: dict[tuple[str, str], MapNode] = {}
        self.edges: set[tuple[int, int, str]] = set()

    def node(
        self,
        kind: NodeKind,
        label: str,
        rel_path: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> int:
        key = (kind, label)
        existing = self.nodes.get(key)
        if existing is None:
            existing = MapNode(
                id=len(self.nodes) + 1, kind=kind, label=label, rel_path=rel_path, meta=meta or {}
            )
            self.nodes[key] = existing
        return existing.id

    def edge(self, source: int, target: int, kind: EdgeKind) -> None:
        if source != target:
            self.edges.add((source, target, kind))


def build_map(
    project_name: str, sources: Sequence[SourceFile], findings: Sequence[NormalizedFinding]
) -> SystemGraph:
    """Build the map in one pass over files (O(files + findings))."""
    graph = _GraphBuilder()
    root_id = graph.node("component", _ROOT_LABEL, None, {"project": project_name})
    dependency_count = 0
    for source in sources:
        extractor = extractor_for(source)
        facts = extractor(source) if extractor else FileFacts()
        component = _component_of(source.rel_path)
        if facts.is_empty() and source.language not in SOURCE_LANGUAGES:
            continue
        comp_id = graph.node(
            "component", component, None if component == _ROOT_LABEL else component
        )
        if comp_id != root_id:
            graph.edge(root_id, comp_id, "imports")
        dependency_count = _add_facts(graph, comp_id, source, facts, dependency_count)
    _add_secrets(graph, findings)
    _attach_counts(graph, findings)
    nodes = sorted(graph.nodes.values(), key=lambda n: n.id)
    edges = [MapEdge(source=s, target=t, kind=k) for s, t, k in sorted(graph.edges)]  # type: ignore[arg-type]
    return SystemGraph(nodes=nodes, edges=edges)


def _add_facts(
    graph: _GraphBuilder, comp_id: int, source: SourceFile, facts: FileFacts, dependency_count: int
) -> int:
    if facts.entry_point:
        entry_id = graph.node(
            "entry_point", source.rel_path, source.rel_path, {"reason": facts.entry_point}
        )
        graph.edge(entry_id, comp_id, "calls")
    for route in facts.routes:
        route_id = graph.node(
            "route", route, source.rel_path, {"frameworks": sorted(facts.frameworks)}
        )
        graph.edge(comp_id, route_id, "handles")
    for store in sorted(facts.data_stores):
        graph.edge(comp_id, graph.node("data_store", store), "reads")
    for service in sorted(facts.external_services):
        graph.edge(comp_id, graph.node("external_service", service), "calls")
    for dependency in facts.dependencies:
        if dependency_count >= MAX_DEPENDENCY_NODES:
            logger.info("Dependency node cap reached; remaining dependencies are not mapped")
            break
        dep_id = graph.node("dependency", dependency, source.rel_path)
        graph.edge(comp_id, dep_id, "depends_on")
        dependency_count += 1
    return dependency_count


def _add_secrets(graph: _GraphBuilder, findings: Sequence[NormalizedFinding]) -> None:
    for finding in findings:
        if finding.cwe in _SECRET_CWES and finding.rel_path and finding.status != "fixed":
            label = f"{finding.rel_path}:{finding.line_start or 1}"
            secret_id = graph.node("secret", label, finding.rel_path, {"title": finding.title})
            comp_id = graph.node(
                "component", _component_of(finding.rel_path), _component_of(finding.rel_path)
            )
            graph.edge(comp_id, secret_id, "reads")


def _attach_counts(graph: _GraphBuilder, findings: Sequence[NormalizedFinding]) -> None:
    open_findings = [f for f in findings if f.status != "fixed" and f.rel_path]
    by_file = Counter(f.rel_path for f in open_findings)
    by_component = Counter(_component_of(f.rel_path or "") for f in open_findings)
    by_secret = Counter(
        f"{f.rel_path}:{f.line_start or 1}" for f in open_findings if f.cwe in _SECRET_CWES
    )
    for key, node in list(graph.nodes.items()):
        count = 0
        if node.kind == "component":
            count = by_component.get(node.label, 0)
        elif node.kind == "secret":
            count = by_secret.get(node.label, 0)
        elif node.kind in ("entry_point", "route") and node.rel_path:
            count = by_file.get(node.rel_path, 0)
        elif node.kind == "dependency":
            count = sum(
                1 for f in open_findings if f.scanner == "osv" and node.label in f.snippet_redacted
            )
        if count:
            graph.nodes[key] = node.model_copy(update={"finding_count": count})


def summarize(graph: SystemGraph) -> SystemSummary:
    """Turn the graph into lists the AI can read out."""
    by_kind: dict[str, list[str]] = {}
    for node in graph.nodes:
        by_kind.setdefault(node.kind, []).append(node.label)
    hotspots = sorted((n for n in graph.nodes if n.finding_count), key=lambda n: -n.finding_count)
    return SystemSummary(
        components=by_kind.get("component", []),
        entry_points=by_kind.get("entry_point", []),
        routes=by_kind.get("route", []),
        data_stores=by_kind.get("data_store", []),
        external_services=by_kind.get("external_service", []),
        secrets_locations=by_kind.get("secret", []),
        dependencies_count=len(by_kind.get("dependency", [])),
        hotspots=[
            Hotspot(node=n.label, kind=n.kind, finding_count=n.finding_count)
            for n in hotspots[:MAX_HOTSPOTS]
        ],
    )

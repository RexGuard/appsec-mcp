"""get_system_map: what the app is made of."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from appsec_mcp.models.common import Id, RelPath, StrictModel

NodeKind = Literal[
    "component", "entry_point", "route", "data_store", "external_service", "secret", "dependency"
]
EdgeKind = Literal["imports", "calls", "handles", "reads", "depends_on"]


class GetSystemMapRequest(StrictModel):
    scan_id: Id
    format: Literal["summary", "graph"] = "summary"


class MapNode(StrictModel):
    id: Id
    kind: NodeKind
    label: str = Field(min_length=1)
    rel_path: RelPath | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
    finding_count: int = Field(default=0, ge=0)


class MapEdge(StrictModel):
    source: Id
    target: Id
    kind: EdgeKind


class SystemGraph(StrictModel):
    nodes: list[MapNode]
    edges: list[MapEdge]

    @model_validator(mode="after")
    def _edges_reference_nodes(self) -> SystemGraph:
        ids = {n.id for n in self.nodes}
        if len(ids) != len(self.nodes):
            raise ValueError("node ids must be unique")
        for e in self.edges:
            if e.source not in ids or e.target not in ids:
                raise ValueError(f"edge {e.source}->{e.target} references a missing node")
        return self


class Hotspot(StrictModel):
    node: str
    finding_count: int = Field(ge=1)


class SystemMapSummary(StrictModel):
    components: list[str]
    entry_points: list[str]
    routes: list[str]
    data_stores: list[str]
    external_services: list[str]
    secrets_locations: list[str]
    dependencies_count: int = Field(ge=0)
    hotspots: list[Hotspot]

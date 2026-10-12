"""System map models: what the app is made of."""

from typing import Any, Literal

from pydantic import Field

from appsec_mcp.models.base import StrictModel

NodeKind = Literal[
    "component",
    "entry_point",
    "route",
    "data_store",
    "external_service",
    "secret",
    "dependency",
]
EdgeKind = Literal["imports", "calls", "handles", "reads", "depends_on"]


class MapNode(StrictModel):
    """A node in the system map. `id` is local to one scan."""

    id: int = Field(ge=1)
    kind: NodeKind
    label: str
    rel_path: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
    finding_count: int = Field(default=0, ge=0)


class MapEdge(StrictModel):
    """A directed edge between two nodes."""

    source: int = Field(ge=1)
    target: int = Field(ge=1)
    kind: EdgeKind


class SystemGraph(StrictModel):
    """The full graph, for the viewer."""

    nodes: list[MapNode]
    edges: list[MapEdge]


class Hotspot(StrictModel):
    """A node with findings attached."""

    node: str
    kind: NodeKind
    finding_count: int = Field(ge=1)


class SystemSummary(StrictModel):
    """A text-friendly summary of the map, for the AI."""

    components: list[str]
    entry_points: list[str]
    routes: list[str]
    data_stores: list[str]
    external_services: list[str]
    secrets_locations: list[str]
    dependencies_count: int = Field(ge=0)
    hotspots: list[Hotspot]


class SystemMapResult(StrictModel):
    """Response of get_system_map: `summary` or `graph`, depending on the requested format."""

    summary: SystemSummary | None = None
    graph: SystemGraph | None = None

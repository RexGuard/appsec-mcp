"""System map nodes and edges, stored per scan."""

import json

from appsec_mcp.models.system_map import MapEdge, MapNode, SystemGraph
from appsec_mcp.storage.db import Database


class MapRepo:
    """Persist and load the system map of a scan."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, scan_id: int, graph: SystemGraph) -> None:
        """Store all nodes and edges of a scan's map."""
        with self._db.connect() as conn:
            conn.executemany(
                "INSERT INTO map_nodes (scan_id, local_id, kind, label, rel_path, meta_json, "
                "finding_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        scan_id,
                        n.id,
                        n.kind,
                        n.label,
                        n.rel_path,
                        json.dumps(n.meta),
                        n.finding_count,
                    )
                    for n in graph.nodes
                ),
            )
            conn.executemany(
                "INSERT INTO map_edges (scan_id, source_local_id, target_local_id, kind) "
                "VALUES (?, ?, ?, ?)",
                ((scan_id, e.source, e.target, e.kind) for e in graph.edges),
            )

    def load(self, scan_id: int) -> SystemGraph:
        """Load the map of a scan (empty if none)."""
        with self._db.connect() as conn:
            node_rows = conn.execute(
                "SELECT local_id, kind, label, rel_path, meta_json, finding_count FROM map_nodes "
                "WHERE scan_id = ? ORDER BY local_id",
                (scan_id,),
            ).fetchall()
            edge_rows = conn.execute(
                "SELECT source_local_id, target_local_id, kind FROM map_edges WHERE scan_id = ? "
                "ORDER BY id",
                (scan_id,),
            ).fetchall()
        nodes = [
            MapNode(
                id=r["local_id"],
                kind=r["kind"],
                label=r["label"],
                rel_path=r["rel_path"],
                meta=json.loads(r["meta_json"] or "{}"),
                finding_count=r["finding_count"],
            )
            for r in node_rows
        ]
        edges = [
            MapEdge(source=r["source_local_id"], target=r["target_local_id"], kind=r["kind"])
            for r in edge_rows
        ]
        return SystemGraph(nodes=nodes, edges=edges)

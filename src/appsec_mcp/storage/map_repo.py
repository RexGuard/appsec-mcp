from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from appsec_mcp.storage.db import Database


@dataclass(frozen=True)
class NodeRecord:
    kind: str
    label: str
    rel_path: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    finding_count: int = 0
    id: int | None = field(default=None, compare=False)


@dataclass(frozen=True)
class EdgeRecord:
    source: int
    target: int
    kind: str


class MapRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add_nodes(self, scan_id: int, nodes: Iterable[NodeRecord]) -> list[int]:
        ids: list[int] = []
        with self.db.transaction() as c:
            for n in nodes:
                cur = c.execute(
                    "INSERT INTO map_nodes (scan_id, kind, label, rel_path, meta_json, finding_count) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        scan_id,
                        n.kind,
                        n.label,
                        n.rel_path,
                        json.dumps(n.meta, sort_keys=True),
                        n.finding_count,
                    ),
                )
                ids.append(int(cur.lastrowid or 0))
        return ids

    def add_edges(self, scan_id: int, edges: Iterable[EdgeRecord]) -> int:
        """Insert edges, silently dropping duplicates. Returns how many were new."""
        with self.db.transaction() as c:
            before = c.total_changes
            c.executemany(
                "INSERT OR IGNORE INTO map_edges (scan_id, source_node_id, target_node_id, kind) VALUES (?, ?, ?, ?)",
                [(scan_id, e.source, e.target, e.kind) for e in edges],
            )
            return c.total_changes - before

    def nodes(self, scan_id: int) -> list[NodeRecord]:
        rows = self.db.conn.execute(
            "SELECT id, kind, label, rel_path, meta_json, finding_count FROM map_nodes WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        return [
            NodeRecord(
                id=r["id"],
                kind=r["kind"],
                label=r["label"],
                rel_path=r["rel_path"],
                meta=json.loads(r["meta_json"] or "{}"),
                finding_count=r["finding_count"],
            )
            for r in rows
        ]

    def edges(self, scan_id: int) -> list[EdgeRecord]:
        rows = self.db.conn.execute(
            "SELECT source_node_id, target_node_id, kind FROM map_edges WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        return [EdgeRecord(source=r[0], target=r[1], kind=r[2]) for r in rows]

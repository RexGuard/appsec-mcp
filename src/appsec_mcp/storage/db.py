"""Opening the database and locating AppSec MCP's home folder."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from appsec_mcp.storage.migrations import migrate

HOME_ENV = "APPSEC_MCP_HOME"


def app_home() -> Path:
    """`~/.appsec-mcp`, or the folder named by APPSEC_MCP_HOME."""
    override = os.getenv(HOME_ENV)
    return Path(override).expanduser() if override else Path.home() / ".appsec-mcp"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class Database:
    """A migrated SQLite connection. All SQL in the repositories is parameterised."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Commit on success, roll back on any exception."""
        try:
            yield self.conn
        except BaseException:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()


def open_database(path: Path | None = None) -> Database:
    """Open (creating if needed) and migrate the database. `path=None` uses `<home>/appsec.db`."""
    if path is None:
        path = app_home() / "appsec.db"
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level="DEFERRED")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    migrate(conn)
    return Database(conn)

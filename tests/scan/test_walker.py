"""Walker and ledger: full accounting, ignores, binaries, size cap, symlinks, speed."""

import os
import time
from pathlib import Path

import pytest

from appsec_mcp.scan.language import detect_language
from appsec_mcp.scan.ledger import LedgerCollector
from appsec_mcp.scan.walker import walk

MAX_10K_SECONDS = 5.0


def _collect(root: Path, max_bytes: int = 1024 * 1024) -> LedgerCollector:
    return LedgerCollector().consume(walk(root, max_bytes))


def test_ledger_accounts_for_every_top_level_path(apps: Path) -> None:
    ledger = _collect(apps)
    on_disk = {p.relative_to(apps).as_posix() for p in apps.rglob("*") if p.is_file()}
    recorded = {e.rel_path for e in ledger.entries}
    assert on_disk <= recorded
    assert ledger.read_count == len(ledger.sources)


def test_skip_reasons(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("secret.txt\nlogs/\n")
    (tmp_path / "secret.txt").write_text("x")
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "a.log").write_text("x")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "m.js").write_text("x")
    (tmp_path / "img.bin").write_bytes(b"\x00\x01\x02")
    (tmp_path / "big.txt").write_text("a" * 2048)
    (tmp_path / "ok.py").write_text("print(1)\n")
    nested = tmp_path / "pkg"
    nested.mkdir()
    (nested / ".gitignore").write_text("*.tmp\n")
    (nested / "a.tmp").write_text("x")
    reasons = {e.rel_path: e.skip_reason for e in _collect(tmp_path, 1024).entries}
    assert reasons["secret.txt"] == "gitignored"
    assert reasons["logs"] == "gitignored"
    assert reasons["node_modules"] == "excluded_dir"
    assert reasons["img.bin"] == "binary"
    assert reasons["big.txt"] == "too_large"
    assert reasons["ok.py"] is None
    assert reasons["pkg/a.tmp"] == "gitignored"


def test_symlink_outside_root_is_skipped(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.symlink(outside, root / "link.txt")
    except OSError:
        pytest.skip("Creating symlinks needs Developer Mode or admin on Windows")
    entry = next(e for e in _collect(root).entries if e.rel_path == "link.txt")
    assert entry.skip_reason == "symlink_outside_root"


def test_hash_and_language_recorded(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("const a = 1;\n")
    entry = _collect(tmp_path).entries[0]
    assert entry.language == "typescript"
    assert entry.sha256 and len(entry.sha256) == 64


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("a/b.py", "python"),
        ("x.TSX", "typescript"),
        ("Dockerfile", "dockerfile"),
        (".env", "dotenv"),
        (".env.local", "dotenv"),
        ("pom.xml", "maven"),
        ("weird.zzz", None),
    ],
)
def test_detect_language(path: str, language: str | None) -> None:
    assert detect_language(path) == language


def test_ten_thousand_files_walk_fast(tmp_path: Path) -> None:
    for d in range(100):
        folder = tmp_path / f"d{d}"
        folder.mkdir()
        for f in range(100):
            (folder / f"f{f}.py").write_text("x = 1\n")
    started = time.perf_counter()
    ledger = _collect(tmp_path)
    assert ledger.read_count == 10_000
    assert time.perf_counter() - started < MAX_10K_SECONDS

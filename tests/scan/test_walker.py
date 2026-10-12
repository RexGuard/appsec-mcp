import os
import time
from pathlib import Path

import pytest

from appsec_mcp.scan.language import detect_language, looks_binary
from appsec_mcp.scan.ledger import Ledger
from appsec_mcp.scan.walker import SkippedEntry, WalkedFile, walk

FIXTURES = Path(__file__).parents[1] / "fixtures" / "vuln_apps"


def _all_files(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink())


def _ledger(root: Path, **kw) -> Ledger:
    ledger = Ledger()
    for _ in ledger.track(walk(root.resolve(), **kw)):
        pass
    return ledger


@pytest.mark.parametrize("app", sorted(p.name for p in FIXTURES.iterdir() if p.is_dir()))
def test_ledger_accounts_for_every_fixture_file(app):
    root = (FIXTURES / app).resolve()
    ledger = _ledger(root)
    missing = [f for f in _all_files(root) if not ledger.accounts_for(f)]
    assert missing == []
    assert ledger.read > 0


def test_fixture_dotenv_is_read_not_skipped():
    ledger = _ledger(FIXTURES / "flask_app")
    env = next(f for f in ledger.files if f.rel_path == ".env")
    assert env.status == "read" and env.language == "dotenv"


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('hi')\n")
    (root / "src" / "big.js").write_text("x" * 3000)
    (root / "logo.png").write_bytes(b"\x89PNG\r\n")
    (root / "data.bin2").write_bytes(b"abc\x00def")
    (root / "node_modules" / "lib").mkdir(parents=True)
    (root / "node_modules" / "lib" / "index.js").write_text("module.exports = 1")
    (root / "secret.log").write_text("ignored")
    (root / "gen").mkdir()
    (root / "gen" / "out.py").write_text("x = 1")
    (root / ".gitignore").write_text("*.log\ngen/\n")
    (root / "sub").mkdir()
    (root / "sub" / ".gitignore").write_text("local.txt\n")
    (root / "sub" / "local.txt").write_text("ignored here")
    (root / "local.txt").write_text("not ignored at the top")
    return root.resolve()


def test_skip_reasons(tree):
    entries = {e.rel_path: e for e in walk(tree, max_file_kb=2)}
    assert isinstance(entries["src/app.py"], WalkedFile)
    assert entries["src/app.py"].language == "python"
    assert entries["src/big.js"] == SkippedEntry("src/big.js", "too_large", 3000)
    assert entries["logo.png"].reason == "binary"
    assert entries["data.bin2"].reason == "binary"
    assert entries["node_modules/"].reason == "excluded_dir"
    assert entries["secret.log"].reason == "gitignored"
    assert entries["gen/"].reason == "gitignored"
    assert entries["sub/local.txt"].reason == "gitignored"
    assert isinstance(entries["local.txt"], WalkedFile)
    assert "node_modules/lib/index.js" not in entries  # never descended into


def test_read_files_carry_hash_and_text(tree):
    import hashlib

    f = next(e for e in walk(tree) if e.rel_path == "src/app.py")
    assert f.sha256 == hashlib.sha256(b"print('hi')\n").hexdigest()
    assert f.text == "print('hi')\n"
    assert f.size_bytes == 12


def test_every_file_accounted_for(tree):
    ledger = _ledger(tree, max_file_kb=2)
    assert [f for f in _all_files(tree) if not ledger.accounts_for(f)] == []
    assert ledger.read + ledger.skipped == len(ledger.files)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need extra privileges on Windows")
def test_symlink_escaping_root_is_skipped(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "passwords.txt").write_text("hunter2")
    root = tmp_path / "proj"
    root.mkdir()
    (root / "a.py").write_text("x = 1")
    (root / "leak.txt").symlink_to(outside / "passwords.txt")
    (root / "leakdir").symlink_to(outside, target_is_directory=True)
    (root / "alias.py").symlink_to(root / "a.py")
    (root / "loop").symlink_to(root, target_is_directory=True)
    entries = {e.rel_path: e for e in walk(root.resolve())}
    assert entries["leak.txt"].reason == "symlink_outside_root"
    assert entries["leakdir/"].reason == "symlink_outside_root"
    assert isinstance(entries["alias.py"], WalkedFile)  # inside the root: fine to read
    assert entries["loop/"].reason == "excluded_dir"  # no infinite recursion
    assert not any("hunter2" in getattr(e, "text", "") for e in entries.values())


def test_walk_is_lazy(tree):
    gen = walk(tree)
    first = next(gen)
    assert first.rel_path


def test_ten_thousand_files_under_five_seconds(tmp_path):
    root = tmp_path / "big"
    for d in range(100):
        sub = root / f"pkg{d}"
        sub.mkdir(parents=True)
        for i in range(100):
            (sub / f"m{i}.py").write_text(f"VALUE = {i}\n")
    start = time.perf_counter()
    ledger = _ledger(root)
    elapsed = time.perf_counter() - start
    assert ledger.read == 10_000
    assert elapsed < 5, f"walk took {elapsed:.2f}s"


@pytest.mark.parametrize(
    ("name", "lang"),
    [
        ("src/a.ts", "typescript"),
        ("App.JSX", "javascript"),
        ("main.cpp", "cpp"),
        ("x.h", "c"),
        ("Main.java", "java"),
        ("index.html", "html"),
        ("Dockerfile", "dockerfile"),
        (".env.local", "dotenv"),
        ("requirements.txt", "pip-requirements"),
        ("pom.xml", "maven"),
        ("README", None),
    ],
)
def test_detect_language(name, lang):
    assert detect_language(name) == lang


def test_looks_binary():
    assert looks_binary("a.png", b"text")
    assert looks_binary("a.dat", b"ab\x00c")
    assert not looks_binary("a.py", b"print(1)")

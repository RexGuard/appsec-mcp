import sys
from pathlib import Path

import pytest

from appsec_mcp.errors import PathForbidden, PathNotDirectory, PathNotFound
from appsec_mcp.security.paths import confine, is_within, resolve_scan_root


def test_resolves_a_project_folder(tmp_path):
    (tmp_path / "app").mkdir()
    assert resolve_scan_root(str(tmp_path / "app" / ".." / "app")) == (tmp_path / "app").resolve()


@pytest.mark.parametrize("raw", ["", "   ", "/definitely/not/here", "bad\x00path"])
def test_missing_paths(raw):
    with pytest.raises(PathNotFound):
        resolve_scan_root(raw)


def test_file_is_not_a_directory(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    with pytest.raises(PathNotDirectory):
        resolve_scan_root(f)


def test_filesystem_root_is_forbidden():
    with pytest.raises(PathForbidden):
        resolve_scan_root(Path(Path.cwd().anchor))


def test_home_itself_is_forbidden(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    with pytest.raises(PathForbidden):
        resolve_scan_root(tmp_path)
    (tmp_path / "project").mkdir()
    assert resolve_scan_root(tmp_path / "project") == (tmp_path / "project").resolve()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX system folders")
@pytest.mark.parametrize("system_dir", ["/etc", "/usr", "/usr/lib"])
def test_system_folders_are_forbidden(system_dir):
    if not Path(system_dir).is_dir():
        pytest.skip(f"{system_dir} not present")
    with pytest.raises(PathForbidden):
        resolve_scan_root(system_dir)


def test_confine_blocks_escapes(tmp_path):
    root = tmp_path.resolve()
    (root / "a").mkdir()
    assert confine(root, "a/b.txt") == root / "a" / "b.txt"
    for escape in ("../x", "a/../../x", str(tmp_path.parent / "x")):
        with pytest.raises(PathForbidden):
            confine(root, escape)


def test_is_within(tmp_path):
    assert is_within(tmp_path, tmp_path)
    assert is_within(tmp_path, tmp_path / "x")
    assert not is_within(tmp_path / "x", tmp_path)

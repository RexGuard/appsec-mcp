import pytest

from appsec_mcp.storage import open_database


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """No test ever touches the real ~/.appsec-mcp."""
    monkeypatch.setenv("APPSEC_MCP_HOME", str(tmp_path / "appsec-home"))


@pytest.fixture
def db(tmp_path):
    database = open_database(tmp_path / "test.db")
    yield database
    database.close()

"""Runtime settings: where data lives and the limits the tool enforces."""

import os
from dataclasses import dataclass
from pathlib import Path

HOME_ENV_VAR = "APPSEC_MCP_HOME"
DEFAULT_MAX_FILE_KB = 1024
SCANNER_TIMEOUT_S = 300
SCANNER_MAX_OUTPUT_BYTES = 50 * 1024 * 1024
PROPOSAL_TTL_MINUTES = 30
WEB_TIMEOUT_S = 10.0
WEB_MAX_REDIRECTS = 5


@dataclass(frozen=True)
class Settings:
    """Paths and limits for one running instance."""

    home: Path

    @property
    def db_path(self) -> Path:
        """SQLite database file."""
        return self.home / "appsec.db"

    @property
    def backups_dir(self) -> Path:
        """Root folder for patch backups."""
        return self.home / "backups"

    @property
    def logs_dir(self) -> Path:
        """Root folder for rotating log files."""
        return self.home / "logs"


def load_settings(home: Path | None = None) -> Settings:
    """Build settings from an explicit home, the env var, or ~/.appsec-mcp."""
    if home is None:
        env_home = os.environ.get(HOME_ENV_VAR)
        home = Path(env_home) if env_home else Path.home() / ".appsec-mcp"
    home = home.expanduser().resolve()
    home.mkdir(parents=True, exist_ok=True)
    return Settings(home=home)

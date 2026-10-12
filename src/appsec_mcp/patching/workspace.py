"""An in-memory view of project files that fixers and recipes edit before anything is written."""

from pathlib import Path

from appsec_mcp.models.patch import FileChange
from appsec_mcp.patching.textio import decode, newline_of
from appsec_mcp.security.paths import confine


class Workspace:
    """Reads files lazily, records edits, and turns them into FileChanges. Writes nothing."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._original: dict[str, str | None] = {}
        self._current: dict[str, str] = {}

    def exists(self, rel_path: str) -> bool:
        """True when the file exists (on disk or created in this workspace)."""
        return self.read(rel_path) is not None

    def read(self, rel_path: str) -> str | None:
        """Current text of a file, or None if it does not exist."""
        if rel_path in self._current:
            return self._current[rel_path]
        if rel_path not in self._original:
            path = confine(self.root, rel_path)
            self._original[rel_path] = decode(path.read_bytes()) if path.is_file() else None
        return self._original[rel_path]

    def write(self, rel_path: str, text: str) -> None:
        """Record new content for a file."""
        self.read(rel_path)
        self._current[rel_path] = text

    def changes(self) -> list[FileChange]:
        """Every file whose content actually changed."""
        return [
            FileChange(rel_path=rel, before=self._original.get(rel), after=text)
            for rel, text in self._current.items()
            if text != self._original.get(rel)
        ]

    def ensure_lines(self, rel_path: str, lines: list[str], header: str | None = None) -> None:
        """Append any of `lines` missing from a line-based file (creating it if needed)."""
        text = self.read(rel_path) or ""
        existing = {line.strip() for line in text.splitlines()}
        missing = [line for line in lines if line.strip() not in existing]
        if not missing:
            return
        newline = newline_of(text) if text else "\n"
        if text and not text.endswith(("\n", "\r")):
            text += newline
        block = ([header] if header else []) + missing
        self.write(rel_path, text + newline.join(block) + newline)

    def ensure_env_ignored(self, base_dir: str = "") -> None:
        """Make sure .env files are git-ignored but .env.example is kept."""
        gitignore = f"{base_dir}/.gitignore" if base_dir else ".gitignore"
        self.ensure_lines(
            gitignore,
            [".env", ".env.*", "!.env.example"],
            header="# Local secrets (added by appsec-mcp)",
        )

    def ensure_env_example(self, names: list[str], base_dir: str = "") -> None:
        """List required environment variable names (never values) in .env.example."""
        example = f"{base_dir}/.env.example" if base_dir else ".env.example"
        self.ensure_lines(example, [f"{name}=" for name in names])

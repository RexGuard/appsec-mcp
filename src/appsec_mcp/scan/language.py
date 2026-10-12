"""Language detection by file name and extension."""

from pathlib import PurePosixPath

_BY_EXTENSION: dict[str, str] = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".py": "python",
    ".pyw": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".html": "html",
    ".htm": "html",
    ".vue": "html",
    ".svelte": "html",
    ".css": "css",
    ".scss": "css",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
    ".ini": "ini",
    ".cfg": "ini",
    ".properties": "properties",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".cs": "csharp",
    ".sql": "sql",
    ".md": "markdown",
    ".txt": "text",
}
_BY_NAME: dict[str, str] = {
    "dockerfile": "dockerfile",
    "makefile": "makefile",
    "cmakelists.txt": "cmake",
    "requirements.txt": "requirements",
    "pom.xml": "maven",
    "package.json": "npm",
}

SOURCE_LANGUAGES = frozenset(
    {
        "javascript",
        "typescript",
        "python",
        "java",
        "kotlin",
        "c",
        "cpp",
        "html",
        "go",
        "ruby",
        "php",
        "rust",
        "csharp",
    }
)


def detect_language(rel_path: str) -> str | None:
    """Return a language id for a path, or None if unknown."""
    path = PurePosixPath(rel_path)
    name = path.name.lower()
    if name in _BY_NAME:
        return _BY_NAME[name]
    if name == ".env" or name.startswith(".env."):
        return "dotenv"
    return _BY_EXTENSION.get(path.suffix.lower())

"""Language and binary-file detection by name and content."""

from __future__ import annotations

from pathlib import PurePosixPath

_BY_EXTENSION: dict[str, str] = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "vue",
    ".svelte": "svelte",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "css",
    ".py": "python",
    ".pyw": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
    ".gradle": "gradle",
    ".properties": "properties",
    ".ini": "ini",
    ".cfg": "ini",
    ".md": "markdown",
    ".txt": "text",
    ".env": "dotenv",
    ".lock": "lockfile",
}

_BY_NAME: dict[str, str] = {
    "dockerfile": "dockerfile",
    "makefile": "makefile",
    "cmakelists.txt": "cmake",
    "gemfile": "ruby",
    "pipfile": "toml",
    "requirements.txt": "pip-requirements",
    "package-lock.json": "lockfile",
    "yarn.lock": "lockfile",
    "pnpm-lock.yaml": "lockfile",
    "poetry.lock": "lockfile",
    "pom.xml": "maven",
    ".gitignore": "gitignore",
}

# Never text, whatever their content looks like.
BINARY_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".psd",
        ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".ear",
        ".class", ".dll", ".exe", ".so", ".dylib", ".o", ".obj", ".a", ".lib", ".pyc", ".pyo", ".wasm",
        ".mp3", ".mp4", ".mov", ".avi", ".wav", ".ogg", ".flac", ".webm",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".sqlite", ".db", ".apk", ".ipa", ".dmg", ".iso", ".bin",
    }
)  # fmt: skip


def detect_language(rel_path: str) -> str | None:
    """Best-effort language name from the file name, or None when unknown."""
    p = PurePosixPath(rel_path)
    name = p.name.lower()
    if name in _BY_NAME:
        return _BY_NAME[name]
    if name.startswith(".env"):
        return "dotenv"
    return _BY_EXTENSION.get(p.suffix.lower())


def looks_binary(rel_path: str, head: bytes) -> bool:
    """Binary by extension, or by a NUL byte in the first chunk (the same heuristic git uses)."""
    if PurePosixPath(rel_path).suffix.lower() in BINARY_EXTENSIONS:
        return True
    return b"\x00" in head

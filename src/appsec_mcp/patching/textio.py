"""Byte-exact text helpers so patched and reverted files keep their encoding and line endings."""

import hashlib
from pathlib import Path

_ENCODING = "utf-8"
_ERRORS = "surrogateescape"


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of bytes."""
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str | None:
    """Hex SHA-256 of a file, or None when it does not exist."""
    return sha256_bytes(path.read_bytes()) if path.is_file() else None


def decode(data: bytes) -> str:
    """Decode bytes so that `encode(decode(b)) == b` for any input."""
    return data.decode(_ENCODING, errors=_ERRORS)


def encode(text: str) -> bytes:
    """Inverse of `decode`."""
    return text.encode(_ENCODING, errors=_ERRORS)


def newline_of(text: str) -> str:
    """The file's dominant newline sequence."""
    return "\r\n" if "\r\n" in text else "\n"

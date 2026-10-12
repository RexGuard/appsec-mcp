"""Domain errors. Every error carries a stable code and a plain-language message."""

from enum import StrEnum


class ErrorCode(StrEnum):
    """Stable error codes returned to MCP clients and the HTTP API."""

    PATH_NOT_FOUND = "PATH_NOT_FOUND"
    PATH_NOT_DIRECTORY = "PATH_NOT_DIRECTORY"
    PATH_FORBIDDEN = "PATH_FORBIDDEN"
    PATH_OUTSIDE_ROOT = "PATH_OUTSIDE_ROOT"
    SCAN_IN_PROGRESS = "SCAN_IN_PROGRESS"
    SCAN_NOT_FOUND = "SCAN_NOT_FOUND"
    FINDING_NOT_FOUND = "FINDING_NOT_FOUND"
    NOT_PATCHABLE = "NOT_PATCHABLE"
    RECIPE_NOT_FOUND = "RECIPE_NOT_FOUND"
    RECIPE_NOT_APPLICABLE = "RECIPE_NOT_APPLICABLE"
    TOKEN_INVALID = "TOKEN_INVALID"  # noqa: S105 - an error code, not a secret
    PROPOSAL_EXPIRED = "PROPOSAL_EXPIRED"
    FILES_CHANGED_SINCE_PROPOSAL = "FILES_CHANGED_SINCE_PROPOSAL"
    FILES_CHANGED_SINCE_APPLY = "FILES_CHANGED_SINCE_APPLY"
    WRITE_FAILED = "WRITE_FAILED"
    PATCH_NOT_FOUND = "PATCH_NOT_FOUND"
    NOT_APPLIED = "NOT_APPLIED"
    URL_INVALID = "URL_INVALID"
    URL_PRIVATE_BLOCKED = "URL_PRIVATE_BLOCKED"
    TIMEOUT = "TIMEOUT"
    TLS_ERROR = "TLS_ERROR"
    SCANNER_FAILED = "SCANNER_FAILED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"


class AppSecError(Exception):
    """Base class for all expected (anticipated) failures."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class PathError(AppSecError):
    """A scan or patch path is missing, not a directory, forbidden or escapes the root."""


class NotFoundError(AppSecError):
    """A scan, finding, patch or recipe does not exist."""


class PatchError(AppSecError):
    """A patch could not be proposed, applied or reverted."""


class WebCheckError(AppSecError):
    """A website check was refused or failed."""


class ScannerError(AppSecError):
    """An external scanner failed to run or returned unusable output."""

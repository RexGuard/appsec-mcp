"""Domain errors.

Every expected failure is an `AppSecError` subclass carrying a stable `code` (for the calling AI and
for tests) and a plain-language `message` (for the person). The server converts them to MCP tool
errors; nothing else should reach the client as an unexplained exception.
"""

from __future__ import annotations


class AppSecError(Exception):
    """Base class for every failure the tool anticipates."""

    code: str = "INTERNAL_ERROR"
    default_message: str = "Something went wrong inside AppSec MCP."

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)

    def to_text(self) -> str:
        """The form sent to MCP clients: `CODE: message`."""
        return f"{self.code}: {self.message}"


class PathNotFound(AppSecError):
    code = "PATH_NOT_FOUND"
    default_message = "That folder doesn't exist."


class PathNotDirectory(AppSecError):
    code = "PATH_NOT_DIRECTORY"
    default_message = "That path is a file, not a folder. Point me at your project folder."


class PathForbidden(AppSecError):
    code = "PATH_FORBIDDEN"
    default_message = "That folder is a system or home folder. Point me at a single project folder instead."


class ScanInProgress(AppSecError):
    code = "SCAN_IN_PROGRESS"
    default_message = "A scan of this project is already running. Wait for it to finish."


class ScanNotFound(AppSecError):
    code = "SCAN_NOT_FOUND"
    default_message = "There is no scan with that id."


class FindingNotFound(AppSecError):
    code = "FINDING_NOT_FOUND"
    default_message = "There is no finding with that id."


class NotPatchable(AppSecError):
    code = "NOT_PATCHABLE"
    default_message = "I can't fix this finding automatically. The explanation says how to fix it by hand."


class RecipeNotFound(AppSecError):
    code = "RECIPE_NOT_FOUND"
    default_message = "There is no hardening recipe with that id."


class RecipeNotApplicable(AppSecError):
    code = "RECIPE_NOT_APPLICABLE"
    default_message = "That hardening recipe doesn't fit this project."


class TokenInvalid(AppSecError):
    code = "TOKEN_INVALID"
    default_message = "That proposal token isn't valid. Ask for a new proposal."


class ProposalExpired(AppSecError):
    code = "PROPOSAL_EXPIRED"
    default_message = "That proposal is more than 30 minutes old. Ask for a new one."


class FilesChangedSinceProposal(AppSecError):
    code = "FILES_CHANGED_SINCE_PROPOSAL"
    default_message = "The files changed after the fix was proposed. Ask for a new proposal."


class WriteFailed(AppSecError):
    code = "WRITE_FAILED"
    default_message = "Writing the fix failed, so every file was put back the way it was."


class PatchNotFound(AppSecError):
    code = "PATCH_NOT_FOUND"
    default_message = "There is no patch with that id."


class NotApplied(AppSecError):
    code = "NOT_APPLIED"
    default_message = "That patch was never applied, so there is nothing to revert."


class FilesChangedSinceApply(AppSecError):
    code = "FILES_CHANGED_SINCE_APPLY"
    default_message = "The files changed after the fix was applied. Pass force=true to revert anyway."


class UrlInvalid(AppSecError):
    code = "URL_INVALID"
    default_message = "That isn't a valid http(s) web address."


class UrlPrivateBlocked(AppSecError):
    code = "URL_PRIVATE_BLOCKED"
    default_message = "That address points at a private or local network, which is blocked by default."


class Timeout(AppSecError):
    code = "TIMEOUT"
    default_message = "The website didn't answer in time."


class TlsError(AppSecError):
    code = "TLS_ERROR"
    default_message = "The website's HTTPS certificate couldn't be verified."

"""Analyst feedback: remember rejected findings so later scans stop reporting them."""

from pathlib import Path

from appsec_mcp.errors import ErrorCode, NotFoundError
from appsec_mcp.models.feedback import FeedbackResult, Suppression, SuppressionList
from appsec_mcp.services.query_service import QueryService
from appsec_mcp.services.repositories import Repositories
from appsec_mcp.storage.finding_repo import FindingRow


class FeedbackService:
    """Marks findings as false positives, per project, by their stable fingerprint."""

    def __init__(self, repos: Repositories, queries: QueryService) -> None:
        self._repos = repos
        self._queries = queries

    def _project_id(self, row: FindingRow) -> int:
        return self._queries.scan_row(row.scan_id).project_id

    def mark(self, finding_id: int, reason: str) -> FeedbackResult:
        """Hide a finding from every later scan of its project until it is unmarked."""
        row = self._queries.finding_row(finding_id)
        self._repos.suppressions.add(
            self._project_id(row), row.fingerprint, row.title, row.rel_path, reason.strip()
        )
        return FeedbackResult(
            finding_id=row.id,
            title=row.title,
            rel_path=row.rel_path,
            suppressed=True,
            message="Marked as a false positive. Later scans will hide it and not count it in "
            "the score. If the code on that line changes, it is checked again.",
        )

    def unmark(self, finding_id: int) -> FeedbackResult:
        """Report a finding again on later scans."""
        row = self._queries.finding_row(finding_id)
        removed = self._repos.suppressions.remove(self._project_id(row), row.fingerprint)
        message = (
            "It will be reported again on the next scan."
            if removed
            else "This finding was not marked as a false positive."
        )
        return FeedbackResult(
            finding_id=row.id,
            title=row.title,
            rel_path=row.rel_path,
            suppressed=False,
            message=message,
        )

    def list_for(self, project_path: str) -> SuppressionList:
        """Every false positive recorded for a project folder."""
        project = self._repos.projects.find_by_path(str(Path(project_path).resolve()))
        if project is None:
            raise NotFoundError(
                ErrorCode.SCAN_NOT_FOUND, f"'{project_path}' has not been scanned yet."
            )
        items = [
            Suppression(
                title=s.title, rel_path=s.rel_path, reason=s.reason, created_at=s.created_at
            )
            for s in self._repos.suppressions.for_project(project.id)
        ]
        return SuppressionList(project=project.name, items=items)

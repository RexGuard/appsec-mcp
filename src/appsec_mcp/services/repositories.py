"""Bundle of repositories, injected into services."""

from dataclasses import dataclass

from appsec_mcp.storage.db import Database
from appsec_mcp.storage.finding_repo import FindingRepo
from appsec_mcp.storage.map_repo import MapRepo
from appsec_mcp.storage.patch_repo import PatchRepo
from appsec_mcp.storage.project_repo import ProjectRepo
from appsec_mcp.storage.scan_repo import ScanRepo
from appsec_mcp.storage.suppression_repo import SuppressionRepo


@dataclass(frozen=True)
class Repositories:
    """All repositories over one database."""

    projects: ProjectRepo
    scans: ScanRepo
    findings: FindingRepo
    maps: MapRepo
    patches: PatchRepo
    suppressions: SuppressionRepo

    @classmethod
    def over(cls, db: Database) -> "Repositories":
        """Create every repository for `db`."""
        return cls(
            ProjectRepo(db),
            ScanRepo(db),
            FindingRepo(db),
            MapRepo(db),
            PatchRepo(db),
            SuppressionRepo(db),
        )

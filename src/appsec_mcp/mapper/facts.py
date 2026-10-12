"""Facts extracted from one file, merged by the map builder."""

from dataclasses import dataclass, field


@dataclass
class FileFacts:
    """What one file tells us about the app's structure."""

    entry_point: str | None = None
    routes: list[str] = field(default_factory=list)
    data_stores: set[str] = field(default_factory=set)
    external_services: set[str] = field(default_factory=set)
    dependencies: list[str] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)

    def is_empty(self) -> bool:
        """True when the file contributed nothing."""
        return not (
            self.entry_point
            or self.routes
            or self.data_stores
            or self.external_services
            or self.dependencies
            or self.frameworks
        )

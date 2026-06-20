"""
Collector modules for gathering evidence from various sources.
"""
from .api import GitHubAPICollector
from .archive import GHArchiveCollector
from .local import LocalGitCollector
from .wayback import WaybackCollector

__all__ = [
    "GitHubAPICollector",
    "GHArchiveCollector",
    "LocalGitCollector",
    "WaybackCollector",
]

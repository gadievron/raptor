"""Core domain types + exceptions — re-exports from
``cve_diff.core.exceptions`` and ``cve_diff.core.models``."""
from cve_diff.core.exceptions import (
    AcquisitionError,
    CveDiffError,
    DiscoveryError,
    IdenticalCommitsError,
    UnsupportedSource,
)
from cve_diff.core.models import (
    CommitSha,
    DiffBundle,
    DiscoveryResult,
    IntroducedMarker,
    PatchTuple,
    RepoRef,
)

__all__ = [
    "AcquisitionError",
    "CommitSha",
    "CveDiffError",
    "DiffBundle",
    "DiscoveryError",
    "DiscoveryResult",
    "IdenticalCommitsError",
    "IntroducedMarker",
    "PatchTuple",
    "RepoRef",
    "UnsupportedSource",
]

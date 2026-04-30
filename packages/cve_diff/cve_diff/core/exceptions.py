"""Domain exceptions for the cve-diff pipeline.

Each pipeline stage raises a specific subclass of ``CveDiffError`` so
the CLI can map it to a stable exit code. See the README for the
exit-code table.
"""


class CveDiffError(Exception):
    """Base exception for the cve-diff pipeline."""


class DiscoveryError(CveDiffError):
    """No discoverer returned metadata for this CVE."""


class AcquisitionError(CveDiffError):
    """Clone / fetch cascade failed for the resolved repository."""


class IdenticalCommitsError(CveDiffError):
    """`commit_before` and `commit_after` resolve to the same SHA."""


class UnsupportedSource(CveDiffError):
    """CVE resolves to a closed-source vendor (Cisco/Microsoft/Zyxel/etc.)."""


class AnalysisError(CveDiffError):
    """Post-extract analysis rejected the diff (e.g. notes_only shape)."""

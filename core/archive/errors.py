"""Exceptions for the archive facade. Kept in their own module so detect /
compression / extract can share them without import cycles through __init__."""


class ArchiveError(Exception):
    """Base for archive extraction failures."""


class UnsupportedArchive(ArchiveError):
    """The file is not a recognised Tier-1 archive/compressed format."""


class DecompressionLimitExceeded(ArchiveError):
    """A size / file-count cap was exceeded — treated as a decompression bomb.

    ``cap`` names which bound fired — ``"total_bytes"`` or
    ``"entry_count"`` (``""`` for raisers that predate the kind) — the
    two caps are DIFFERENT operator remediation levers, so consumers
    reporting a truncation must be able to say which one to raise.
    """

    def __init__(self, message: str, *, cap: str = "") -> None:
        super().__init__(message)
        self.cap = cap

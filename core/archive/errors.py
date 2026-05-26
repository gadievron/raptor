"""Exceptions for the archive facade. Kept in their own module so detect /
compression / extract can share them without import cycles through __init__."""


class ArchiveError(Exception):
    """Base for archive extraction failures."""


class UnsupportedArchive(ArchiveError):
    """The file is not a recognised Tier-1 archive/compressed format."""


class DecompressionLimitExceeded(ArchiveError):
    """A size / file-count cap was exceeded — treated as a decompression bomb."""

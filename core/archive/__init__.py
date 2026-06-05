"""Archive facade — multi-format detection + safe extraction.

The umbrella layer over the format-specific primitives. Single-file compressors
(gz/bz2/xz/zst) live here directly (stdlib one-liners); zip and tar delegate to
``core.zip`` / ``core.tar``. New formats land here, never as new top-level
packages.

Public API:
    from core.archive import detect_format, is_archive, extract_to_dir
    from core.archive import ArchiveError, UnsupportedArchive, DecompressionLimitExceeded
    from core.archive import safe_cache_name
"""

from .cache import safe_cache_name
from .detect import detect_format, is_archive
from .errors import ArchiveError, DecompressionLimitExceeded, UnsupportedArchive
from .extract import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_TOTAL_BYTES,
    extract_to_dir,
)

__all__ = [
    "ArchiveError",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_TOTAL_BYTES",
    "DecompressionLimitExceeded",
    "UnsupportedArchive",
    "detect_format",
    "extract_to_dir",
    "is_archive",
    "safe_cache_name",
]

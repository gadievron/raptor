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
from .errors import ArchiveError, DecompressionLimitExceeded, UnsupportedArchive

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


def __getattr__(name):
    if name in ("detect_format", "is_archive"):
        from .detect import detect_format, is_archive
        globals()["detect_format"] = detect_format
        globals()["is_archive"] = is_archive
        return globals()[name]
    if name in ("DEFAULT_MAX_FILES", "DEFAULT_MAX_TOTAL_BYTES", "extract_to_dir"):
        from .extract import (
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_TOTAL_BYTES,
            extract_to_dir,
        )
        globals()["DEFAULT_MAX_FILES"] = DEFAULT_MAX_FILES
        globals()["DEFAULT_MAX_TOTAL_BYTES"] = DEFAULT_MAX_TOTAL_BYTES
        globals()["extract_to_dir"] = extract_to_dir
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

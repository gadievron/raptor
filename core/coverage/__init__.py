"""Coverage tracking — records what tools examined during analysis.

Provides coverage record building (from hook manifests and tool output)
and file read tracking. Phase 2 will add coverage computation and reporting.
"""

from .record import (
    build_from_manifest,
    build_from_semgrep,
    write_record,
    load_record,
    cleanup_manifest,
    COVERAGE_RECORD_FILE,
    READS_MANIFEST,
)

__all__ = [
    "build_from_manifest",
    "build_from_semgrep",
    "write_record",
    "load_record",
    "cleanup_manifest",
    "COVERAGE_RECORD_FILE",
    "READS_MANIFEST",
]

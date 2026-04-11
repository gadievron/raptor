"""Coverage tracking and reporting.

Provides coverage record building (from hook manifests and tool output),
file read tracking, and Phase 2 coverage summary reporting.
"""

from .record import (
    build_from_manifest,
    build_from_semgrep,
    build_from_codeql,
    build_from_findings,
    write_record,
    load_record,
    load_records,
    cleanup_manifest,
    COVERAGE_RECORD_FILE,
    READS_MANIFEST,
)

__all__ = [
    "build_from_manifest",
    "build_from_semgrep",
    "build_from_codeql",
    "build_from_findings",
    "write_record",
    "load_record",
    "load_records",
    "cleanup_manifest",
    "COVERAGE_RECORD_FILE",
    "READS_MANIFEST",
]

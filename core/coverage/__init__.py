"""Coverage tracking and reporting.

Provides coverage record building (from hook manifests and tool output), file
read tracking, the persistent verdict-bearing store, and the unified
store-backed coverage report (coverage state from the store + per-run tool
execution detail from records).
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
from .store import (
    CoverageStore,
    COVERAGE_STORE_FILE,
    coverage_store_lock,
    iter_inventory_functions,
    content_identity,
)
from .registry import category_of, depth_of, classify
from .importer import (
    backfill,
    import_run_dir,
    import_checked_by,
    import_findings,
    import_run_findings,
    import_annotations,
    import_understand,
    import_runtime,
    run_provenance,
)
from .store_summary import (
    store_view, format_store_view, file_level_view, format_file_level_view,
    render_coverage, coverage_view, render_run_coverage,
    store_coverage_threshold_met, format_store_threshold_result,
    store_llm_coverage_percent,
)
from .clean import (
    clean_run,
    classify_removal,
    apply_removal,
    dedup_runs,
    format_consequence,
    CleanConsequence,
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
    "CoverageStore",
    "COVERAGE_STORE_FILE",
    "coverage_store_lock",
    "iter_inventory_functions",
    "content_identity",
    "category_of",
    "depth_of",
    "classify",
    "backfill",
    "import_run_dir",
    "import_checked_by",
    "import_findings",
    "import_run_findings",
    "import_annotations",
    "import_understand",
    "import_runtime",
    "run_provenance",
    "store_view",
    "format_store_view",
    "file_level_view",
    "format_file_level_view",
    "render_coverage",
    "coverage_view",
    "render_run_coverage",
    "store_coverage_threshold_met",
    "format_store_threshold_result",
    "store_llm_coverage_percent",
    "clean_run",
    "classify_removal",
    "apply_removal",
    "dedup_runs",
    "format_consequence",
    "CleanConsequence",
]

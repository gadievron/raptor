"""Persistent graph memory for /understand-derived context.

The graph store is intentionally an internal substrate. Existing JSON
artefacts remain the public contract; callers should use this package rather
than querying SQLite directly.
"""

from .ingest import (
    ingest_annotations,
    ingest_audit_hypotheses,
    ingest_codeql_sarif,
    ingest_run,
    ingest_scan_findings,
    ingest_validation_outcomes,
    rebuild_graph,
)
from .queries import (
    alternative_paths,
    attack_paths,
    build_context_map,
    coverage_residual,
    dashboard_summary,
    fuzz_targets,
    graph_diff,
    graph_summary,
    hypothesis_seeds,
    prompt_context_for_location,
    propagate_binary_verdicts,
    reachable_sinks,
    sca_reachability,
    scan_dedup_chains,
    threat_model_graph_context,
)
from .store import (
    GRAPH_FILENAME,
    graph_path_for_run,
    open_graph,
    query_graph,
)

__all__ = [
    "GRAPH_FILENAME",
    "alternative_paths",
    "attack_paths",
    "build_context_map",
    "coverage_residual",
    "dashboard_summary",
    "fuzz_targets",
    "graph_diff",
    "graph_path_for_run",
    "graph_summary",
    "hypothesis_seeds",
    "ingest_annotations",
    "ingest_audit_hypotheses",
    "ingest_codeql_sarif",
    "ingest_run",
    "ingest_scan_findings",
    "ingest_validation_outcomes",
    "open_graph",
    "prompt_context_for_location",
    "propagate_binary_verdicts",
    "query_graph",
    "reachable_sinks",
    "rebuild_graph",
    "sca_reachability",
    "scan_dedup_chains",
    "threat_model_graph_context",
]

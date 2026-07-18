"""SAGE persistent memory integration for RAPTOR."""

from .config import SageConfig
from .client import SageClient
from .hooks import (
    # Scan
    recall_context_for_scan,
    store_scan_results,
    # Analysis
    store_analysis_results,
    enrich_analysis_prompt,
    # Crash analysis
    recall_context_for_crash_analysis,
    store_crash_analysis_pattern,
    # Fuzzing
    recall_context_for_fuzzing_strategy,
    store_fuzzing_strategy_outcome,
    # Web
    recall_context_for_web_scan,
    store_web_payload_effectiveness,
    # CodeQL
    recall_context_for_codeql_build,
    store_codeql_build_reliability,
    # Validation
    recall_context_for_validation,
    store_validation_verdicts,
    store_validation_disproven,
    # Understand
    recall_context_for_map,
    recall_context_for_trace,
    recall_context_for_hunt,
    store_map_results,
    store_trace_result,
    store_hunt_results,
    # Exploit
    recall_context_for_exploit,
    store_exploit_outcomes,
)

__all__ = [
    "SageConfig",
    "SageClient",
    "recall_context_for_scan",
    "store_scan_results",
    "store_analysis_results",
    "enrich_analysis_prompt",
    "recall_context_for_crash_analysis",
    "store_crash_analysis_pattern",
    "recall_context_for_fuzzing_strategy",
    "store_fuzzing_strategy_outcome",
    "recall_context_for_web_scan",
    "store_web_payload_effectiveness",
    "recall_context_for_codeql_build",
    "store_codeql_build_reliability",
    "recall_context_for_validation",
    "store_validation_verdicts",
    "store_validation_disproven",
    "recall_context_for_map",
    "recall_context_for_trace",
    "recall_context_for_hunt",
    "store_map_results",
    "store_trace_result",
    "store_hunt_results",
    "recall_context_for_exploit",
    "store_exploit_outcomes",
]

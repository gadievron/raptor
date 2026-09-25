"""SAGE persistent memory integration for RAPTOR."""

from .client import SageClient
from .config import SageConfig
from .hooks import (
    SUPPRESS_VERDICTS,
    VerdictWalkTruncated,
    compute_finding_source_hash,
    finding_source_hashes,
    finding_verdict_source_hash,
    # Finding verdict — operator verbs (/review verdict)
    forget_finding_verdicts,
    infer_codeql_build_from_sage_recall_row,
    list_finding_verdict_rows,
    operator_client,
    parse_rule_metadata,
    recall_concepts_for_study,
    recall_concepts_for_teach,
    # CodeQL build flags (mechanical inference from prior outcomes)
    recall_context_for_codeql_build,
    # Fuzzing strategy (mechanical AFL flag inference)
    recall_context_for_fuzzing_strategy,
    # SCA (mechanical short-circuit)
    recall_context_for_sca,
    # Finding verdict — cross-run FP suppression
    recall_prior_finding_verdict,
    recall_prior_fp_verdicts,
    recall_proven_rules,
    recall_verified_proven_rules,
    should_replay_rule,
    store_codeql_build_reliability,
    store_finding_verdict,
    store_fuzzing_strategy_outcome,
    # Rule library — proven checker accumulation
    store_proven_rule_metadata,
    store_sca_outcomes,
    # Study / Teach (N1)
    store_study_concepts,
)

__all__ = [
    "SUPPRESS_VERDICTS",
    "SageClient",
    "SageConfig",
    "VerdictWalkTruncated",
    "compute_finding_source_hash",
    "finding_source_hashes",
    "finding_verdict_source_hash",
    "forget_finding_verdicts",
    "infer_codeql_build_from_sage_recall_row",
    "list_finding_verdict_rows",
    "operator_client",
    "parse_rule_metadata",
    "recall_concepts_for_study",
    "recall_concepts_for_teach",
    "recall_context_for_codeql_build",
    "recall_context_for_fuzzing_strategy",
    "recall_context_for_sca",
    "recall_prior_finding_verdict",
    "recall_prior_fp_verdicts",
    "recall_proven_rules",
    "recall_verified_proven_rules",
    "should_replay_rule",
    "store_codeql_build_reliability",
    "store_finding_verdict",
    "store_fuzzing_strategy_outcome",
    "store_proven_rule_metadata",
    "store_sca_outcomes",
    "store_study_concepts",
]

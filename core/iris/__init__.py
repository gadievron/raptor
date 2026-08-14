"""IRIS — LLM-inferred taint specifications for mechanical tools.

Named after the IRIS paper (ICLR 2025, arXiv:2405.17238) which showed
that LLM-inferred taint specs doubled CodeQL's finding count vs stock
rules.  This package owns the full lifecycle: candidate identification,
LLM synthesis, iterative refinement, persistent storage, and a
consumer API that any RAPTOR pipeline can pull from.
"""

from .specs import (
    CandidateFunction,
    TaintSpec,
    compile_codeql_config,
    compile_joern_config,
    identify_candidates,
    parse_spec_response,
    specs_from_json,
    specs_to_json,
)

from .scorecard_bridge import (
    DECISION_CLASS as SCORECARD_DECISION_CLASS,
    SpecOutcome,
    cwe_quality_summary,
    record_refinement_outcomes,
)

from .api import promote_spec_on_annotation

from .assumptions import (
    AssumptionCategory,
    BypassFinding,
    SafetyAssumption,
    assumption_from_dict,
    assumptions_from_list,
    evict_stale_assumptions,
    merge_assumptions,
)
from .bypass import CompositionalAnalyzer

__all__ = [
    "CandidateFunction",
    "TaintSpec",
    "compile_codeql_config",
    "compile_joern_config",
    "identify_candidates",
    "parse_spec_response",
    "specs_from_json",
    "specs_to_json",
    "SCORECARD_DECISION_CLASS",
    "SpecOutcome",
    "cwe_quality_summary",
    "record_refinement_outcomes",
    "promote_spec_on_annotation",
    "AssumptionCategory",
    "BypassFinding",
    "SafetyAssumption",
    "assumption_from_dict",
    "assumptions_from_list",
    "evict_stale_assumptions",
    "merge_assumptions",
    "CompositionalAnalyzer",
]

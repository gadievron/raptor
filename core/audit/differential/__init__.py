"""Differential family execution — peer-vs-deviant witness runs.

Public surface: the eligibility gate, the comparison classifier, the
compute rails, and the record types. Execution itself reuses the
dark-witness executor (same sandbox floor, same loader-resolution
refusals, same authenticated protocol); this package adds the
family-comparison layer on top and shares its execution namespace
with nothing — a divergence receipt and a consistency receipt must
never corroborate each other as independent tools.
"""

from ._classify import (
    classify_lead,
    classify_vector,
    observation_from_result,
)
from ._gate import (
    ARGS_SHAPED_LANGS,
    DIMENSION_FLOOR_KEY,
    differential_applicable,
    usable_family,
)
from ._metamorphic import (
    VERDICT_RELATION_HOLDS,
    VERDICT_RELATION_VIOLATED,
    MetamorphicRelation,
    MetamorphicVerdict,
    build_relation_prompt,
    classify_relation,
    parse_relation_response,
    validate_relation_on_family,
)
from ._prompts import (
    build_member_spec,
    build_vector_prompt,
    parse_vector_response,
)
from ._rails import (
    MAX_CONFORMING_EXECUTED,
    MAX_DIFFERENTIAL_EXECUTIONS,
    MAX_DIFFERENTIAL_WALL_S,
    MAX_RELATION_PAIRS,
    MAX_VECTORS_PER_LEAD,
    MIN_CONFORMING_EXECUTED,
    DifferentialBudget,
)
from ._types import (
    COMPARISON_CONTRACTS,
    CONTRACT_ACCEPT_REJECT,
    CONTRACT_EXCEPTION_PARITY,
    CONTRACT_RETURN_EQUIVALENCE,
    OBS_ACCEPT,
    OBS_ERROR,
    OBS_REJECT,
    VERDICT_CONFIRMED,
    VERDICT_FAMILY_AGREES,
    VERDICT_INCONCLUSIVE,
    VERDICT_NONDIRECTIONAL,
    DifferentialVector,
    LeadVerdict,
    MemberObservation,
    VectorVerdict,
)

__all__ = [
    "ARGS_SHAPED_LANGS",
    "COMPARISON_CONTRACTS",
    "CONTRACT_ACCEPT_REJECT",
    "CONTRACT_EXCEPTION_PARITY",
    "CONTRACT_RETURN_EQUIVALENCE",
    "DIMENSION_FLOOR_KEY",
    "DifferentialBudget",
    "DifferentialVector",
    "LeadVerdict",
    "MAX_CONFORMING_EXECUTED",
    "MAX_DIFFERENTIAL_EXECUTIONS",
    "MAX_DIFFERENTIAL_WALL_S",
    "MAX_RELATION_PAIRS",
    "MAX_VECTORS_PER_LEAD",
    "MIN_CONFORMING_EXECUTED",
    "MemberObservation",
    "MetamorphicRelation",
    "MetamorphicVerdict",
    "OBS_ACCEPT",
    "OBS_ERROR",
    "OBS_REJECT",
    "VERDICT_CONFIRMED",
    "VERDICT_FAMILY_AGREES",
    "VERDICT_INCONCLUSIVE",
    "VERDICT_NONDIRECTIONAL",
    "VERDICT_RELATION_HOLDS",
    "VERDICT_RELATION_VIOLATED",
    "VectorVerdict",
    "build_member_spec",
    "build_relation_prompt",
    "build_vector_prompt",
    "classify_lead",
    "classify_relation",
    "classify_vector",
    "differential_applicable",
    "observation_from_result",
    "parse_relation_response",
    "parse_vector_response",
    "usable_family",
    "validate_relation_on_family",
]

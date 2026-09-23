"""Model scorecard — per-model reliability tracking across decision classes.

The scorecard records how often each (model, decision_class) cell has
been **overruled by an authoritative signal**. The full event-type
inventory lives in :data:`core.llm.scorecard.scorecard.ALL_EVENT_TYPES`
(17 types at the time of writing); the founding six below illustrate
the signal shapes — see each producer module for the rest
(``dataflow_validation``, ``cross_run_stability``,
``self_consistency``, ``cross_family_consistency``,
``validate_feedback``, ``schema_valid``, ``study_question``, ...):

  * ``cheap_short_circuit`` — cheap-tier model said "clear FP";
    full ANALYSE later said "TP".
  * ``multi_model_consensus`` — this model dissented from the majority
    of N models analysing the same finding (#290 / #302).
  * ``judge_review`` — a configured judge model reviewed this model's
    verdict and overruled / upheld it.
  * ``tool_evidence`` — tool evidence (codeql query, grep, AST search)
    in :mod:`packages.hypothesis_validation` contradicted this model's
    claim.
  * ``operator_feedback`` — operator marked the finding's outcome
    (``exploitable`` / ``disproven`` / etc.) and the marking
    contradicted this model's verdict.
  * ``reasoning_divergence`` — sister of ``multi_model_consensus``
    for the agreed-verdict case: panel landed on the same answer
    but the outlier model's reasoning text sits farthest from the
    rest of the panel by token-set Jaccard distance. Outlier gets
    ``incorrect``; non-outliers get ``correct``. Observability-only
    in v1: no policy gate consumes this signal yet.

Most event types have wired producers today (the sibling
``consensus`` / ``judge`` / ``prefilter`` / ``tool_evidence`` /
``stability`` / ``self_consistency`` / ``cross_family`` /
``reasoning_divergence`` / ``dataflow_validation`` /
``validate_feedback`` modules); the remainder live in the schema as
reserved zero-count keys until their producers land.

The scorecard's primary policy method is
:meth:`ModelScorecard.should_short_circuit`. Consumers ask the
scorecard whether to trust a cheap-tier verdict for a given
``(decision_class, model)`` cell; the scorecard answers from
**measured** miss-rate (Wilson 95% upper bound), not from the
model's self-reported confidence. This deliberately ignores
self-reported confidence because LLM confidence calibration varies
unpredictably between models — the empirical track record is the
only signal the scorecard should trust.

Storage layout (model → decision_class → events) keeps each
model's profile contiguous in the JSON, which (a) supports the
"what is this model good at?" research framing and (b) makes the
common destructive case (``reset --model X`` after a model switch)
a single dict delete rather than a walk.
"""

# Canonical cap for disagreement-sample reasoning text length. Every
# scorecard producer slices its persisted reasoning text
# (`analysis_reasoning` / `this_reasoning` / `sample_reasoning` /
# `checker_ruling` / `reason`) by this value before handing the sample
# over, and the sink (`ModelScorecard._append_sample`) additionally
# bounds EVERY string leaf by it — so sibling fields without a
# producer slice, and forged/corrupt upstream strings, are bounded by
# construction. Defined once here so the producers cannot drift apart;
# `tests/test_reasoning_cap_unique.py` is the parse-time guard and its
# PRODUCERS list must name every module that slices by the cap.
_MAX_REASONING_CHARS = 500

from .prefilter import (
    PrefilterDecision,
    fast_tier_model_name,
    prefilter_decision,
    record_prefilter_outcome,
    run_cheap_fp_check,
)
from .scorecard import (
    DecisionClassStats,
    EventType,
    ModelScorecard,
    Outcome,
    Policy,
)

__all__ = [
    "_MAX_REASONING_CHARS",
    "DecisionClassStats",
    "EventType",
    "ModelScorecard",
    "Outcome",
    "Policy",
    "PrefilterDecision",
    "fast_tier_model_name",
    "prefilter_decision",
    "record_prefilter_outcome",
    "run_cheap_fp_check",
]

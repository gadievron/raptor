"""Model scorecard — per-model reliability tracking across decision classes.

The scorecard records how often each (model, decision_class) cell has
been **overruled by an authoritative signal**. Six event-type signals
are recognised:

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

Only ``cheap_short_circuit`` has a producer wired in the first
shipping PR; the other four event types live in the schema as
reserved zero-count keys until their producer PRs land. See the
``scorecard unwired producers`` project memory for each producer's
intended outcome semantics + hook location.

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

from .scorecard import (
    ModelScorecard,
    EventType,
    Policy,
    Outcome,
    DecisionClassStats,
)
from .prefilter import (
    PrefilterDecision,
    prefilter_decision,
    record_prefilter_outcome,
)

__all__ = [
    "ModelScorecard",
    "EventType",
    "Policy",
    "Outcome",
    "DecisionClassStats",
    "PrefilterDecision",
    "prefilter_decision",
    "record_prefilter_outcome",
]

"""Optional Beta-Bernoulli aggregation of supplied tool observations.

Each observation contributes to a model: a match adds confirmation,
absence of a match adds refutation, and tool failure contributes nothing.
Definitive SMT predicates use the hypothesis's declared polarity instead
of match presence. The caller chooses the prior and any observation weights.

The resulting mean is conditional on this mapping and the Bernoulli model.
It is not a calibrated probability that source code is vulnerable. Repeated
or correlated observations do not establish independent evidence, and the
score does not grant source-reachability or finding-promotion authority.

For a Beta(alpha, beta) prior, a positive observation adds its weight to
alpha and a negative observation adds its weight to beta. The model mean
is alpha / (alpha + beta); the sum is the model's pseudo-count strength.
These arithmetic updates do not establish the model's empirical calibration.

The helpers are exposed as an optional library API. Neither the hypothesis
runner nor the audit orchestrator uses these helpers to score or promote
findings. Callers can use ``posterior_from`` with a ``ValidationResult``
evidence list when they explicitly want this model, retaining the evidence's
scope and the assumptions required to interpret the score.
"""

import math
from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable

from .result import Verdict


# Uniform prior — Beta(1, 1) — encodes "no prior knowledge". Any
# stronger prior is a tuning decision callers should make explicitly.
_DEFAULT_ALPHA = 1.0
_DEFAULT_BETA = 1.0


@dataclass(frozen=True)
class Posterior:
    """Beta(alpha, beta) posterior over `p(vuln)`.

    Frozen so callers can pass it around without aliasing surprises.
    All arithmetic returns a new instance.

    Attributes:
        alpha: Confirming-evidence count plus prior pseudo-count.
            Always positive (≥ prior).
        beta: Refuting-evidence count plus prior pseudo-count.
            Always positive (≥ prior).
    """

    alpha: float = _DEFAULT_ALPHA
    beta: float = _DEFAULT_BETA

    @property
    def mean(self) -> float:
        """Posterior mean — the point estimate of `p(vuln)`.

        Returns 0.5 (uniform) when `alpha + beta == 0`, defending
        against a caller who explicitly constructs an empty Posterior;
        the default constructor cannot produce that state.
        """
        total = self.alpha + self.beta
        if total <= 0:
            return 0.5
        return self.alpha / total

    @property
    def strength(self) -> float:
        """Total observation count (prior pseudo-counts included).

        Higher means a more concentrated posterior. Useful as a
        confidence proxy: a hypothesis with strength=2 (uniform prior,
        no evidence) has the same mean as strength=20 with 9 confirms
        and 9 refutes, but the latter is far more informative.
        """
        return self.alpha + self.beta


# Convenience: the prior used everywhere unless overridden.
UNIFORM_PRIOR = Posterior(alpha=_DEFAULT_ALPHA, beta=_DEFAULT_BETA)


def update(p: Posterior, *, confirms: bool, weight: float = 1.0) -> Posterior:
    """One conjugate update step.

    `confirms=True` adds `weight` to alpha (positive observation);
    `confirms=False` adds `weight` to beta. `weight` defaults to 1.0
    so every evidence item contributes equally; tune per-adapter when
    you have calibrated likelihoods (CodeQL dataflow ≫ Semgrep
    pattern, for example).

    `weight` must be a positive finite number — this is the only
    mutation point, so validating here is what keeps the documented
    alpha/beta > 0 invariant true (a negative weight would let `mean`
    escape [0, 1] and silently flip `verdict_from_posterior`).
    """
    if not math.isfinite(weight) or weight <= 0:
        msg = f"weight must be a positive finite number, got {weight!r}"
        raise ValueError(msg)
    if confirms:
        return Posterior(alpha=p.alpha + weight, beta=p.beta)
    return Posterior(alpha=p.alpha, beta=p.beta + weight)


def posterior_from(
    evidence_list: Iterable[Any],
    prior: Posterior = UNIFORM_PRIOR,
    *,
    polarity: str = "",
) -> Posterior:
    """Aggregate a list of evidence into a Beta posterior.

    Mechanical reading of each evidence item:
      - tool failure (`success=False`)        → no-op
      - definitive SMT predicates              → declared polarity direction
        (no declared direction                 → no-op)
      - tool succeeded with matches present   → confirming observation
      - tool succeeded with no matches        → refuting observation

    This is the same evidence-to-signal mapping the verdict ladder
    uses, but expressed as a continuous update rather than a discrete
    one. Callers that want LLM-claim-aware aggregation should run
    `verdict_from` per item and pass the verdicts through `update`
    directly — this function deliberately stays free of the LLM in
    the loop so the posterior reflects mechanical evidence only.

    Accepts any object exposing `.success` and `.matches` (both
    `Evidence` from `result.py` and `ToolEvidence` from
    `adapters/base.py` qualify).
    """
    p = prior
    for e in evidence_list:
        if not getattr(e, "success", True):
            continue
        if getattr(e, "tool", "") == "smt" and getattr(
            e, "predicate_verdict", "",
        ) in ("sat", "unsat"):
            from .verdict import verdict_from

            direction = verdict_from(e, polarity=polarity)
            if direction != "inconclusive":
                p = update(p, confirms=direction == "confirmed")
            continue
        matches = bool(getattr(e, "matches", []) or [])
        p = update(p, confirms=matches)
    return p


def verdict_from_posterior(
    p: Posterior,
    *,
    confirm_threshold: float = 0.8,
    refute_threshold: float = 0.2,
) -> Verdict:
    """Project a continuous posterior onto the 3-valued verdict.

    Thresholds are explicit and tunable. The defaults (0.8 / 0.2)
    require ~3 confirming or refuting observations against the uniform
    prior before the verdict tips — a single observation isn't enough,
    matching the conservative behaviour of the existing ladder.

    Triage callers that want to *rank* hypotheses should read
    `Posterior.mean` directly rather than thresholding; this function
    exists for callers that still want a single label.
    """
    if not 0.0 <= refute_threshold < confirm_threshold <= 1.0:
        msg = "thresholds must satisfy 0 ≤ refute_threshold < confirm_threshold ≤ 1"
        raise ValueError(msg)
    m = p.mean
    if m > confirm_threshold:
        return "confirmed"
    if m < refute_threshold:
        return "refuted"
    return "inconclusive"


__all__ = [
    "UNIFORM_PRIOR",
    "Posterior",
    "posterior_from",
    "update",
    "verdict_from_posterior",
]

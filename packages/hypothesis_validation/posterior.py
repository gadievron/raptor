"""Bayesian verdict aggregation — Beta-Bernoulli posterior over hypotheses.

The 3-valued verdict ladder in `verdict.py` is the right floor: tool
failure, confirmed-without-matches, and refuted-with-matches all
collapse to a known cell of the lattice. But it discards information
when evidence is plentiful — three confirming runs and one refuting
run looks identical to one of each, because both collapse to
inconclusive.

This module fixes that by aggregating evidence through a Beta-Bernoulli
posterior. Each piece of evidence contributes a single observation
(match present → confirmation, match absent → refutation, tool
failure → no-op). The Beta distribution is the conjugate prior for
Bernoulli observations, so the posterior update is one line of
arithmetic and the result is a calibrated probability `p(vuln)`.

Math reminder. Beta(α, β) is the prior belief over the unknown
probability `p` that the hypothesis is a real vulnerability. After one
positive observation: Beta(α+1, β). After one negative: Beta(α, β+1).
The posterior mean — `α / (α + β)` — is the point estimate, and the
total `α + β` is "evidence strength" (higher = more concentrated
distribution). No MCMC, no integrals; the conjugate update is exact.

This module is standalone. No callers in `runner.py` yet — wiring is
deliberately deferred until the math is exercised against real
evidence. Use it directly from a `ValidationResult.evidence` list
when you need a probability instead of a discrete verdict.
"""

from dataclasses import dataclass
from typing import Any, Iterable

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
    """
    if confirms:
        return Posterior(alpha=p.alpha + weight, beta=p.beta)
    return Posterior(alpha=p.alpha, beta=p.beta + weight)


def posterior_from(
    evidence_list: Iterable[Any],
    prior: Posterior = UNIFORM_PRIOR,
) -> Posterior:
    """Aggregate a list of evidence into a Beta posterior.

    Mechanical reading of each evidence item:
      - tool failure (`success=False`)        → no-op
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
        raise ValueError(
            "thresholds must satisfy 0 ≤ refute_threshold < confirm_threshold ≤ 1"
        )
    m = p.mean
    if m > confirm_threshold:
        return "confirmed"
    if m < refute_threshold:
        return "refuted"
    return "inconclusive"


__all__ = [
    "Posterior",
    "UNIFORM_PRIOR",
    "update",
    "posterior_from",
    "verdict_from_posterior",
]

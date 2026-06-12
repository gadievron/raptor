"""Beta-distribution priors for the calibrated-aggregation arc.

Phase 1b deliverable. Pure math + factory helpers; no IO, no scipy.
The current checkout's scorecard audit (``core/llm/scorecard/scripts/scorecard-audit``)
returned ``no-data``, so prior parameterization is left explicit at
the call site: Phase 3 picks a factory + parameters at integration
time once real panel-log data exists.

The Beta distribution is the conjugate prior for a Bernoulli /
Binomial likelihood, so this module is the natural shape for tracking
posteriors over per-model reliability (``α_m``, ``β_m`` in the
Dawid–Skene confusion matrix) and per-class incidence rates. Updates
are closed-form: ``Beta(α + successes, β + failures)``.

Why this module deliberately omits ``class_base_rate_from_scorecard``:
the scorecard's ``correct / incorrect`` counts measure
agreement-with-majority, not true-positive incidence. Using them as a
class base-rate prior would re-introduce the circularity that the
whole arc exists to remove. Real base rates require the panel log
(Phase 2) — that consumer arrives in Phase 3.

Incomplete-beta function: continued-fraction expansion, Numerical
Recipes section 6.4 (Lentz–Thompson). Accuracy ~1e-12 for arguments
in the regime we care about (α, β ∈ [0.5, 10⁴], x ∈ (0, 1)).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Tuple


# ---------------------------------------------------------------------------
# Pure-Python incomplete beta + bisection inverse CDF
# ---------------------------------------------------------------------------


_MAX_CF_ITER = 200
_CF_EPS = 1e-15
_FPMIN = 1e-300  # smallest positive double we treat as nonzero


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function. Standard
    Lentz–Thompson with denominator-floor guard. Returns the continued
    fraction value used by :func:`_betai_regularized`.

    Convergence within ``_CF_EPS`` is reached in well under
    ``_MAX_CF_ITER`` for arguments in the calibration regime; the cap
    exists to bound worst-case latency, not as a correctness gate.
    """
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _FPMIN:
        d = _FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, _MAX_CF_ITER + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _CF_EPS:
            return h
    return h


def _betai_regularized(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta function ``I_x(a, b)``.

    This is the CDF of ``Beta(a, b)`` evaluated at ``x``. The
    symmetric reflection ``I_x(a, b) = 1 − I_{1−x}(b, a)`` swaps the
    branch when the continued fraction would converge slowly.
    """
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    # log-Beta normalisation: B(a,b) = Γ(a)Γ(b)/Γ(a+b)
    log_bt = (
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
        + a * math.log(x) + b * math.log(1.0 - x)
    )
    bt = math.exp(log_bt)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def _inverse_betai(a: float, b: float, p: float,
                   *, tol: float = 1e-9, max_iter: int = 80) -> float:
    """Bisection on ``_betai_regularized`` to invert the Beta CDF.

    Used only for ``BetaPrior.credible_interval`` — not on any hot
    path. Bisection is overkill on accuracy and fast enough at this
    rate.
    """
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(max_iter):
        mid = 0.5 * (lo + hi)
        if _betai_regularized(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
        if hi - lo < tol:
            break
    return 0.5 * (lo + hi)


# ---------------------------------------------------------------------------
# BetaPrior
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BetaPrior:
    """Beta(α, β) prior / posterior.

    Frozen because every update returns a fresh instance — mutation
    would invite the "did this prior get updated already?" bug class.

    ``alpha`` and ``beta`` must be strictly positive. ``alpha = β = 1``
    is the uniform distribution; ``α = β = 0.5`` is the Jeffreys prior
    (uninformative under reparametrisation). ``α + β`` is the
    *strength* — the equivalent sample count the prior is worth, used
    by ``weak_informative_prior`` and reported by ``strength``.
    """
    alpha: float
    beta: float

    def __post_init__(self) -> None:
        if not (self.alpha > 0.0 and self.beta > 0.0):
            raise ValueError(
                f"BetaPrior requires alpha > 0 and beta > 0; "
                f"got alpha={self.alpha}, beta={self.beta}"
            )

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def mode(self) -> float:
        """Mode is α=β=1 → undefined (uniform); α<1 or β<1 → endpoint
        (0 or 1); otherwise the standard interior mode. Returns
        ``self.mean`` for the uniform special case rather than raising,
        because mean is a defensible centre for a flat distribution."""
        if self.alpha <= 1.0 and self.beta <= 1.0:
            if self.alpha == 1.0 and self.beta == 1.0:
                return 0.5
            # Bimodal at 0 and 1; return the mean as a single summary
            return self.mean
        if self.alpha <= 1.0:
            return 0.0
        if self.beta <= 1.0:
            return 1.0
        return (self.alpha - 1.0) / (self.alpha + self.beta - 2.0)

    @property
    def variance(self) -> float:
        s = self.alpha + self.beta
        return (self.alpha * self.beta) / (s * s * (s + 1.0))

    @property
    def strength(self) -> float:
        """``α + β``. Interpretable as the equivalent sample size the
        prior contributes. After ``posterior_update(prior, s, f)`` the
        posterior's strength is ``prior.strength + s + f``."""
        return self.alpha + self.beta

    def credible_interval(self, level: float = 0.95) -> Tuple[float, float]:
        """Two-sided equal-tailed credible interval at the given
        confidence level (default 0.95). Implementation: inverse Beta
        CDF at the two tail probabilities.

        For ``Beta(1, 1)`` (uniform) the 95% interval is approximately
        [0.025, 0.975] — sanity-checkable closed-form.
        """
        if not 0.0 < level < 1.0:
            raise ValueError(f"level must be in (0, 1); got {level}")
        tail = (1.0 - level) / 2.0
        lo = _inverse_betai(self.alpha, self.beta, tail)
        hi = _inverse_betai(self.alpha, self.beta, 1.0 - tail)
        return (lo, hi)


# ---------------------------------------------------------------------------
# Updates and factories
# ---------------------------------------------------------------------------


def posterior_update(prior: BetaPrior, successes: int,
                     failures: int) -> BetaPrior:
    """Conjugate update: ``Beta(α + s, β + f)``.

    ``successes`` and ``failures`` are non-negative integer event
    counts (matching the scorecard's ``correct / incorrect`` shape, but
    the function makes no commitment to what "success" semantically
    means — that's the caller's contract).
    """
    if successes < 0 or failures < 0:
        raise ValueError(
            f"successes / failures must be non-negative; "
            f"got successes={successes}, failures={failures}"
        )
    return BetaPrior(prior.alpha + successes, prior.beta + failures)


def uniform_prior() -> BetaPrior:
    """``Beta(1, 1)`` — flat density over [0, 1]. The most
    uninformative choice given no audit-derived base rate."""
    return BetaPrior(1.0, 1.0)


def jeffreys_prior() -> BetaPrior:
    """``Beta(½, ½)`` — Jeffreys prior. Minimax under
    reparametrisation; mass concentrates near 0 and 1. Reasonable
    default when the underlying rate is expected to be near an
    endpoint (e.g. true-positive incidence on a high-FP rule)."""
    return BetaPrior(0.5, 0.5)


def weak_informative_prior(mean: float, strength: float) -> BetaPrior:
    """Build a Beta prior with given mean and strength
    (``strength = α + β``).

    ``mean`` ∈ (0, 1), ``strength`` > 0. ``strength = 2`` recovers a
    uniform-equivalent prior centred at ``mean``; larger strengths
    concentrate the prior more tightly.

    Use when an operator (or Phase 3 integration) has a defensible
    point estimate — e.g. a per-CWE base-rate guess — but no data
    yet justifying a tight prior.
    """
    if not 0.0 < mean < 1.0:
        raise ValueError(f"mean must be in (0, 1); got {mean}")
    if not strength > 0.0:
        raise ValueError(f"strength must be > 0; got {strength}")
    alpha = mean * strength
    beta = (1.0 - mean) * strength
    return BetaPrior(alpha, beta)


__all__ = [
    "BetaPrior",
    "posterior_update",
    "uniform_prior",
    "jeffreys_prior",
    "weak_informative_prior",
]

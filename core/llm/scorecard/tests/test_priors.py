"""Tests for ``core.llm.scorecard.priors`` — Phase 1b math.

Covers:
- ``BetaPrior`` invariants (positivity, mean, mode, variance, strength).
- Credible-interval correctness against textbook reference values.
- Conjugate updates (degenerate / adversarial / symmetric).
- Factory helpers (uniform / Jeffreys / weak-informative).
- Pure-Python incomplete-beta numerics (regression-bound; the CDF
  accuracy underwrites every other guarantee in the module).

No external numerics dep — every expected value is either closed-form
or a tight-tolerance regression against the reference algorithm.
"""
from __future__ import annotations


import pytest

from core.llm.scorecard.priors import (
    BetaPrior,
    _betai_regularized,
    _inverse_betai,
    jeffreys_prior,
    posterior_update,
    prior_from_validation_labels,
    priors_from_validation,
    uniform_prior,
    weak_informative_prior,
)


# ---------------------------------------------------------------------------
# BetaPrior invariants
# ---------------------------------------------------------------------------


def test_positivity_required():
    with pytest.raises(ValueError):
        BetaPrior(0.0, 1.0)
    with pytest.raises(ValueError):
        BetaPrior(1.0, -1.0)
    # Boundary just above zero is allowed (the smallest defensible prior).
    BetaPrior(1e-6, 1e-6)


def test_uniform_mean_mode_variance():
    p = uniform_prior()
    assert p.mean == pytest.approx(0.5)
    assert p.mode == pytest.approx(0.5)
    # Var(Beta(1,1)) = 1/12
    assert p.variance == pytest.approx(1.0 / 12.0)
    assert p.strength == pytest.approx(2.0)


def test_jeffreys_summary_stats():
    p = jeffreys_prior()
    assert p.mean == pytest.approx(0.5)
    # Jeffreys is bimodal at 0 and 1; mode() returns the mean as a
    # single-summary convention.
    assert p.mode == pytest.approx(0.5)


def test_mode_branches_at_unity():
    # alpha > 1, beta > 1 → interior mode at (α-1)/(α+β-2)
    p = BetaPrior(3.0, 2.0)
    assert p.mode == pytest.approx(2.0 / 3.0)
    # alpha <= 1 < beta → mode at 0
    p = BetaPrior(0.5, 2.0)
    assert p.mode == pytest.approx(0.0)
    # alpha > 1, beta <= 1 → mode at 1
    p = BetaPrior(2.0, 0.5)
    assert p.mode == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Credible interval — textbook reference values
# ---------------------------------------------------------------------------


def test_uniform_credible_interval_endpoints():
    """For Beta(1, 1) the CDF is the identity, so the 95% CI is
    exactly [0.025, 0.975]. This is the cleanest closed-form check
    on the inverse-CDF bisection."""
    p = uniform_prior()
    lo, hi = p.credible_interval(0.95)
    assert lo == pytest.approx(0.025, abs=1e-6)
    assert hi == pytest.approx(0.975, abs=1e-6)


def test_credible_interval_tightens_with_data():
    """A symmetric posterior centred at 0.5 with more data has a
    narrower CI. Beta(51, 51) is much tighter than Beta(1, 1)."""
    wide = uniform_prior().credible_interval(0.95)
    tight = BetaPrior(51.0, 51.0).credible_interval(0.95)
    assert (wide[1] - wide[0]) > (tight[1] - tight[0])
    # Beta(51,51) mean = 0.5, std ~ 0.0494 → 95% CI ~ [0.405, 0.595]
    assert tight[0] == pytest.approx(0.405, abs=0.01)
    assert tight[1] == pytest.approx(0.595, abs=0.01)


def test_credible_interval_skewed_posterior():
    """Beta(91, 11) heavily favours 1 — CI should reflect that.
    Mean = 91/102 ≈ 0.892."""
    p = BetaPrior(91.0, 11.0)
    assert p.mean == pytest.approx(91.0 / 102.0)
    lo, hi = p.credible_interval(0.95)
    assert 0.8 < lo < 0.85
    assert 0.93 < hi < 0.96


def test_credible_interval_rejects_bad_level():
    p = uniform_prior()
    with pytest.raises(ValueError):
        p.credible_interval(0.0)
    with pytest.raises(ValueError):
        p.credible_interval(1.0)
    with pytest.raises(ValueError):
        p.credible_interval(-0.1)


# ---------------------------------------------------------------------------
# Conjugate updates
# ---------------------------------------------------------------------------


def test_posterior_update_degenerate_no_data():
    """Zero observations → posterior identical to prior."""
    prior = uniform_prior()
    posterior = posterior_update(prior, 0, 0)
    assert posterior.alpha == prior.alpha
    assert posterior.beta == prior.beta


def test_posterior_update_adversarial_all_failures():
    """100 failures shifts the mean toward 0; under Beta(1,1) prior
    the posterior is Beta(1, 101) → mean ≈ 1/102."""
    prior = uniform_prior()
    posterior = posterior_update(prior, 0, 100)
    assert posterior.alpha == pytest.approx(1.0)
    assert posterior.beta == pytest.approx(101.0)
    assert posterior.mean == pytest.approx(1.0 / 102.0)


def test_posterior_update_symmetric_high_n_concentrates_at_half():
    prior = uniform_prior()
    posterior = posterior_update(prior, 500, 500)
    assert posterior.mean == pytest.approx(0.5)
    # Variance shrinks by ~250x relative to prior.
    assert posterior.variance < prior.variance / 100


def test_posterior_update_rejects_negative_counts():
    prior = uniform_prior()
    with pytest.raises(ValueError):
        posterior_update(prior, -1, 0)
    with pytest.raises(ValueError):
        posterior_update(prior, 0, -1)


def test_posterior_update_chaining_matches_single_update():
    """Sequential Bayesian updates compose: posterior_update(.,
    a₁+a₂, b₁+b₂) == posterior_update(posterior_update(., a₁, b₁),
    a₂, b₂). This is the property that makes the scorecard's
    incremental updates principled."""
    prior = uniform_prior()
    one_shot = posterior_update(prior, 30, 5)
    incremental = posterior_update(
        posterior_update(prior, 17, 2), 13, 3
    )
    assert one_shot.alpha == incremental.alpha
    assert one_shot.beta == incremental.beta


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def test_weak_informative_prior_recovers_mean_and_strength():
    p = weak_informative_prior(mean=0.1, strength=10.0)
    assert p.mean == pytest.approx(0.1)
    assert p.strength == pytest.approx(10.0)
    assert p.alpha == pytest.approx(1.0)
    assert p.beta == pytest.approx(9.0)


def test_weak_informative_prior_rejects_bad_inputs():
    with pytest.raises(ValueError):
        weak_informative_prior(0.0, 10.0)
    with pytest.raises(ValueError):
        weak_informative_prior(1.0, 10.0)
    with pytest.raises(ValueError):
        weak_informative_prior(0.5, 0.0)
    with pytest.raises(ValueError):
        weak_informative_prior(0.5, -1.0)


def test_weak_informative_extreme_mean_concentrates_correctly():
    """High-strength prior centred near an endpoint should reflect
    that in both mean and mode."""
    p = weak_informative_prior(mean=0.95, strength=100.0)
    assert p.mean == pytest.approx(0.95)
    # alpha = 95, beta = 5 → interior mode = 94/98 ≈ 0.959
    assert p.mode == pytest.approx(94.0 / 98.0)


# ---------------------------------------------------------------------------
# Incomplete-beta numerics — regression bounds
# ---------------------------------------------------------------------------


def test_incomplete_beta_endpoints():
    assert _betai_regularized(2.0, 3.0, 0.0) == 0.0
    assert _betai_regularized(2.0, 3.0, 1.0) == 1.0


def test_incomplete_beta_uniform_identity():
    """I_x(1, 1) ≡ x — the uniform CDF is the identity."""
    for x in (0.1, 0.25, 0.5, 0.75, 0.9):
        assert _betai_regularized(1.0, 1.0, x) == pytest.approx(x, abs=1e-12)


def test_incomplete_beta_known_value():
    """I_{0.5}(2, 2) = 0.5 by symmetry of Beta(2,2). I_{0.5}(3, 5) =
    0.7734375 (closed form from the binomial expansion)."""
    assert _betai_regularized(2.0, 2.0, 0.5) == pytest.approx(0.5, abs=1e-9)
    assert _betai_regularized(3.0, 5.0, 0.5) == pytest.approx(
        0.7734375, abs=1e-9
    )


def test_inverse_beta_round_trip():
    """For a few representative (α, β, p), inverting and re-evaluating
    the CDF returns p within bisection tolerance."""
    for a, b in ((1.0, 1.0), (2.0, 5.0), (10.0, 10.0), (50.0, 2.0)):
        for p in (0.025, 0.1, 0.5, 0.9, 0.975):
            x = _inverse_betai(a, b, p)
            recovered = _betai_regularized(a, b, x)
            assert recovered == pytest.approx(p, abs=1e-6)


# ---------------------------------------------------------------------------
# Immutability — frozen dataclass
# ---------------------------------------------------------------------------


def test_betaprior_is_frozen():
    p = uniform_prior()
    with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
        p.alpha = 99.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# /validate-sourced informed priors (review of PR #793, item 4)
# ---------------------------------------------------------------------------


def test_validation_labels_no_data_is_uniform_cold_start():
    # No labels → exactly the uniform Beta(1,1) cold-start.
    p = prior_from_validation_labels(0, 0)
    assert (p.alpha, p.beta) == (uniform_prior().alpha, uniform_prior().beta)
    assert p.mean == pytest.approx(0.5)


def test_validation_labels_sharpen_toward_base_rate():
    # 8 exploitable, 2 disproven → Beta(9, 3), mean 0.75.
    p = prior_from_validation_labels(8, 2)
    assert (p.alpha, p.beta) == (9.0, 3.0)
    assert p.mean == pytest.approx(0.75)
    # More data tightens the prior (greater strength).
    assert p.strength > prior_from_validation_labels(1, 0).strength


def test_validation_labels_reject_negative():
    with pytest.raises(ValueError):
        prior_from_validation_labels(-1, 0)


def test_priors_from_validation_maps_per_class():
    priors = priors_from_validation({
        "py:sql-injection": (5, 1),
        "cpp:format-string": (0, 4),
        "py:xss": (0, 0),
    })
    assert priors["py:sql-injection"].mean == pytest.approx(6 / 8)
    assert priors["cpp:format-string"].mean == pytest.approx(1 / 6)
    # (0,0) degenerates to uniform.
    assert priors["py:xss"].mean == pytest.approx(0.5)


def test_priors_from_validation_absent_class_omitted_for_cold_start():
    # A class with no /validate labels is simply absent — the consumer's
    # default_prior (uniform) then applies. No silent informed prior.
    priors = priors_from_validation({"py:sql-injection": (3, 0)})
    assert "cpp:format-string" not in priors

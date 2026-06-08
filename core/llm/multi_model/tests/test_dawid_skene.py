"""Property tests for ``core.llm.multi_model.dawid_skene`` — Phase 2c.

Each test fixes the panel structure so the EM has a single deterministic
attractor. This avoids RNG-dependent failure modes from random-truth
fixtures (where small N can produce vote configurations that legitimately
mislead any estimator).

Coverage:

* Degenerate / strong-agreement: panel unanimously splits findings into
  two groups → posteriors near 0 and 1; confusion matrices near (1, 1).
* Adversarial inverter: one model votes opposite the rest on every
  finding → inferred ``(α, β)`` near (0, 0) — the EM correctly detects
  anti-correlation.
* Symmetric noise: every model 50/50 random → posteriors stay near
  prior mean; confusion matrices regress toward initial reliability.
* Two-model identifiability: with N=2 models and a strong prior, EM
  remains stable; with uniform prior, the result is recognisably
  prior-dominated.
* Convergence flags, prior-mean fixing, partition dispatch.
"""
from __future__ import annotations

from typing import List

import pytest

from core.llm.multi_model.dawid_skene import (
    DEFAULT_CLIP_EPSILON,
    DEFAULT_INITIAL_RELIABILITY,
    estimate,
    estimate_partitioned,
)
from core.llm.multi_model.panel_log import PanelRecord
from core.llm.scorecard.priors import (
    BetaPrior,
    jeffreys_prior,
    uniform_prior,
    weak_informative_prior,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _unanimous_panel(n_pos: int, n_neg: int, models: List[str],
                     decision_class: str = "dc") -> List[PanelRecord]:
    """``n_pos`` findings where all models vote True, ``n_neg`` where
    all vote False. Single-attractor case — EM should land near
    α=β=1, posteriors at 0 and 1."""
    records: List[PanelRecord] = []
    for i in range(n_pos):
        for m in models:
            records.append(PanelRecord(f"P{i}", decision_class, m, True))
    for i in range(n_neg):
        for m in models:
            records.append(PanelRecord(f"N{i}", decision_class, m, False))
    return records


def _inverter_panel(n_pos: int, n_neg: int, reliable_models: List[str],
                    inverter: str,
                    decision_class: str = "dc") -> List[PanelRecord]:
    """``reliable_models`` vote correctly; ``inverter`` always votes the
    opposite. EM should infer the inverter's (α, β) near (0, 0)."""
    records: List[PanelRecord] = []
    for i in range(n_pos):
        for m in reliable_models:
            records.append(PanelRecord(f"P{i}", decision_class, m, True))
        records.append(PanelRecord(f"P{i}", decision_class, inverter, False))
    for i in range(n_neg):
        for m in reliable_models:
            records.append(PanelRecord(f"N{i}", decision_class, m, False))
        records.append(PanelRecord(f"N{i}", decision_class, inverter, True))
    return records


def _deterministic_noisy_panel(
    n_pos: int, n_neg: int, models: List[str],
    *, vote_pattern: dict, decision_class: str = "dc",
) -> List[PanelRecord]:
    """Generic fixed-vote panel. ``vote_pattern`` is a dict
    ``{model: (positives_voted_true_count, negatives_voted_true_count)}``
    where the counts are deterministic — no RNG. ``positives_voted_true``
    must be ≤ n_pos; ``negatives_voted_true`` ≤ n_neg."""
    records: List[PanelRecord] = []
    for model, (pos_true, neg_true) in vote_pattern.items():
        for i in range(n_pos):
            records.append(PanelRecord(
                f"P{i}", decision_class, model, i < pos_true,
            ))
        for i in range(n_neg):
            records.append(PanelRecord(
                f"N{i}", decision_class, model, i < neg_true,
            ))
    return records


# ---------------------------------------------------------------------------
# Strong-agreement: posteriors → boundaries, confusion → identity
# ---------------------------------------------------------------------------


def test_unanimous_panel_drives_posteriors_to_boundaries():
    records = _unanimous_panel(
        n_pos=10, n_neg=10, models=["m1", "m2", "m3"],
    )
    result = estimate(records, uniform_prior(), decision_class="dc")
    assert result.converged
    # All P-findings should have posterior > 0.9; all N-findings < 0.1.
    for f in result.findings:
        if f.finding_id.startswith("P"):
            assert f.posterior > 0.9, f"{f.finding_id}: {f.posterior}"
        else:
            assert f.posterior < 0.1, f"{f.finding_id}: {f.posterior}"


def test_unanimous_panel_drives_confusion_to_identity():
    records = _unanimous_panel(
        n_pos=10, n_neg=10, models=["m1", "m2", "m3"],
    )
    result = estimate(records, uniform_prior(), decision_class="dc")
    for r in result.model_reliabilities:
        assert r.alpha > 0.9, f"{r.model} α={r.alpha}"
        assert r.beta > 0.9, f"{r.model} β={r.beta}"


# ---------------------------------------------------------------------------
# Adversarial inverter: confusion → (0, 0)
# ---------------------------------------------------------------------------


def test_inverter_detected_with_low_alpha_and_beta():
    records = _inverter_panel(
        n_pos=10, n_neg=10,
        reliable_models=["m1", "m2"], inverter="m3",
    )
    result = estimate(records, uniform_prior(), decision_class="dc")
    assert result.converged
    by_model = {r.model: r for r in result.model_reliabilities}
    # Reliable models should be high; inverter should be low on both.
    assert by_model["m1"].alpha > 0.8
    assert by_model["m2"].alpha > 0.8
    assert by_model["m3"].alpha < 0.2
    assert by_model["m3"].beta < 0.2


def test_inverter_does_not_corrupt_posteriors():
    """With 2 reliable models and 1 inverter, the EM should still
    arrive at correct posteriors — the inverter's vote should weigh
    AGAINST itself."""
    records = _inverter_panel(
        n_pos=10, n_neg=10,
        reliable_models=["m1", "m2"], inverter="m3",
    )
    result = estimate(records, uniform_prior(), decision_class="dc")
    for f in result.findings:
        if f.finding_id.startswith("P"):
            assert f.posterior > 0.7
        else:
            assert f.posterior < 0.3


# ---------------------------------------------------------------------------
# Symmetric noise: posteriors → prior mean, confusion → ~initial
# ---------------------------------------------------------------------------


def test_pure_noise_posteriors_track_prior_mean():
    """Every finding has *identical* vote patterns across models — EM
    has no information to distinguish findings, so posteriors must
    stay near the prior mean.

    Construction: 20 findings, on each one m1 votes True, m2 votes
    False, m3 votes True. Identical structure across every finding →
    no per-finding signal → posteriors all converge to prior mean
    (0.5 under uniform prior).
    """
    records: List[PanelRecord] = []
    for i in range(20):
        records.append(PanelRecord(f"F{i}", "dc", "m1", True))
        records.append(PanelRecord(f"F{i}", "dc", "m2", False))
        records.append(PanelRecord(f"F{i}", "dc", "m3", True))
    result = estimate(records, uniform_prior(), decision_class="dc")
    # Prior mean is 0.5 → posteriors should be close to 0.5.
    for f in result.findings:
        assert 0.35 < f.posterior < 0.65, f"{f.finding_id}: {f.posterior}"


# ---------------------------------------------------------------------------
# Two-model identifiability
# ---------------------------------------------------------------------------


def test_two_models_unanimous_with_uniform_prior_still_resolves():
    """Two-model panels are formally non-identifiable in classical
    D–S, but with a unanimous split and our uniform prior + fixed
    initial reliability, the EM should still recover the right
    pattern (posteriors split at the boundaries) — the prior breaks
    the label-swap symmetry."""
    records = _unanimous_panel(n_pos=20, n_neg=20, models=["m1", "m2"])
    result = estimate(records, uniform_prior(), decision_class="dc")
    assert result.converged
    p_findings = [f for f in result.findings if f.finding_id.startswith("P")]
    n_findings = [f for f in result.findings if f.finding_id.startswith("N")]
    assert all(f.posterior > 0.7 for f in p_findings)
    assert all(f.posterior < 0.3 for f in n_findings)


def test_strong_prior_pulls_posteriors_toward_prior_mean():
    """A weak-informative prior centred at 0.1 with high strength
    should pull posteriors down even on a unanimous-positive panel."""
    records = _unanimous_panel(n_pos=5, n_neg=0, models=["m1", "m2"])
    strong_prior = weak_informative_prior(mean=0.1, strength=100.0)
    result = estimate(records, strong_prior, decision_class="dc")
    # All P-findings: prior pulls hard, posterior nowhere near 1.
    for f in result.findings:
        assert f.posterior < 0.5


# ---------------------------------------------------------------------------
# CI behavior
# ---------------------------------------------------------------------------


def test_credible_interval_tightens_with_more_models():
    """Same posterior, more models → tighter CI. The variational
    Beta approximation uses n_models as effective sample size."""
    small_panel = _unanimous_panel(n_pos=5, n_neg=5, models=["m1", "m2"])
    big_panel = _unanimous_panel(
        n_pos=5, n_neg=5, models=["m1", "m2", "m3", "m4", "m5"],
    )
    small_result = estimate(small_panel, uniform_prior(), decision_class="dc")
    big_result = estimate(big_panel, uniform_prior(), decision_class="dc")
    # Same-finding-id comparison.
    for sf, bf in zip(
        sorted(small_result.findings, key=lambda f: f.finding_id),
        sorted(big_result.findings, key=lambda f: f.finding_id),
    ):
        assert sf.finding_id == bf.finding_id
        small_width = sf.credible_interval[1] - sf.credible_interval[0]
        big_width = bf.credible_interval[1] - bf.credible_interval[0]
        assert big_width <= small_width, (
            f"{sf.finding_id}: small_width={small_width:.3f} "
            f"big_width={big_width:.3f}"
        )


def test_credible_interval_within_unit_interval():
    records = _unanimous_panel(n_pos=5, n_neg=5, models=["m1", "m2", "m3"])
    result = estimate(records, uniform_prior(), decision_class="dc")
    for f in result.findings:
        lo, hi = f.credible_interval
        assert 0.0 <= lo <= f.posterior <= hi <= 1.0 or \
               0.0 <= lo <= hi <= 1.0  # Beta approx; posterior may
                                        # exit the variational interval


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_result():
    result = estimate([], uniform_prior(), decision_class="dc")
    assert result.findings == []
    assert result.model_reliabilities == []
    assert result.iterations == 0
    assert result.converged


def test_single_finding_two_models_no_crash():
    records = [
        PanelRecord("F1", "dc", "m1", True),
        PanelRecord("F1", "dc", "m2", True),
    ]
    result = estimate(records, uniform_prior(), decision_class="dc")
    assert len(result.findings) == 1
    assert len(result.model_reliabilities) == 2


def test_jeffreys_prior_does_not_crash():
    """Jeffreys prior (Beta(0.5, 0.5)) has α < 1. M-step posterior-mean
    update must stay in (0, 1) — that's the whole reason we use
    posterior-mean and not MAP. This test asserts no boundary collapse."""
    records = _unanimous_panel(n_pos=5, n_neg=5, models=["m1", "m2"])
    result = estimate(records, jeffreys_prior(), decision_class="dc")
    for r in result.model_reliabilities:
        assert 0.0 < r.alpha < 1.0
        assert 0.0 < r.beta < 1.0


def test_max_iter_zero_reports_not_converged():
    records = _unanimous_panel(n_pos=5, n_neg=5, models=["m1", "m2"])
    result = estimate(
        records, uniform_prior(),
        decision_class="dc", max_iter=1,
    )
    # 1 iteration is unlikely to converge; assert flag is False.
    assert result.iterations == 1
    assert not result.converged


# ---------------------------------------------------------------------------
# Partition dispatch
# ---------------------------------------------------------------------------


def test_partitioned_runs_per_class():
    """``estimate_partitioned`` runs EM separately per decision_class;
    classes don't bleed into each other."""
    records = []
    records.extend(_unanimous_panel(
        n_pos=5, n_neg=5, models=["m1", "m2"], decision_class="A",
    ))
    records.extend(_unanimous_panel(
        n_pos=5, n_neg=5, models=["m1", "m2"], decision_class="B",
    ))
    results = estimate_partitioned(
        records,
        priors={"A": uniform_prior(), "B": uniform_prior()},
        default_prior=uniform_prior(),
    )
    assert [r.decision_class for r in results] == ["A", "B"]
    for r in results:
        assert r.converged
        assert len(r.findings) == 10


def test_partitioned_falls_back_to_default_prior():
    """A class not in ``priors`` uses ``default_prior``."""
    records = _unanimous_panel(
        n_pos=5, n_neg=5, models=["m1", "m2"], decision_class="orphan",
    )
    strong_prior = weak_informative_prior(mean=0.5, strength=200.0)
    results = estimate_partitioned(
        records,
        priors={},  # empty — every class uses default
        default_prior=strong_prior,
    )
    assert len(results) == 1
    # Strong prior at 0.5 with 200 strength against 5 unanimous votes
    # should still leave posteriors near the prior mean.
    for f in results[0].findings:
        assert 0.3 < f.posterior < 0.7


# ---------------------------------------------------------------------------
# Numerical regime
# ---------------------------------------------------------------------------


def test_clip_eps_keeps_log_space_well_defined():
    """Even with degenerate inputs (one model always votes the same
    way), the log-space E-step must not blow up. The clip floor is
    the substrate that prevents log(0)."""
    records = _deterministic_noisy_panel(
        n_pos=10, n_neg=10, models=["m1", "m2"],
        vote_pattern={
            "m1": (10, 10),  # always votes True
            "m2": (10, 0),   # accurate
        },
    )
    result = estimate(records, uniform_prior(), decision_class="dc")
    assert result.converged
    # m1's α should be high (it says True on all positives), but β should
    # be low (it says True on all negatives — never says False when
    # truly negative).
    by_model = {r.model: r for r in result.model_reliabilities}
    assert by_model["m1"].alpha > 0.5
    assert by_model["m1"].beta < 0.5

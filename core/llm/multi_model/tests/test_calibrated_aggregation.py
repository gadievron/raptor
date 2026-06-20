"""Tests for ``core.llm.multi_model.calibrated_aggregation`` — Phase 3a.

Covers the entry-point semantics that the orchestrator wire-up
(Phase 3b) will rely on:

* Multi-model findings → D–S verdict, method = ``dawid_skene``.
* Single-model / no-panel findings → vote fallback, method = ``vote``,
  fallback reason populated.
* Per-class partitioning matches ``estimate_partitioned`` behavior.
* Prior dispatch: ``priors_by_class`` overrides ``default_prior``;
  unknown classes use the default.
* JSON-shape helper round-trips through ``save_json``-compatible dict.
"""
from __future__ import annotations

import json


from core.llm.multi_model.calibrated_aggregation import (
    METHOD_DAWID_SKENE,
    METHOD_VOTE,
    calibrate_results,
    verdict_to_json,
)
from core.llm.scorecard.priors import (
    uniform_prior,
    weak_informative_prior,
)


def _make_finding(fid: str, rule_id: str, *,
                  is_exploitable=None, analyses=None) -> dict:
    f = {"finding_id": fid, "rule_id": rule_id}
    if is_exploitable is not None:
        f["is_exploitable"] = is_exploitable
    if analyses is not None:
        f["multi_model_analyses"] = analyses
    return f


def _entry(model: str, is_exploitable: bool, **extra) -> dict:
    out = {"model": model, "is_exploitable": is_exploitable}
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_multi_model_finding_uses_dawid_skene():
    results = {
        "F1": _make_finding("F1", "rule-a", analyses=[
            _entry("m1", True), _entry("m2", True), _entry("m3", False),
        ]),
    }
    verdicts = calibrate_results(results)
    assert verdicts["F1"].aggregation_method == METHOD_DAWID_SKENE
    assert verdicts["F1"].aggregation_fallback_reason is None
    assert verdicts["F1"].n_models == 3
    assert verdicts["F1"].decision_class == "agentic:rule-a"
    assert 0.0 <= verdicts["F1"].posterior_true_positive <= 1.0


def test_unanimous_panel_gives_strong_posterior_with_many_findings():
    """When EM has enough findings to identify reliable models, the
    posterior on a unanimous-positive finding should be near 1."""
    results = {}
    # 10 P findings + 10 N findings, all unanimous across 3 models.
    for i in range(10):
        results[f"P{i}"] = _make_finding(
            f"P{i}", "rule-a", analyses=[
                _entry("m1", True), _entry("m2", True), _entry("m3", True),
            ],
        )
        results[f"N{i}"] = _make_finding(
            f"N{i}", "rule-a", analyses=[
                _entry("m1", False), _entry("m2", False), _entry("m3", False),
            ],
        )
    verdicts = calibrate_results(results)
    for fid, v in verdicts.items():
        if fid.startswith("P"):
            assert v.posterior_true_positive > 0.9, f"{fid}: {v}"
        else:
            assert v.posterior_true_positive < 0.1, f"{fid}: {v}"


def test_model_reliabilities_attached():
    """Each D–S verdict should carry the per-model (α, β) inferred for
    its decision class. Phase 4 reads these for posterior-weighted
    scorecard updates."""
    results = {
        f"F{i}": _make_finding(f"F{i}", "rule-a", analyses=[
            _entry("m1", True), _entry("m2", False),
        ]) for i in range(5)
    }
    verdicts = calibrate_results(results)
    v = verdicts["F0"]
    assert len(v.model_reliabilities) == 2
    models = {r["model"] for r in v.model_reliabilities}
    assert models == {"m1", "m2"}
    for r in v.model_reliabilities:
        assert 0.0 < r["alpha"] < 1.0
        assert 0.0 < r["beta"] < 1.0


# ---------------------------------------------------------------------------
# Vote fallback
# ---------------------------------------------------------------------------


def test_finding_without_multi_model_analyses_falls_back_to_vote():
    results = {
        "F1": _make_finding("F1", "rule-a", is_exploitable=True),
    }
    verdicts = calibrate_results(results)
    assert verdicts["F1"].aggregation_method == METHOD_VOTE
    assert verdicts["F1"].aggregation_fallback_reason == "no_panel"
    assert verdicts["F1"].n_models == 0
    assert verdicts["F1"].posterior_true_positive == 1.0


def test_vote_fallback_negative_finding():
    results = {
        "F1": _make_finding("F1", "rule-a", is_exploitable=False),
    }
    verdicts = calibrate_results(results)
    assert verdicts["F1"].posterior_true_positive == 0.0
    assert verdicts["F1"].credible_interval == (0.0, 0.0)


def test_vote_fallback_missing_is_exploitable():
    results = {
        "F1": _make_finding("F1", "rule-a"),  # no is_exploitable
    }
    verdicts = calibrate_results(results)
    # Missing or non-True → treated as 0.0 (matches legacy truthy check).
    assert verdicts["F1"].posterior_true_positive == 0.0


def test_single_valid_panel_entry_falls_back_to_vote():
    """Even with ``multi_model_analyses`` present, if only one entry
    is valid the finding doesn't have a real panel."""
    results = {
        "F1": _make_finding("F1", "rule-a",
                            is_exploitable=True,
                            analyses=[
                                _entry("m1", True),
                                {"error": "rate limit", "model": "m2"},
                            ]),
    }
    verdicts = calibrate_results(results)
    assert verdicts["F1"].aggregation_method == METHOD_VOTE
    assert "insufficient_panel_size" in verdicts["F1"].aggregation_fallback_reason
    assert verdicts["F1"].posterior_true_positive == 1.0  # from is_exploitable


def test_all_error_panel_falls_back():
    results = {
        "F1": _make_finding("F1", "rule-a",
                            is_exploitable=False,
                            analyses=[
                                {"error": "x", "model": "m1"},
                                {"error": "y", "model": "m2"},
                            ]),
    }
    verdicts = calibrate_results(results)
    assert verdicts["F1"].aggregation_method == METHOD_VOTE
    assert verdicts["F1"].aggregation_fallback_reason == "no_panel"


# ---------------------------------------------------------------------------
# Per-class partition
# ---------------------------------------------------------------------------


def test_findings_partitioned_by_decision_class():
    """Two decision classes should run separate EMs — a model's
    reliability on class A doesn't influence its inferred reliability
    on class B.

    Class A uses three models so the label-swap symmetry breaks
    (m1 + m2 reliable, m3 inverter); a 2-model adversarial fixture
    would have no information content to distinguish positives from
    negatives and would converge to the degenerate (α=β=0.5) fixed
    point.
    """
    results = {}
    # Class A: m1 + m2 reliable, m3 inverter
    for i in range(10):
        results[f"A_P{i}"] = _make_finding(
            f"A_P{i}", "rule-a", analyses=[
                _entry("m1", True), _entry("m2", True), _entry("m3", False),
            ],
        )
        results[f"A_N{i}"] = _make_finding(
            f"A_N{i}", "rule-a", analyses=[
                _entry("m1", False), _entry("m2", False), _entry("m3", True),
            ],
        )
    # Class B: m1 + m2 reliable; m3 is the only model that wasn't on
    # class A, so its reliability is independent
    for i in range(10):
        results[f"B_P{i}"] = _make_finding(
            f"B_P{i}", "rule-b", analyses=[
                _entry("m1", True), _entry("m2", True),
            ],
        )
        results[f"B_N{i}"] = _make_finding(
            f"B_N{i}", "rule-b", analyses=[
                _entry("m1", False), _entry("m2", False),
            ],
        )
    verdicts = calibrate_results(results)
    # Class A: m3 (the inverter) should have low α and β
    a_verdict = verdicts["A_P0"]
    a_models = {r["model"]: r for r in a_verdict.model_reliabilities}
    assert "m3" in a_models, "class A should include m3 reliability"
    assert "m3" not in {r["model"] for r in verdicts["B_P0"].model_reliabilities}, \
        "class B should not include m3 — confirms partition isolation"
    assert a_models["m1"]["alpha"] > 0.7
    assert a_models["m2"]["alpha"] > 0.7
    assert a_models["m3"]["alpha"] < 0.3
    # Class B: both models high reliability
    b_verdict = verdicts["B_P0"]
    b_models = {r["model"]: r for r in b_verdict.model_reliabilities}
    assert b_models["m1"]["alpha"] > 0.7
    assert b_models["m2"]["alpha"] > 0.7


def test_priors_by_class_overrides_default():
    """A strong prior on the class should pull posteriors toward the
    prior mean, even on a unanimous-positive panel."""
    results = {
        f"F{i}": _make_finding(f"F{i}", "rule-x", analyses=[
            _entry("m1", True), _entry("m2", True),
        ]) for i in range(5)
    }
    strong_prior = weak_informative_prior(mean=0.05, strength=200.0)
    verdicts = calibrate_results(
        results,
        default_prior=uniform_prior(),
        priors_by_class={"agentic:rule-x": strong_prior},
    )
    # Posteriors should be pulled way down from "unanimous yes".
    for v in verdicts.values():
        assert v.posterior_true_positive < 0.3


def test_unknown_class_uses_default_prior():
    results = {
        f"F{i}": _make_finding(f"F{i}", "rule-y", analyses=[
            _entry("m1", True), _entry("m2", True),
        ]) for i in range(5)
    }
    strong_prior = weak_informative_prior(mean=0.05, strength=200.0)
    # priors_by_class has no entry for "agentic:rule-y" → falls to default.
    verdicts = calibrate_results(
        results,
        default_prior=strong_prior,
        priors_by_class={"agentic:other-rule": uniform_prior()},
    )
    for v in verdicts.values():
        assert v.posterior_true_positive < 0.3


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------


def test_verdict_to_json_round_trips():
    results = {
        "F1": _make_finding("F1", "rule-a", analyses=[
            _entry("m1", True), _entry("m2", False),
        ]),
    }
    verdicts = calibrate_results(results)
    payload = verdict_to_json(verdicts["F1"])
    # Round-trip through json to confirm all values are serializable.
    recovered = json.loads(json.dumps(payload))
    assert recovered["aggregation_method"] in (METHOD_DAWID_SKENE, METHOD_VOTE)
    assert isinstance(recovered["credible_interval"], list)
    assert len(recovered["credible_interval"]) == 2
    assert isinstance(recovered["n_models"], int)
    assert isinstance(recovered["posterior_true_positive"], float)


def test_verdict_to_json_handles_vote_fallback():
    results = {
        "F1": _make_finding("F1", "rule-a", is_exploitable=True),
    }
    verdicts = calibrate_results(results)
    payload = verdict_to_json(verdicts["F1"])
    recovered = json.loads(json.dumps(payload))
    assert recovered["aggregation_method"] == METHOD_VOTE
    assert recovered["aggregation_fallback_reason"] == "no_panel"
    assert recovered["model_reliabilities"] == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_results_returns_empty():
    assert calibrate_results({}) == {}


def test_every_finding_appears_in_output():
    """Whether D–S runs or falls back to vote, every input finding
    must show up in the output. Phase 3b will rely on this for safe
    .get() lookups."""
    results = {
        "with_panel": _make_finding("with_panel", "x", analyses=[
            _entry("m1", True), _entry("m2", False),
        ]),
        "no_panel": _make_finding("no_panel", "x", is_exploitable=True),
        "empty_panel": _make_finding("empty_panel", "x", analyses=[]),
    }
    verdicts = calibrate_results(results)
    assert set(verdicts.keys()) == set(results.keys())


def test_custom_decision_class_prefix():
    results = {
        "F1": _make_finding("F1", "rule-a", analyses=[
            _entry("m1", True), _entry("m2", True),
        ]),
    }
    verdicts = calibrate_results(
        results, decision_class_prefix="codeql",
    )
    assert verdicts["F1"].decision_class == "codeql:rule-a"

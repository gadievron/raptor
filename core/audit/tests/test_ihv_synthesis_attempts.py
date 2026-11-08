"""Every completed immediate synthesis attempt consumes its attempt count."""

import pytest

from core.audit import checker_synthesis
from core.audit import orchestrator as orch


def _request(tmp_path):
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    outcome = orch.ReviewOutcome(file="a.c", function="f", status="suspicious", body="Unresolved",
                                hypothesis="discarded error", review_result={"hypothesis": "discarded error"})
    return cfg, outcome, orch.OrchestratorResult()


def _attempt(cfg, outcome, result):
    return orch._try_ihv_synthesis(outcome, cfg, result, {"mechanism": outcome.hypothesis}, "CWE-252", "")


@pytest.mark.parametrize("confirmed,cost", [(True, 0.07), (False, 0.03), (False, 0.0)])
def test_attempt_count_does_not_depend_on_confirmation_or_price(tmp_path, monkeypatch, confirmed, cost):
    cfg, outcome, result = _request(tmp_path)
    seen = []

    def attempted(candidate, config, **kwargs):
        seen.append(kwargs["synthesis_count"])
        return checker_synthesis.OnDemandSynthesisResult(confirmed=confirmed,
            stamp="semgrep:independent-check" if confirmed else "", cost_usd=cost)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", attempted)
    stamp = _attempt(cfg, outcome, result)
    assert seen == [0]
    assert result.ondemand_synthesized == 1
    assert result.total_cost_usd == pytest.approx(cost)
    assert stamp == ("semgrep:independent-check" if confirmed else None)


def test_unconfirmed_attempts_advance_the_producer_cap_input(tmp_path, monkeypatch):
    cfg, outcome, result = _request(tmp_path)
    counts, attempts = [], []

    def capped(candidate, config, **kwargs):
        counts.append(kwargs["synthesis_count"])
        if kwargs["synthesis_count"] >= 2:
            return None
        attempts.append(candidate.hypothesis)
        return checker_synthesis.OnDemandSynthesisResult(cost_usd=0.01)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", capped)
    for _ in range(3):
        assert _attempt(cfg, outcome, result) is None
    assert counts == [0, 1, 2]
    assert len(attempts) == result.ondemand_synthesized == 2
    assert result.total_cost_usd == pytest.approx(0.02)


def test_skipped_synthesis_does_not_consume_an_attempt(tmp_path, monkeypatch):
    cfg, outcome, result = _request(tmp_path)
    seen = []

    def unavailable(*args, **kwargs):
        seen.append(kwargs["synthesis_count"])
        return None

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", unavailable)
    assert _attempt(cfg, outcome, result) is None
    assert seen == [0]
    assert result.ondemand_synthesized == 0
    assert result.total_cost_usd == 0

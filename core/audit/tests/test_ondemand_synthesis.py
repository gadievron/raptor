"""Tests for on-demand Mode-2 checker synthesis — the verification
channel for chain-less suspicious hypotheses. No real LLM or engine
calls: the synthesis substrate and tool chain are stubbed."""

from __future__ import annotations

from types import SimpleNamespace
from typing import ClassVar

from packages.checker_synthesis.models import (
    CheckerSynthesisResult,
    SeedBug,
    SynthesisedRule,
)


class _FakeLLMClient:
    def __init__(self):
        self.total_cost = 0.0
        self.model_name = "stub-model"
        # Mirrors LLMClient's per-class cost history — synthesis cost
        # attribution reads the checker_synthesis class delta (the
        # shared budget client's total_cost moves with every
        # concurrent call class).
        self._call_cost_history: dict = {}

    def note(self, cost, call_class="checker_synthesis"):
        n, total = self._call_cost_history.get(call_class, (0, 0.0))
        self._call_cost_history[call_class] = (n + 1, total + cost)
        self.total_cost += cost


def _fake_llm_pair(monkeypatch, cost_per_call=0.05):
    """Patch _build_llm_callable to a stub pair; return the client."""
    client = _FakeLLMClient()

    def _callable(prompt, schema, system_prompt):
        client.note(cost_per_call)

    monkeypatch.setattr(
        "core.audit.checker_synthesis._build_llm_callable",
        lambda config: (_callable, client),
    )
    return client


def _cs_result(
    *, rule=True, positive=True, dual=True, engine="semgrep",
    rule_id="ondemand-1",
):
    seed = SeedBug(
        file="a.c", function="f", line_start=1, line_end=1,
        cwe="CWE-1234", reasoning="hyp", snippet="",
    )
    cs = CheckerSynthesisResult(seed=seed)
    if rule:
        cs.rule = SynthesisedRule(
            engine=engine, rule_id=rule_id, body="rule-body",
            rationale="r",
        )
    cs.positive_control = positive
    cs.dual_control = dual
    return cs


def _stub_synthesise(monkeypatch, cs, client=None, cost=0.05):
    def _run(seed, **kwargs):
        if client is not None:
            client.note(cost)
        return cs

    monkeypatch.setattr(
        "packages.checker_synthesis.synthesise.synthesise_and_run", _run,
    )


class _StubLibrary:
    calls: ClassVar[list[dict]] = []

    def add_rule(self, **kwargs):
        _StubLibrary.calls.append(kwargs)


def _stub_library(monkeypatch):
    _StubLibrary.calls = []
    import packages.checker_synthesis as pkg
    monkeypatch.setattr(pkg, "RuleLibrary", _StubLibrary)
    return _StubLibrary


def _outcome(status="suspicious", hypothesis="off-by-one in ring buffer wrap"):
    from core.audit.orchestrator import ReviewOutcome
    o = ReviewOutcome(
        file="a.c", function="f", status=status,
        body="looks off", hypothesis=hypothesis, line=3,
    )
    o.review_result = {"hypothesis": hypothesis}
    return o


def _config(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=tmp_path, out_dir=out)


class TestSynthesizeVerificationRule:
    def test_cap_reached_returns_none(self, tmp_path, monkeypatch):
        from core.audit.checker_synthesis import (
            MAX_ONDEMAND_SYNTHESIS_PER_RUN,
            synthesize_verification_rule,
        )
        monkeypatch.setattr(
            "core.audit.checker_synthesis._build_llm_callable",
            lambda config: (_ for _ in ()).throw(
                AssertionError("LLM must not be built past the cap"),
            ),
        )
        assert synthesize_verification_rule(
            _outcome(), _config(tmp_path),
            synthesis_count=MAX_ONDEMAND_SYNTHESIS_PER_RUN,
        ) is None

    def test_clean_outcome_skipped(self, tmp_path, monkeypatch):
        from core.audit.checker_synthesis import (
            synthesize_verification_rule,
        )
        _fake_llm_pair(monkeypatch)
        assert synthesize_verification_rule(
            _outcome(status="clean"), _config(tmp_path),
        ) is None

    def test_missing_hypothesis_skipped(self, tmp_path, monkeypatch):
        from core.audit.checker_synthesis import (
            synthesize_verification_rule,
        )
        _fake_llm_pair(monkeypatch)
        assert synthesize_verification_rule(
            _outcome(hypothesis=""), _config(tmp_path),
        ) is None

    def test_confirmed_rule_returns_stamp_and_persists(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.checker_synthesis import (
            synthesize_verification_rule,
        )
        client = _fake_llm_pair(monkeypatch)
        _stub_synthesise(
            monkeypatch, _cs_result(), client=client, cost=0.07,
        )
        lib = _stub_library(monkeypatch)

        synth = synthesize_verification_rule(
            _outcome(), _config(tmp_path), cwe="CWE-1234",
        )

        assert synth is not None
        assert synth.confirmed is True
        assert synth.stamp == "semgrep:synth-ondemand-1"
        assert synth.cwe == "CWE-1234"
        assert abs(synth.cost_usd - 0.07) < 1e-9
        assert len(lib.calls) == 1
        assert lib.calls[0]["source"] == "audit-ondemand"
        assert lib.calls[0]["rule_id"] == "ondemand-1"

    def test_dual_control_failure_not_confirmed(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.checker_synthesis import (
            synthesize_verification_rule,
        )
        client = _fake_llm_pair(monkeypatch)
        _stub_synthesise(
            monkeypatch, _cs_result(dual=False), client=client,
        )
        lib = _stub_library(monkeypatch)

        synth = synthesize_verification_rule(_outcome(), _config(tmp_path))

        assert synth is not None
        assert synth.confirmed is False
        assert synth.stamp == ""
        assert lib.calls == []

    def test_no_rule_still_reports_attempt_cost(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.checker_synthesis import (
            synthesize_verification_rule,
        )
        client = _fake_llm_pair(monkeypatch)
        _stub_synthesise(
            monkeypatch, _cs_result(rule=False), client=client, cost=0.03,
        )

        synth = synthesize_verification_rule(_outcome(), _config(tmp_path))

        assert synth is not None
        assert synth.confirmed is False
        assert abs(synth.cost_usd - 0.03) < 1e-9


class TestOnDemandHookInPromoteSuspicious:
    def _patch_environment(self, monkeypatch, chain=None):
        monkeypatch.setattr(
            "core.audit.orchestrator._hypothesis_to_tool_chain",
            lambda *a, **kw: list(chain or []),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: SimpleNamespace(hits=[]),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int f(void) { return 0; }",
        )

    def _patch_synth(self, monkeypatch, retval):
        calls = []

        def fake(outcome, config, **kwargs):
            calls.append(kwargs)
            return retval

        monkeypatch.setattr(
            "core.audit.checker_synthesis.synthesize_verification_rule",
            fake,
        )
        return calls

    def _result(self, outcomes):
        from core.audit.orchestrator import OrchestratorResult
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
        r.findings = sum(1 for o in outcomes if o.status == "finding")
        return r

    def test_confirmed_synthesis_promotes(self, tmp_path, monkeypatch):
        from core.audit.checker_synthesis import OnDemandSynthesisResult
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(monkeypatch)
        calls = self._patch_synth(monkeypatch, OnDemandSynthesisResult(
            stamp="semgrep:synth-ondemand-1",
            rule_id="ondemand-1",
            tool="semgrep",
            content="rule-body",
            cwe="CWE-1234",
            confirmed=True,
            cost_usd=0.02,
        ))
        outcome = _outcome()
        result = self._result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        assert len(calls) == 1
        promoted = result.outcomes[0]
        assert promoted.status == "finding"
        assert promoted.evidence_tool == "semgrep:synth-ondemand-1"
        assert result.sweep_promoted == 1
        assert result.suspicious == 0
        assert result.findings == 1
        assert result.ondemand_synthesized == 1
        assert abs(result.total_cost_usd - 0.02) < 1e-9
        tc = result.tier_counters["synthesis_on_demand"]
        assert tc.confirmed == 1

    def test_unconfirmed_stays_suspicious(self, tmp_path, monkeypatch):
        from core.audit.checker_synthesis import OnDemandSynthesisResult
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(monkeypatch)
        self._patch_synth(monkeypatch, OnDemandSynthesisResult(
            cwe="CWE-1234", confirmed=False, cost_usd=0.02,
        ))
        outcome = _outcome()
        result = self._result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        assert result.outcomes[0].status == "suspicious"
        assert result.ondemand_synthesized == 1
        tc = result.tier_counters["synthesis_on_demand"]
        assert tc.inconclusive == 1
        assert tc.confirmed == 0

    def test_opt_out_flag_disables(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(monkeypatch)
        calls = self._patch_synth(monkeypatch, None)
        outcome = _outcome()
        result = self._result([outcome])
        config = _config(tmp_path)
        config.on_demand_synthesis = False

        _promote_suspicious(result, config)

        assert not calls
        assert result.outcomes[0].status == "suspicious"

    def test_skipped_attempt_not_counted(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(monkeypatch)
        self._patch_synth(monkeypatch, None)  # cap reached / no LLM
        outcome = _outcome()
        result = self._result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        assert result.ondemand_synthesized == 0
        tc = result.tier_counters["synthesis_on_demand"]
        assert tc.confirmed == 0
        assert tc.inconclusive == 0

    def test_nonempty_chain_bypasses_synthesis(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(
            monkeypatch, chain=[{"type": "smt", "config": {"verb": "x"}}],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: [],
        )
        calls = self._patch_synth(monkeypatch, None)
        outcome = _outcome()
        result = self._result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        assert not calls
        assert result.outcomes[0].status == "suspicious"

    def test_attempt_cap_passed_through(self, tmp_path, monkeypatch):
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(monkeypatch)
        calls = self._patch_synth(monkeypatch, None)
        outcome = _outcome()
        result = self._result([outcome])
        result.ondemand_synthesized = 7

        _promote_suspicious(result, _config(tmp_path))

        assert len(calls) == 1
        assert calls[0]["synthesis_count"] == 7

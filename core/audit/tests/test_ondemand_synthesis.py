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


def _fake_llm_pair(monkeypatch, cost_per_call=0.05):
    """Patch _build_llm_callable to a stub pair; return the client.

    Cost attribution contract: the CALLABLE accumulates its own
    calls' spend on ``cost_usd`` (per-callable attribution — reading
    the shared client's per-class history cross-attributed concurrent
    synthesis callers).
    """
    client = _FakeLLMClient()

    def _callable(prompt, schema, system_prompt):
        _callable.cost_usd += cost_per_call

    _callable.cost_usd = 0.0
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
        # The real engine's LLM calls route through the callable,
        # which accumulates its own spend.
        llm = kwargs.get("llm")
        if llm is not None and hasattr(llm, "cost_usd"):
            llm.cost_usd += cost
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
    # The lane requires a stated harm (harm gate): the structured
    # impact primitive stands in for a concrete CWE here — see
    # test_cwe_dispatch_policy.py for the refusal paths.
    o.review_result = {
        "hypothesis": hypothesis,
        "impact": {"primitive": "write"},
    }
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

    def test_secondary_sweep_routes_aliasing_mechanism_to_synthesis(
        self, tmp_path, monkeypatch,
    ):
        """The real corpus scenario: primary hypothesis is integer
        overflow (CWE-190), but mechanism #4 is an aliasing UAF
        (CWE-416). The secondary sweep should route that mechanism
        to synthesis via chain exhaustion."""
        from core.audit.orchestrator import _dispatch_secondary_hypotheses

        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int _aead_recvmsg(void) { return 0; }",
        )

        synth_calls: list[tuple] = []
        _real_synth = None
        try:
            from core.audit.orchestrator import (
                _synthesize_unmapped_suspicious as _real,
            )
            _real_synth = _real
        except ImportError:
            pass

        def fake_synth(result, config, i, outcome, hyp, cwe, source, **kw):
            synth_calls.append((hyp, cwe))

        monkeypatch.setattr(
            "core.audit.orchestrator._synthesize_unmapped_suspicious",
            fake_synth,
        )

        outcome = _outcome(
            hypothesis=(
                "Integer underflow in decryption output length "
                "calculation when auth tag size exceeds available data"
            ),
        )
        outcome.review_result["cwe"] = "CWE-190"
        outcome.file = "crypto/algif_aead.c"
        outcome.function = "_aead_recvmsg"
        outcome.hypotheses = [
            {
                "mechanism": (
                    "Integer underflow in decryption output length "
                    "calculation when auth tag size exceeds available data"
                ),
                "confidence": "high",
            },
            {
                "mechanism": (
                    "Aliasing vulnerability: memcpy_sglist copies data "
                    "from TX SGL to RX SGL. If source and destination "
                    "reference the same page frames, the decryption "
                    "frees pages via the source scatterlist that are "
                    "still referenced by the destination"
                ),
                "confidence": "medium",
            },
        ]
        result = self._result([outcome])

        _dispatch_secondary_hypotheses(
            result, _config(tmp_path), joern_server=None,
        )

        assert any(
            "CWE-416" in cwe for _, cwe in synth_calls
        ), (
            f"synthesis must fire for CWE-416 aliasing mechanism; "
            f"got calls: {synth_calls}"
        )

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

    def test_empty_chain_routes_to_synthesis(self, tmp_path, monkeypatch):
        """When the LLM router drops the standing chain (not dominated),
        the empty chain routes to synthesis."""
        from core.audit.orchestrator import _promote_suspicious

        aliasing_hyp = (
            "scatterlist aliasing — src and dst reference the same "
            "pages; free through src invalidates dst"
        )
        self._patch_environment(monkeypatch)
        monkeypatch.setattr(
            "core.audit.orchestrator._effective_cwe",
            lambda *a, **kw: "CWE-416",
        )
        calls = self._patch_synth(monkeypatch, None)
        outcome = _outcome(hypothesis=aliasing_hyp)
        outcome.review_result["cwe"] = "CWE-416"
        result = self._result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        assert len(calls) == 1

    def test_chain_exhaustion_routes_to_synthesis(self, tmp_path, monkeypatch):
        """When the tool chain ran but nothing confirmed, and the CWE
        has dark_verify, synthesis fires as a fallback."""
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(
            monkeypatch,
            chain=[{"type": "coccinelle", "config": {"rule": "x.cocci"}}],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._effective_cwe",
            lambda *a, **kw: "CWE-416",
        )
        calls = self._patch_synth(monkeypatch, None)
        outcome = _outcome(
            hypothesis="use after free in error cleanup path",
        )
        outcome.review_result["cwe"] = "CWE-416"
        result = self._result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        assert len(calls) == 1

    def test_chain_exhaustion_no_dark_verify_stays_quiet(
        self, tmp_path, monkeypatch,
    ):
        """Chain exhaustion without dark_verify does not route to
        synthesis — the tools adjudicated and the hypothesis stays
        suspicious."""
        from core.audit.orchestrator import _promote_suspicious

        self._patch_environment(
            monkeypatch,
            chain=[{"type": "smt", "config": {"verb": "check-oob"}}],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._effective_cwe",
            lambda *a, **kw: "CWE-120",
        )
        calls = self._patch_synth(monkeypatch, None)
        outcome = _outcome()
        outcome.review_result["cwe"] = "CWE-120"
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


class TestSynthesisHypothesisForCwe:
    """Re-pair the synthesis hypothesis with the text that carries the
    inferred CWE — the long instrumented run synthesized a CWE-778
    checker whose promotion logged the no-harm sibling hypothesis."""

    def _outcome(self, primary, mechanisms, *, inferred=None, declared=None):
        o = _outcome(hypothesis=primary)
        o.hypotheses = [{"mechanism": m} for m in mechanisms]
        o.review_result = {}
        if inferred:
            o.review_result["cwe_inferred"] = inferred
        if declared:
            o.review_result["cwe"] = declared
        return o

    def test_inferred_cwe_repairs_to_carrying_sibling(self):
        from core.audit.cwe_dispatch import infer_cwe_from_hypothesis
        from core.audit.orchestrator import _synthesis_hypothesis_for_cwe
        no_harm = "Empty function body performs no dereference — cannot cause memory unsafety"
        harm = "use after free: the context is freed in the error path and dereferenced by the cleanup handler"
        cwe = infer_cwe_from_hypothesis(harm)
        assert cwe, "fixture must use an inferable mechanism"
        assert infer_cwe_from_hypothesis(no_harm) != cwe
        o = self._outcome(no_harm, [no_harm, harm], inferred=cwe)
        assert _synthesis_hypothesis_for_cwe(o, cwe, no_harm) == harm

    def test_declared_cwe_keeps_primary(self):
        from core.audit.orchestrator import _synthesis_hypothesis_for_cwe
        o = self._outcome("primary text", ["primary text", "sibling"],
                          declared="CWE-120")
        assert _synthesis_hypothesis_for_cwe(o, "CWE-120", "primary text") \
            == "primary text"

    def test_primary_carrying_inferred_cwe_kept(self):
        from core.audit.cwe_dispatch import infer_cwe_from_hypothesis
        from core.audit.orchestrator import _synthesis_hypothesis_for_cwe
        harm = "buffer overflow: unchecked memcpy into fixed stack buffer"
        cwe = infer_cwe_from_hypothesis(harm)
        assert cwe
        o = self._outcome(harm, [harm, "unrelated"], inferred=cwe)
        assert _synthesis_hypothesis_for_cwe(o, cwe, harm) == harm

    def test_no_match_falls_back_to_primary(self):
        from core.audit.orchestrator import _synthesis_hypothesis_for_cwe
        o = self._outcome("p", ["p", "q"], inferred="CWE-416")
        assert _synthesis_hypothesis_for_cwe(o, "CWE-416", "p") == "p"


class TestCVE2026_31431_AliasingRoute:
    """Focused proof that CVE-2026-31431 (_aead_recvmsg, CWE-416
    aliasing UAF) routes to on-demand synthesis instead of dying
    as suspicious.

    Uses the REAL chain builder — only tool execution and
    source-reading are stubbed.
    """

    ALIASING_HYP = (
        "scatterlist aliasing — src and dst reference the same "
        "pages through zero-copy splice; the decryption operation "
        "frees pages via the source scatterlist that are still "
        "referenced by the destination"
    )

    def test_cwe_chain_empty_but_string_chain_not(self):
        """The LLM router drops the CWE-416 standing tools (not
        dominated), but string-matching adds joern/codeql back from
        'free' in the hypothesis text."""
        from core.audit.orchestrator import (
            _cwe_fallback_chain,
            _hypothesis_to_tool_chain,
        )

        class _NotDominatedClient:
            def generate_structured(self, *a, **kw):
                return {"dominated": False, "reasoning": "aliasing"}

        client = _NotDominatedClient()

        cwe_chain = _cwe_fallback_chain(
            "CWE-416", self.ALIASING_HYP,
            "crypto/algif_aead.c", None,
            llm_client=client,
        )
        assert cwe_chain == [], (
            "LLM router should drop CWE-416 standing tools for aliasing hyp"
        )

        full_chain = _hypothesis_to_tool_chain(
            self.ALIASING_HYP, "crypto/algif_aead.c", cwe="CWE-416",
            llm_client=client,
        )
        assert len(full_chain) > 0, (
            "string-matched tools should still populate the chain"
        )
        chain_types = {e["type"] for e in full_chain}
        assert "coccinelle" not in chain_types, (
            "CWE-416 cocci rules (sequential UAF) must be absent"
        )
        assert "smt" not in chain_types, (
            "CWE-416 smt:check-early-release must be absent"
        )

    def test_sequential_uaf_keeps_full_chain(self, monkeypatch):
        """Contrast: a sequential UAF hypothesis keeps the full
        CWE-416 standing tools (cocci, smt, codeql, joern)."""
        from core.audit.orchestrator import _cwe_fallback_chain

        monkeypatch.setattr(
            "core.audit.orchestrator._codeql_query_file",
            lambda q: q or None,
        )

        seq_hyp = (
            "kfree is called and then the pointer is dereferenced "
            "in the error cleanup path"
        )
        cwe_chain = _cwe_fallback_chain(
            "CWE-416", seq_hyp, "crypto/algif_aead.c", None,
        )
        chain_types = {e["type"] for e in cwe_chain}
        assert "coccinelle" in chain_types
        assert "codeql" in chain_types

    def test_exhaustion_routes_to_synthesis_with_real_chain(
        self, tmp_path, monkeypatch,
    ):
        """Layer 2 (chain exhaustion): no LLM client, so the CWE-416
        standing tools stay; string-matched tools also fire. All return
        nothing → chain exhaustion routes to synthesis."""
        from core.audit.orchestrator import _promote_suspicious

        # No llm_budget_client on config → LLM routing skipped → CWE-416
        # standing tools + string-matched tools form the chain. All tools
        # return [] → chain exhaustion fires.
        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: SimpleNamespace(hits=[]),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int _aead_recvmsg(void) { return 0; }",
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._effective_cwe",
            lambda *a, **kw: "CWE-416",
        )

        calls: list[dict] = []

        def fake_synth(outcome, config, **kwargs):
            calls.append(kwargs)
            return None

        monkeypatch.setattr(
            "core.audit.checker_synthesis.synthesize_verification_rule",
            fake_synth,
        )

        outcome = _outcome(hypothesis=self.ALIASING_HYP)
        outcome.review_result["cwe"] = "CWE-416"
        outcome.file = "crypto/algif_aead.c"
        outcome.function = "_aead_recvmsg"
        result = self._result([outcome])

        _promote_suspicious(result, _config(tmp_path))

        assert len(calls) == 1, (
            "synthesis must fire — chain exhaustion + dark_verify(CWE-416)"
        )

    def test_llm_routing_drops_cwe_chain_for_aliasing(
        self, tmp_path, monkeypatch,
    ):
        """LLM routing: LLM says standing tools do NOT dominate the
        aliasing hypothesis → CWE chain dropped → string-matched
        residual tools run but find nothing → chain exhaustion
        routes to synthesis."""
        from core.audit.orchestrator import _promote_suspicious

        class _NotDominatedClient:
            def generate_structured(self, *a, **kw):
                return {"dominated": False, "reasoning": "aliasing"}

        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_prefilter",
            lambda **kw: SimpleNamespace(hits=[]),
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int _aead_recvmsg(void) { return 0; }",
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._effective_cwe",
            lambda *a, **kw: "CWE-416",
        )

        calls: list[dict] = []

        def fake_synth(outcome, config, **kwargs):
            calls.append(kwargs)
            return None

        monkeypatch.setattr(
            "core.audit.checker_synthesis.synthesize_verification_rule",
            fake_synth,
        )

        outcome = _outcome(hypothesis=self.ALIASING_HYP)
        outcome.review_result["cwe"] = "CWE-416"
        outcome.file = "crypto/algif_aead.c"
        outcome.function = "_aead_recvmsg"
        result = self._result([outcome])

        config = _config(tmp_path)
        config.llm_budget_client = _NotDominatedClient()

        _promote_suspicious(result, config)

        assert len(calls) == 1, (
            "synthesis must fire — LLM dropped CWE chain + exhaustion"
        )

    def test_secondary_sweep_routes_aliasing_mechanism_to_synthesis(
        self, tmp_path, monkeypatch,
    ):
        """The real corpus scenario: primary hypothesis is integer
        overflow (CWE-190), but mechanism #4 is an aliasing UAF
        (CWE-416). The secondary sweep should route that mechanism
        to synthesis via chain exhaustion."""
        from core.audit.orchestrator import _dispatch_secondary_hypotheses

        monkeypatch.setattr(
            "core.audit.orchestrator._run_tool_chain",
            lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            "core.audit.orchestrator._read_raw_source",
            lambda *a, **kw: "int _aead_recvmsg(void) { return 0; }",
        )

        synth_calls: list[tuple] = []

        def fake_synth(result, config, i, outcome, hyp, cwe, source, **kw):
            synth_calls.append((hyp, cwe))

        monkeypatch.setattr(
            "core.audit.orchestrator._synthesize_unmapped_suspicious",
            fake_synth,
        )

        outcome = _outcome(
            hypothesis=(
                "Integer underflow in decryption output length "
                "calculation when auth tag size exceeds available data"
            ),
        )
        outcome.review_result["cwe"] = "CWE-190"
        outcome.file = "crypto/algif_aead.c"
        outcome.function = "_aead_recvmsg"
        outcome.hypotheses = [
            {
                "mechanism": (
                    "Integer underflow in decryption output length "
                    "calculation when auth tag size exceeds available data"
                ),
                "confidence": "high",
            },
            {
                "mechanism": (
                    "Aliasing vulnerability: memcpy_sglist copies data "
                    "from TX SGL to RX SGL. If source and destination "
                    "reference the same page frames, the decryption "
                    "frees pages via the source scatterlist that are "
                    "still referenced by the destination"
                ),
                "confidence": "medium",
            },
        ]
        result = self._result([outcome])

        _dispatch_secondary_hypotheses(
            result, _config(tmp_path), joern_server=None,
        )

        assert any(
            "CWE-416" in cwe for _, cwe in synth_calls
        ), (
            f"synthesis must fire for CWE-416 aliasing mechanism; "
            f"got calls: {synth_calls}"
        )

    def _result(self, outcomes):
        from core.audit.orchestrator import OrchestratorResult
        r = OrchestratorResult()
        r.outcomes = list(outcomes)
        r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
        r.findings = sum(1 for o in outcomes if o.status == "finding")
        return r

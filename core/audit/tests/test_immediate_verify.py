"""Tests for _verify_hypotheses_immediate (IHV) — the inline fast path."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

from core.audit.orchestrator import (
    AtomicSynthesisCounter,
    ReviewOutcome,
    _aggregate_ihv_verdicts,
    _extract_all_hypotheses,
    _ihv_context_gate,
    _verify_hypotheses_immediate,
)


# ── Lightweight stubs ────────────────────────────────────────────────

@dataclass
class _Config:
    immediate_verify: bool = True
    sweep_validate_findings: bool = True
    on_demand_synthesis: bool = True
    target_path: str = "/src"
    out_dir: str = "/out"
    mode: str = "default"
    models: list = field(default_factory=lambda: ["haiku"])
    blind_first_pass: bool = False
    tool_chain_early_exit: bool = False
    debug: bool = False
    llm_client: Any = None


@dataclass
class _Result:
    clean: int = 0
    suspicious: int = 0
    findings: int = 0
    immediate_verified: int = 0
    ondemand_synthesized: int = 0
    total_cost_usd: float = 0.0
    tier_counters: dict = field(default_factory=dict)
    cost_tracker: Any = field(default_factory=lambda: MagicMock())
    _lock: threading.Lock = field(default_factory=threading.Lock)


# ── AtomicSynthesisCounter ───────────────────────────────────────────

class TestAtomicSynthesisCounter:
    def test_reserve_within_cap(self):
        c = AtomicSynthesisCounter(cap=3)
        assert c.try_reserve()
        assert c.try_reserve()
        assert c.try_reserve()
        assert not c.try_reserve()
        assert c.count == 3
        assert c.remaining == 0

    def test_remaining_decrements(self):
        c = AtomicSynthesisCounter(cap=5)
        assert c.remaining == 5
        c.try_reserve()
        assert c.remaining == 4

    def test_thread_contention(self):
        c = AtomicSynthesisCounter(cap=10)
        results = []

        def worker():
            successes = 0
            for _ in range(20):
                if c.try_reserve():
                    successes += 1
            results.append(successes)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(results) == 10
        assert c.count == 10


# ── _extract_all_hypotheses ──────────────────────────────────────────

class TestExtractHypotheses:
    def test_empty_outcome(self):
        o = ReviewOutcome(file="a.c", function="f", status="clean", body="")
        assert _extract_all_hypotheses(o) == []

    def test_primary_only(self):
        o = ReviewOutcome(
            file="a.c", function="f", status="finding", body="",
            hypothesis="buffer overflow via memcpy",
            review_result={"cwe": "CWE-120"},
        )
        hyps = _extract_all_hypotheses(o)
        assert len(hyps) == 1
        assert hyps[0]["mechanism"] == "buffer overflow via memcpy"
        assert hyps[0]["is_primary"] is True

    def test_primary_plus_secondary(self):
        o = ReviewOutcome(
            file="a.c", function="f", status="suspicious", body="",
            hypothesis="UAF via kfree",
            review_result={
                "cwe": "CWE-416",
                "hypothesis": "UAF via kfree",
                "hypotheses": [
                    {"mechanism": "UAF via kfree", "confidence": "high"},
                    {"mechanism": "double free in error path", "confidence": "medium"},
                    {"mechanism": "null deref", "confidence": "low"},
                ],
            },
        )
        hyps = _extract_all_hypotheses(o)
        assert len(hyps) == 2
        assert hyps[0]["mechanism"] == "UAF via kfree"
        assert hyps[1]["mechanism"] == "double free in error path"

    def test_dedup_primary(self):
        o = ReviewOutcome(
            file="a.c", function="f", status="finding", body="",
            hypothesis="overflow",
            review_result={
                "hypothesis": "overflow",
                "hypotheses": [
                    {"mechanism": "overflow", "confidence": "high"},
                    {"mechanism": "underflow", "confidence": "high"},
                ],
            },
        )
        hyps = _extract_all_hypotheses(o)
        mechanisms = [h["mechanism"] for h in hyps]
        assert mechanisms.count("overflow") == 1
        assert "underflow" in mechanisms

    def test_four_hypotheses(self):
        o = ReviewOutcome(
            file="a.c", function="f", status="suspicious", body="",
            hypothesis="integer underflow",
            review_result={
                "cwe": "CWE-190",
                "hypothesis": "integer underflow",
                "hypotheses": [
                    {"mechanism": "integer underflow", "confidence": "high"},
                    {"mechanism": "aliasing type confusion", "confidence": "high"},
                    {"mechanism": "missing bounds check", "confidence": "medium"},
                    {"mechanism": "uninitialized var", "confidence": "medium"},
                ],
            },
        )
        hyps = _extract_all_hypotheses(o)
        assert len(hyps) == 4
        assert hyps[0]["is_primary"] is True


# ── _verify_hypotheses_immediate ─────────────────────────────────────

class TestVerifyImmediate:
    def _make_outcome(self, **kw):
        defaults = dict(
            file="net/tls.c", function="_aead_recvmsg",
            status="suspicious", body="test",
            hypothesis="integer underflow in length calculation",
            review_result={
                "cwe": "CWE-190",
                "hypothesis": "integer underflow in length calculation",
                "hypotheses": [
                    {"mechanism": "integer underflow in length calculation",
                     "confidence": "high"},
                ],
            },
        )
        defaults.update(kw)
        return ReviewOutcome(**defaults)

    def test_noop_when_disabled(self):
        cfg = _Config(immediate_verify=False)
        o = self._make_outcome()
        result = _Result()
        out = _verify_hypotheses_immediate(o, cfg, result)
        assert out is o
        assert result.immediate_verified == 0

    def test_noop_no_hypotheses(self):
        cfg = _Config()
        o = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
        )
        result = _Result()
        out = _verify_hypotheses_immediate(o, cfg, result)
        assert out is o

    @patch("core.audit.orchestrator._correlated_mech_detector_tool")
    def test_prep_phase_correlation_confirms(self, mock_corr):
        mock_corr.return_value = "coccinelle:use_after_free"
        cfg = _Config()
        o = self._make_outcome()
        result = _Result()
        out = _verify_hypotheses_immediate(o, cfg, result)
        assert out.status == "finding"
        assert out.evidence_tool == "coccinelle:use_after_free"
        assert result.immediate_verified == 1
        assert out.review_result["immediate_verified"] is True

    @patch("core.audit.orchestrator._run_tool_chain")
    @patch("core.audit.orchestrator._hypothesis_to_tool_chain")
    @patch("core.audit.orchestrator._correlated_mech_detector_tool")
    @patch("core.audit.orchestrator._gather_library_candidates")
    def test_tool_chain_confirms(
        self, mock_lib, mock_corr, mock_chain, mock_run,
    ):
        mock_corr.return_value = None
        mock_lib.return_value = []
        mock_chain.return_value = [
            {"type": "semgrep", "config": {"rule": "test.yaml"}},
        ]
        mock_run.return_value = ["semgrep:test"]
        cfg = _Config()
        o = self._make_outcome()
        result = _Result()
        out = _verify_hypotheses_immediate(o, cfg, result)
        assert out.status == "finding"
        assert out.evidence_tool == "semgrep:test"
        assert "semgrep" in (out.tools_dispatched or set())

    @patch("core.audit.orchestrator._run_tool_chain")
    @patch("core.audit.orchestrator._hypothesis_to_tool_chain")
    @patch("core.audit.orchestrator._correlated_mech_detector_tool")
    @patch("core.audit.orchestrator._gather_library_candidates")
    def test_all_refuted_becomes_clean(
        self, mock_lib, mock_corr, mock_chain, mock_run,
    ):
        mock_corr.return_value = None
        mock_lib.return_value = []
        mock_chain.return_value = [
            {"type": "smt", "config": {"verb": "check-oob"}},
        ]
        mock_run.return_value = []  # no confirmations
        cfg = _Config()
        o = self._make_outcome()
        result = _Result()
        out = _verify_hypotheses_immediate(o, cfg, result)
        assert out.status == "clean"
        assert out.review_result["ihv_all_refuted"] is True
        assert "smt" in (out.tools_dispatched or set())

    @patch("core.audit.orchestrator._run_tool_chain")
    @patch("core.audit.orchestrator._hypothesis_to_tool_chain")
    @patch("core.audit.orchestrator._correlated_mech_detector_tool")
    @patch("core.audit.orchestrator._gather_library_candidates")
    def test_joern_stripped_from_chain(
        self, mock_lib, mock_corr, mock_chain, mock_run,
    ):
        mock_corr.return_value = None
        mock_lib.return_value = []
        mock_chain.return_value = [
            {"type": "joern", "config": {}},
        ]
        mock_run.return_value = []
        cfg = _Config()
        o = self._make_outcome()
        result = _Result()
        out = _verify_hypotheses_immediate(o, cfg, result)
        # Joern-only chain → empty after strip → untested (not refuted)
        mock_run.assert_not_called()
        assert out.status == "suspicious"
        assert "ihv_all_refuted" not in out.review_result

    @patch("core.audit.orchestrator._run_tool_chain")
    @patch("core.audit.orchestrator._hypothesis_to_tool_chain")
    @patch("core.audit.orchestrator._correlated_mech_detector_tool")
    @patch("core.audit.orchestrator._gather_library_candidates")
    def test_mixed_chain_strips_joern_keeps_others(
        self, mock_lib, mock_corr, mock_chain, mock_run,
    ):
        mock_corr.return_value = None
        mock_lib.return_value = []
        mock_chain.return_value = [
            {"type": "joern", "config": {}},
            {"type": "semgrep", "config": {"rule": "x.yaml"}},
        ]
        mock_run.return_value = ["semgrep:x"]
        cfg = _Config()
        o = self._make_outcome()
        result = _Result()
        _verify_hypotheses_immediate(o, cfg, result)
        called_chain = mock_run.call_args[0][0]
        assert all(e["type"] != "joern" for e in called_chain)
        assert any(e["type"] == "semgrep" for e in called_chain)


class TestIHVSynthesis:
    @patch("core.audit.orchestrator._correlated_mech_detector_tool")
    @patch("core.audit.orchestrator._gather_library_candidates")
    @patch("core.audit.orchestrator._get_llm_client")
    def test_synthesis_on_not_dominated(
        self, mock_llm, mock_lib, mock_corr,
    ):
        from core.audit.cwe_dispatch import RoutingResult

        mock_corr.return_value = None
        mock_lib.return_value = []
        mock_llm.return_value = MagicMock()

        routing = RoutingResult(False, "", "no checker covers aliasing")
        with patch(
            "core.audit.cwe_dispatch.route_hypothesis_to_checkers",
            return_value=routing,
        ):
            cfg = _Config()
            o = ReviewOutcome(
                file="a.c", function="f", status="suspicious", body="t",
                hypothesis="aliasing confusion",
                review_result={"cwe": "CWE-843", "hypothesis": "aliasing confusion",
                               "hypotheses": [{"mechanism": "aliasing confusion",
                                               "confidence": "high"}]},
            )
            counter = AtomicSynthesisCounter(cap=10)
            result = _Result()

            with patch(
                "core.audit.orchestrator._try_ihv_synthesis",
            ) as mock_synth:
                _verify_hypotheses_immediate(
                    o, cfg, result,
                    synthesis_counter=counter,
                )
                mock_synth.assert_called_once()
                assert counter.count == 1

    def test_synthesis_cap_exhausted_skips(self):
        counter = AtomicSynthesisCounter(cap=0)
        assert not counter.try_reserve()

    @patch("core.audit.orchestrator._correlated_mech_detector_tool")
    @patch("core.audit.orchestrator._gather_library_candidates")
    @patch("core.audit.orchestrator._get_llm_client")
    def test_cap_exhausted_untested_not_refuted(
        self, mock_llm, mock_lib, mock_corr,
    ):
        """Synthesis cap exhausted → untested, NOT demoted to clean."""
        from core.audit.cwe_dispatch import RoutingResult

        mock_corr.return_value = None
        mock_lib.return_value = []
        mock_llm.return_value = MagicMock()

        routing = RoutingResult(False, "", "no checker")
        with patch(
            "core.audit.cwe_dispatch.route_hypothesis_to_checkers",
            return_value=routing,
        ):
            cfg = _Config()
            o = ReviewOutcome(
                file="a.c", function="f", status="suspicious", body="t",
                hypothesis="aliasing confusion",
                review_result={
                    "cwe": "CWE-843", "hypothesis": "aliasing confusion",
                    "hypotheses": [{"mechanism": "aliasing confusion",
                                    "confidence": "high"}],
                },
            )
            counter = AtomicSynthesisCounter(cap=0)
            result = _Result()
            out = _verify_hypotheses_immediate(
                o, cfg, result, synthesis_counter=counter,
            )
            assert out.status == "suspicious"
            assert "ihv_all_refuted" not in out.review_result


# ── Routing cache ────────────────────────────────────────────────────

class TestRoutingCache:
    def test_cache_hit(self):
        from core.audit.cwe_dispatch import (
            RoutingResult,
            _routing_cache,
            _routing_cache_key,
            _routing_cache_lock,
        )

        key = _routing_cache_key("CWE-416", "UAF via kfree", frozenset())
        result = RoutingResult(True, "", "test")
        with _routing_cache_lock:
            _routing_cache[key] = result

        try:
            from core.audit.cwe_dispatch import route_hypothesis_to_checkers
            out = route_hypothesis_to_checkers(
                "CWE-416", "UAF via kfree", None,
            )
            assert out.dominated is True
        finally:
            with _routing_cache_lock:
                _routing_cache.pop(key, None)

    def test_different_candidates_different_key(self):
        from core.audit.cwe_dispatch import _routing_cache_key

        k1 = _routing_cache_key("CWE-416", "UAF", frozenset())
        k2 = _routing_cache_key("CWE-416", "UAF", frozenset({"rule_1"}))
        assert k1 != k2


# ── Context validation gates ────────────────────────────────────────

class TestIHVContextGate:
    """Gates block promotion, not verification."""

    def test_no_gate_blocks_clean_outcome(self):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="buffer overflow", body="overflow in memcpy",
            review_result={},
        )
        config = _Config()
        assert _ihv_context_gate(outcome, config) is None

    def test_caller_attribution_blocks(self):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="callerFunc passes wrong size",
            body="the bug is in callerFunc",
            review_result={"callers": [{"name": "callerFunc"}]},
        )
        config = _Config()
        reason = _ihv_context_gate(outcome, config)
        assert reason is not None
        assert "caller-attributed" in reason
        assert "callerFunc" in reason

    def test_short_caller_name_ignored(self):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="fn passes wrong size",
            body="the bug is in fn",
            review_result={"callers": [{"name": "fn"}]},
        )
        config = _Config()
        assert _ihv_context_gate(outcome, config) is None

    def test_guarded_sink_blocks(self):
        mock_joern = MagicMock()
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="SQL injection", body="",
            review_result={},
        )
        config = _Config()
        with patch(
            "core.audit.orchestrator._guard_blocks_promotion",
            return_value="guarded",
        ):
            reason = _ihv_context_gate(
                outcome, config, joern_server=mock_joern,
            )
        assert reason == "guarded-sink:guarded"

    def test_guarded_sink_skipped_without_joern(self):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="SQL injection", body="",
            review_result={},
        )
        config = _Config()
        assert _ihv_context_gate(outcome, config, joern_server=None) is None

    def test_refuting_counter_blocks(self):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="buffer overflow", body="",
            review_result={},
        )
        config = _Config()
        with patch(
            "core.audit.orchestrator._has_refuting_counter",
            return_value=True,
        ):
            reason = _ihv_context_gate(outcome, config)
        assert reason == "refuting-counter"


class TestAggregateWithGates:
    """_aggregate_ihv_verdicts respects context gates."""

    def test_gate_blocks_promotion_preserves_evidence(self):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="caller bug", body="the bug is in callerFunc",
            review_result={"callers": [{"name": "callerFunc"}]},
        )
        result = _Result()
        out = _aggregate_ihv_verdicts(
            outcome, result,
            hypotheses=[{"mechanism": "caller bug", "confidence": "high"}],
            confirmed_tools=["semgrep"],
            confirmed_hypotheses=[{"mechanism": "caller bug"}],
            refuted_count=0,
            config=_Config(),
        )
        # Gate blocked → status NOT promoted to finding
        assert out.status != "finding"
        # Evidence preserved for slow path
        assert out.review_result["ihv_tools"] == ["semgrep"]
        assert out.review_result["ihv_gate_blocked"] is not None
        assert "caller-attributed" in out.review_result["ihv_gate_blocked"]
        # NOT stamped immediate_verified — slow path can re-process
        assert "immediate_verified" not in out.review_result
        # Counter NOT incremented
        assert result.immediate_verified == 0

    def test_no_gate_promotes_to_finding(self):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="buffer overflow", body="overflow in memcpy",
            review_result={},
        )
        result = _Result()
        out = _aggregate_ihv_verdicts(
            outcome, result,
            hypotheses=[{"mechanism": "overflow", "confidence": "high"}],
            confirmed_tools=["semgrep"],
            confirmed_hypotheses=[{"mechanism": "overflow"}],
            refuted_count=0,
            config=_Config(),
        )
        assert out.status == "finding"
        assert out.review_result["immediate_verified"] is True
        assert "ihv_gate_blocked" not in out.review_result
        assert result.immediate_verified == 1

    def test_refuting_counter_gate_blocks(self):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="overflow", body="",
            review_result={},
        )
        result = _Result()
        with patch(
            "core.audit.orchestrator._has_refuting_counter",
            return_value=True,
        ):
            out = _aggregate_ihv_verdicts(
                outcome, result,
                hypotheses=[{"mechanism": "overflow"}],
                confirmed_tools=["coccinelle"],
                confirmed_hypotheses=[{"mechanism": "overflow"}],
                refuted_count=0,
                config=_Config(),
            )
        assert out.status != "finding"
        assert out.review_result["ihv_gate_blocked"] == "refuting-counter"
        assert out.review_result["ihv_tools"] == ["coccinelle"]
        assert "immediate_verified" not in out.review_result

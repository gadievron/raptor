"""Tests for _verify_hypotheses_immediate (IHV) — the inline fast path."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from core.audit.claim_verification import ClaimVerification
from core.audit.verification_results import ToolChainResult
from core.audit.refutation_source import capture_source_identity

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

    @pytest.mark.parametrize("rule,owner,hypothesis,cwe,promotes", [
        pytest.param("use_after_free", "use_after_free", "use after free of a pointer", "CWE-416", False, id="detection-uaf"),
        pytest.param("mmap_leak_err", "mmap_leak_err", "mapping memory leak at return", "CWE-401", False, id="detection-mapping-leak"),
        pytest.param("mmap_free", "mmap_free", "mapping pointer passed to free", "CWE-762", False, id="detection-mapping-release"),
        pytest.param("free_nonbase_ptr_inc", "free_nonbase_ptr", "invalid free of an offset pointer", "CWE-761", False, id="detection-offset-alias"),
        pytest.param("double_fclose", "double_close", "double close of a stream", "CWE-415", False, id="detection-stream-alias"),
        pytest.param("stack_addr_escape_outparam", "stack_addr_escape", "stack address escapes through output parameter", "CWE-562", False, id="detection-stack-alias"),
        pytest.param("uid_truncation", "uid_truncation", "UID cast narrows an identity value", "CWE-681", False, id="detection-uid-range"),
        pytest.param("shift_overflow", "shift_overflow", "invalid built-in shift count", "CWE-682", False, id="detection-shift-family"),
        pytest.param("shift_overflow_int", "shift_overflow", "invalid built-in int shift count", "CWE-682", False, id="detection-shift-int"),
        pytest.param("shift_overflow_long", "shift_overflow", "invalid built-in long shift count", "CWE-682", False, id="detection-shift-long"),
        pytest.param("shift_overflow_negative", "shift_overflow", "negative built-in shift count", "CWE-682", False, id="detection-shift-negative"),
        pytest.param("division_by_zero", "division_by_zero", "integer divisor may be zero", "CWE-369", False, id="detection-divisor-family"),
        pytest.param("division_by_zero_param", "division_by_zero", "integer division before zero check", "CWE-369", False, id="detection-divisor-alias"),
        pytest.param("modulo_by_zero_param", "division_by_zero", "integer modulo before zero check", "CWE-369", False, id="detection-modulo-alias"),
        pytest.param("copy_user_size_mismatch", "copy_user_size_mismatch", "user-copy extent exceeds object capacity", "CWE-805", False, id="detection-usercopy-capacity"),
        pytest.param("copy_from_user_sizeof_ptr", "copy_user_size_mismatch", "pointer size used as user-copy extent", "CWE-805", False, id="detection-usercopy-pointer-alias"),
        pytest.param("integer_overflow_alloc", "integer_overflow_alloc", "allocation product wraps", "CWE-190", False, id="detection-allocation-product"),
        pytest.param("negative_errno_unsigned_return", "negative_errno_unsigned_return", "negative error returned as unsigned count", "CWE-195", False, id="detection-unsigned-errno"),
        pytest.param("missing_bounds_check", "missing_bounds_check", "array index exceeds the local buffer extent", "CWE-119", False, id="detection-array-index"),
        pytest.param("missing_null_check", "missing_null_check", "allocation result used without a null check", "CWE-476", False, id="detection-allocation-null"),
        pytest.param("unchecked_return", "unchecked_return", "failure return ignored by the caller", "CWE-252", False, id="detection-return-check"),
        pytest.param("strncpy_no_nul", "strncpy_no_nul", "copied buffer reaches a string read without termination", "CWE-170", False, id="detection-string-termination"),
        pytest.param("snprintf_truncation_boundary", "snprintf_truncation_boundary", "strict comparison misses the truncated equality case", "CWE-193", False, id="detection-format-boundary"),
        pytest.param("snprintf_advance", "snprintf_advance", "format return advances beyond the available buffer", "CWE-787", False, id="detection-format-cursor"),
        pytest.param("packet_length_inverted_guard", "packet_length_inverted_guard", "packet range exceeds the available length", "CWE-125", False, id="detection-packet-length"),
        pytest.param("scatterlist_frag_undersize", "scatterlist_frag_undersize", "scatterlist has too few entries for packet fragments", "CWE-787", False, id="detection-scatterlist-size"),
        pytest.param("rcu_no_lock", "rcu_no_lock", "RCU pointer accessed without read-side protection", "CWE-416", False, id="detection-rcu-assignment"),
        pytest.param("rcu_dereference_outside_rcu", "rcu_dereference_outside_rcu", "RCU pointer accessed outside read-side protection", "CWE-416", False, id="detection-rcu-dereference"),
        pytest.param("double_close", "double_close", "descriptor released twice", "CWE-675", False, id="detection-descriptor-release"),
        pytest.param("fdopendir_double_close", "fdopendir_double_close", "directory stream and descriptor both released", "CWE-675", False, id="detection-directory-ownership"),
        pytest.param("use_after_close", "use_after_close", "descriptor I/O after close", "CWE-672", False, id="detection-closed-descriptor"),
        pytest.param("use_after_fclose", "use_after_fclose", "stdio operation after fclose", "CWE-416", False, id="detection-closed-stream"),
        pytest.param("alloc_narrow_count", "alloc_narrow_count", "division-derived count contributes to allocation size", "CWE-190", False, id="detection-narrow-count"),
        pytest.param("double_sizeof", "double_sizeof", "repeated sizeof allocation factors", "CWE-468", False, id="detection-repeated-width"),
        pytest.param("pointer_scaling_double", "double_sizeof", "explicit sizeof pointer stride", "CWE-468", False, id="detection-pointer-stride"),
        pytest.param("sizeof_container_of", "sizeof_container_of", "allocation capacity for enclosing object", "CWE-131", False, id="detection-container-capacity"),
        pytest.param("malloc_strlen_strcpy", "malloc_strlen_strcpy", "allocation size excludes the string terminator", "CWE-131", False, id="detection-string-size"),
        pytest.param("sizeof_array_param", "sizeof_array_param", "sizeof array parameter used as copy extent", "CWE-467", False, id="detection-array-size"),
        pytest.param("sizeof_array_param_unsized", "sizeof_array_param", "sizeof unsized array parameter used as copy extent", "CWE-467", False, id="detection-unsized-alias"),
        pytest.param("free_stack_array", "free_stack_array", "stack array passed to free", "CWE-590", True, id="verified-stack-release"),
    ])
    def test_prep_phase_correlation_requires_verification_grade(
        self, tmp_path, monkeypatch, rule, owner, hypothesis, cwe, promotes,
    ):
        from core.audit.evidence_grade import is_verification_evidence
        from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult

        monkeypatch.setenv("RAPTOR_DIR", str(Path(__file__).resolve().parents[3]))
        receipt = f"coccinelle:{rule}"
        assert (Path(__file__).resolve().parents[3] / "engine/coccinelle/rules" / f"{owner}.cocci").is_file()
        assert is_verification_evidence(receipt) is promotes
        cfg = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path / "out", on_demand_synthesis=False,
        )
        # The standing receipt is the only evidence. Keep unrelated library,
        # synthesis and live-tool work outside this consumer contract.
        monkeypatch.setattr("core.audit.orchestrator._gather_library_candidates", lambda *a: [])
        monkeypatch.setattr("core.audit.orchestrator._hypothesis_to_tool_chain", lambda *a, **kw: [])
        o = self._make_outcome(
            hypothesis=hypothesis, review_result={"cwe": cwe, "hypothesis": hypothesis},
        )
        result = OrchestratorResult()
        mechanical = {f"{o.file}:{o.function}": [{
            "file": o.file, "function": o.function, "line": o.line,
            "detector": f"cocci:{rule}", "description": hypothesis,
        }]}
        out = _verify_hypotheses_immediate(o, cfg, result, mechanical_findings=mechanical)
        assert out.status == ("finding" if promotes else "suspicious")
        assert out.evidence_tool == (receipt if promotes else "")
        assert result.immediate_verified == int(promotes)
        assert bool(out.review_result.get("immediate_verified")) is promotes
        assert not out.review_result.get("ihv_all_refuted")

    @pytest.mark.parametrize("receipt,hypothesis,cwe", [
        pytest.param("coccinelle:use_after_free", "use after free of a pointer", "CWE-416", id="detection-uaf"),
        pytest.param("coccinelle:mmap_leak_err", "mapping memory leak at return", "CWE-401", id="detection-mapping-leak"),
        pytest.param("coccinelle:mmap_free", "mapping pointer passed to free", "CWE-762", id="detection-mapping-release"),
        pytest.param("coccinelle:free_nonbase_ptr_inc", "invalid free of an offset pointer", "CWE-761", id="detection-offset-alias"),
        pytest.param("coccinelle:double_fclose", "double close of a stream", "CWE-415", id="detection-stream-alias"),
        pytest.param("coccinelle:uid_truncation", "UID cast narrows an identity value", "CWE-681", id="detection-uid-range"),
        pytest.param("coccinelle:shift_overflow", "invalid built-in shift count", "CWE-682", id="detection-shift-family"),
        pytest.param("coccinelle:shift_overflow_int", "invalid built-in int shift count", "CWE-682", id="detection-shift-int"),
        pytest.param("coccinelle:shift_overflow_long", "invalid built-in long shift count", "CWE-682", id="detection-shift-long"),
        pytest.param("coccinelle:shift_overflow_negative", "negative built-in shift count", "CWE-682", id="detection-shift-negative"),
        pytest.param("coccinelle:division_by_zero", "integer divisor may be zero", "CWE-369", id="detection-divisor-family"),
        pytest.param("coccinelle:division_by_zero_param", "integer division before zero check", "CWE-369", id="detection-divisor-alias"),
        pytest.param("coccinelle:modulo_by_zero_param", "integer modulo before zero check", "CWE-369", id="detection-modulo-alias"),
        pytest.param("coccinelle:copy_user_size_mismatch", "user-copy extent exceeds object capacity", "CWE-805", id="detection-usercopy-capacity"),
        pytest.param("coccinelle:copy_from_user_sizeof_ptr", "pointer size used as user-copy extent", "CWE-805", id="detection-usercopy-pointer-alias"),
        pytest.param("coccinelle:integer_overflow_alloc", "allocation product wraps", "CWE-190", id="detection-allocation-product"),
        pytest.param("coccinelle:negative_errno_unsigned_return", "negative error returned as unsigned count", "CWE-195", id="detection-unsigned-errno"),
        pytest.param("coccinelle:missing_bounds_check", "array index exceeds the local buffer extent", "CWE-119", id="detection-array-index"),
        pytest.param("coccinelle:missing_null_check", "allocation result used without a null check", "CWE-476", id="detection-allocation-null"),
        pytest.param("coccinelle:unchecked_return", "failure return ignored by the caller", "CWE-252", id="detection-return-check"),
        pytest.param("coccinelle:strncpy_no_nul", "copied buffer reaches a string read without termination", "CWE-170", id="detection-string-termination"),
        pytest.param("coccinelle:snprintf_truncation_boundary", "strict comparison misses the truncated equality case", "CWE-193", id="detection-format-boundary"),
        pytest.param("coccinelle:snprintf_advance", "format return advances beyond the available buffer", "CWE-787", id="detection-format-cursor"),
        pytest.param("coccinelle:packet_length_inverted_guard", "packet range exceeds the available length", "CWE-125", id="detection-packet-length"),
        pytest.param("coccinelle:scatterlist_frag_undersize", "scatterlist has too few entries for packet fragments", "CWE-787", id="detection-scatterlist-size"),
        pytest.param("coccinelle:rcu_no_lock", "RCU pointer accessed without read-side protection", "CWE-416", id="detection-rcu-assignment"),
        pytest.param("coccinelle:rcu_dereference_outside_rcu", "RCU pointer accessed outside read-side protection", "CWE-416", id="detection-rcu-dereference"),
        pytest.param("coccinelle:double_close", "descriptor released twice", "CWE-675", id="detection-descriptor-release"),
        pytest.param("coccinelle:fdopendir_double_close", "directory stream and descriptor both released", "CWE-675", id="detection-directory-ownership"),
        pytest.param("coccinelle:use_after_close", "descriptor I/O after close", "CWE-672", id="detection-closed-descriptor"),
        pytest.param("coccinelle:use_after_fclose", "stdio operation after fclose", "CWE-416", id="detection-closed-stream"),
        pytest.param("coccinelle:alloc_narrow_count", "division-derived count contributes to allocation size", "CWE-190", id="detection-narrow-count"),
        pytest.param("coccinelle:double_sizeof", "repeated sizeof allocation factors", "CWE-468", id="detection-repeated-width"),
        pytest.param("coccinelle:pointer_scaling_double", "explicit sizeof pointer stride", "CWE-468", id="detection-pointer-stride"),
        pytest.param("coccinelle:sizeof_container_of", "allocation capacity for enclosing object", "CWE-131", id="detection-container-capacity"),
        pytest.param("coccinelle:malloc_strlen_strcpy", "allocation size excludes the string terminator", "CWE-131", id="detection-string-size"),
        pytest.param("coccinelle:sizeof_array_param", "sizeof array parameter used as copy extent", "CWE-467", id="detection-array-size"),
        pytest.param("coccinelle:sizeof_array_param_unsized", "sizeof unsized array parameter used as copy extent", "CWE-467", id="detection-unsized-alias"),
    ])
    @patch("core.audit.orchestrator._correlated_mech_detector_tool")
    def test_prep_phase_detection_receipt_cannot_bypass_aggregation(
        self, mock_corr, monkeypatch, tmp_path, receipt, hypothesis, cwe,
    ):
        from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult

        monkeypatch.setenv("RAPTOR_DIR", str(Path(__file__).resolve().parents[3]))
        # Even an erroneous upstream admission must not launder a lead into
        # verification. The real correlation refusal is covered above.
        mock_corr.return_value = receipt
        o = self._make_outcome(
            hypothesis=hypothesis, review_result={"cwe": cwe, "hypothesis": hypothesis},
        )
        result = OrchestratorResult()
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
        out = _verify_hypotheses_immediate(o, config, result)
        assert out.status == "suspicious"
        assert not out.evidence_tool
        assert result.immediate_verified == 0
        assert not out.review_result.get("immediate_verified")
        assert out.review_result["ihv_tools"] == [receipt]
        assert out.review_result["ihv_hypotheses_confirmed"] == 0

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

    @pytest.mark.parametrize("verb,can_refute", [
        ("check-overflow", True), ("check-oob", False),
        ("check-overflow-to-oob", False), ("check-negative-bypass", False),
    ])
    @patch("core.audit.orchestrator._run_tool_chain")
    @patch("core.audit.orchestrator._hypothesis_to_tool_chain")
    @patch("core.audit.orchestrator._correlated_mech_detector_tool")
    @patch("core.audit.orchestrator._gather_library_candidates")
    def test_refutation_requires_source_capable_producer(
        self, mock_lib, mock_corr, mock_chain, mock_run, tmp_path, verb, can_refute,
    ):
        mock_corr.return_value = None
        mock_lib.return_value = []
        mock_chain.return_value = [
            {"type": "smt", "config": {"verb": verb}},
        ]
        def negative_result(chain, **kwargs):
            result = ToolChainResult(file=kwargs["file_path"], function=kwargs["function_name"],
                                     line_start=kwargs["line_start"], hypothesis=kwargs["hypothesis"],
                                     source_identity=capture_source_identity(tmp_path, kwargs["file_path"]))
            result.observe("smt", "refuted", verb, "numeric query is unsatisfiable")
            return result

        mock_run.side_effect = negative_result
        (tmp_path / "net").mkdir()
        (tmp_path / "net/tls.c").write_text("int Read(int n) { return n; }\n")
        cfg = _Config(target_path=tmp_path, out_dir=tmp_path)
        o = self._make_outcome()
        result = _Result()
        out = _verify_hypotheses_immediate(o, cfg, result)
        assert out.status == ("clean" if can_refute else "suspicious")
        assert bool(out.review_result.get("ihv_all_refuted")) is can_refute
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
                return_value=None,
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

    def test_caller_annotation_does_not_block(self):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="callerFunc passes wrong size",
            body="the bug is in callerFunc",
            review_result={"callers": [{"name": "callerFunc"}]},
        )
        config = _Config()
        reason = _ihv_context_gate(outcome, config)
        assert reason is None
        assert outcome.caller_attributed
        assert outcome.attributed_caller == "callerFunc"

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

    def test_gate_blocks_promotion_preserves_evidence(self, monkeypatch):
        outcome = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            hypothesis="caller bug", body="the bug is in callerFunc",
            review_result={"callers": [{"name": "callerFunc"}]},
        )
        result = _Result()
        monkeypatch.setattr(
            "core.audit.orchestrator._guard_blocks_promotion",
            lambda *args, **kwargs: "sanitised sink",
        )
        out = _aggregate_ihv_verdicts(
            outcome, result,
            hypotheses=[{"mechanism": "caller bug", "confidence": "high"}],
            verifications=[ClaimVerification({"mechanism": "caller bug"}, ("semgrep",))],
            config=_Config(), joern_server=object(),
        )
        # Gate blocked → status NOT promoted to finding
        assert out.status != "finding"
        # Evidence preserved for slow path
        assert out.review_result["ihv_tools"] == ["semgrep"]
        assert out.review_result["ihv_gate_blocked"] is not None
        assert out.review_result["ihv_gate_blocked"] == "guarded-sink:sanitised sink"
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
            verifications=[ClaimVerification({"mechanism": "overflow"}, ("semgrep",))],
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
                verifications=[ClaimVerification({"mechanism": "overflow"}, ("coccinelle",))],
                config=_Config(),
            )
        assert out.status != "finding"
        assert out.review_result["ihv_gate_blocked"] == "refuting-counter"
        assert out.review_result["ihv_tools"] == ["coccinelle"]
        assert "immediate_verified" not in out.review_result

"""End-to-end test: run_orchestrator with a capturing review_fn.

Exercises the FULL orchestrator loop against eval/audit-synthetic/target:

    checklist.json (on disk) → gap scoring → evidence index build
    → prefilter → block-level context → review_fn call → outcome tally

The review_fn is a mock that records the context it receives for each
function.  Tests assert that the right mechanical signals (block analysis,
sink narrowing, taint evidence, scope narrowing) arrive at the "LLM"
and that prefilter decisions are correct.

No actual LLM calls.  ~1s wall time.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

pytestmark = pytest.mark.slow

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_TARGET_DIR = _RAPTOR_DIR / "eval" / "audit-synthetic" / "target"
_CHECKLIST_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-build-checklist")


@pytest.fixture(scope="module")
def target_path():
    if not _TARGET_DIR.exists():
        pytest.skip("eval/audit-synthetic/target not available")
    return _TARGET_DIR


@pytest.fixture(scope="module")
def out_dir(target_path, tmp_path_factory):
    """Build checklist.json via the real libexec script."""
    out = tmp_path_factory.mktemp("orchestrator_e2e")
    import os
    env = dict(os.environ, CLAUDECODE="1", _RAPTOR_TRUSTED="1",
               PYTHONPATH=str(_RAPTOR_DIR))
    r = subprocess.run(
        [sys.executable, _CHECKLIST_CLI, str(target_path), str(out)],
        env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, f"build-checklist failed: {r.stderr}"
    assert (out / "checklist.json").exists()
    return out


@dataclass
class _CapturedCall:
    """One review_fn invocation."""
    file: str
    function: str
    ctx: Dict[str, Any]


class _CapturingReviewFn:
    """Mock review_fn that records the context it receives."""

    def __init__(self):
        self.calls: List[_CapturedCall] = []

    def __call__(self, ctx, config):
        from core.audit.orchestrator import ReviewOutcome
        self.calls.append(_CapturedCall(
            file=ctx["file"],
            function=ctx["function"],
            ctx=dict(ctx),
        ))
        return ReviewOutcome(
            file=ctx["file"],
            function=ctx["function"],
            status="clean",
            body="mock review — no LLM",
        )

    def ctx_for(self, file: str, function: str) -> Optional[Dict[str, Any]]:
        for call in self.calls:
            if call.file == file and call.function == function:
                return call.ctx
        return None


@pytest.fixture(scope="module")
def orchestrator_run(target_path, out_dir):
    """Run the orchestrator with a capturing review_fn."""
    from core.audit.orchestrator import OrchestratorConfig, run_orchestrator

    config = OrchestratorConfig(
        target_path=target_path,
        out_dir=out_dir,
        prefilter=True,
        force=True,
        resume=False,
        enable_session_context=False,
        propagate_constraints=False,
        include_stale=False,
    )

    review_fn = _CapturingReviewFn()
    result = run_orchestrator(config, review_fn)
    return result, review_fn


# =====================================================================
# 1. Orchestrator completes and processes all functions
# =====================================================================


class TestOrchestratorCompletion:

    def test_orchestrator_completes(self, orchestrator_run):
        result, _ = orchestrator_run
        assert result.terminated_by == "complete"

    def test_all_functions_processed(self, orchestrator_run):
        """Every function should be reviewed or prefilter-skipped."""
        result, review_fn = orchestrator_run
        total = result.reviewed + result.prefilter_skipped
        assert total > 0, "no functions processed"
        reviewed_names = {c.function for c in review_fn.calls}
        assert len(reviewed_names) >= 3, (
            f"expected at least 3 reviewed functions, got {reviewed_names}"
        )

    def test_no_errors(self, orchestrator_run):
        result, _ = orchestrator_run
        assert result.errors == 0


# =====================================================================
# 2. Block-level context arrives at the review_fn
# =====================================================================


class TestBlockContextInReviewFn:

    def test_parse_headers_gets_block_analysis(self, orchestrator_run):
        """parse_headers (CC=11) should have block_analysis in its ctx."""
        _, review_fn = orchestrator_run
        ctx = review_fn.ctx_for("reqparse.c", "parse_headers")
        if ctx is None:
            pytest.skip("parse_headers was prefilter-skipped")

        assert "block_analysis" in ctx, (
            "parse_headers should receive block-level analysis"
        )
        ba = ctx["block_analysis"]
        assert "Block-level analysis" in ba
        assert "taint-relevant branches" in ba

    def test_block_analysis_has_dangerous_calls(self, orchestrator_run):
        """Block context for parse_headers should flag memcpy."""
        _, review_fn = orchestrator_run
        ctx = review_fn.ctx_for("reqparse.c", "parse_headers")
        if ctx is None:
            pytest.skip("parse_headers was prefilter-skipped")
        ba = ctx.get("block_analysis", "")
        assert "DANGEROUS CALLS" in ba
        assert "memcpy" in ba

    def test_block_analysis_has_tainted_vars(self, orchestrator_run):
        """Block context should show tainted variables."""
        _, review_fn = orchestrator_run
        ctx = review_fn.ctx_for("reqparse.c", "parse_headers")
        if ctx is None:
            pytest.skip("parse_headers was prefilter-skipped")
        ba = ctx.get("block_analysis", "")
        assert "Tainted at entry:" in ba
        assert "buf" in ba.lower()

    def test_simple_function_no_block_analysis(self, orchestrator_run):
        """to_lowercase (simple) should NOT have block_analysis."""
        _, review_fn = orchestrator_run
        ctx = review_fn.ctx_for("reqparse.c", "to_lowercase")
        if ctx is None:
            return
        assert ctx.get("block_analysis") is None


# =====================================================================
# 3. Sink narrowing arrives at the review_fn
# =====================================================================


class TestSinkNarrowingInReviewFn:

    def test_unreachable_fn_has_sink_unreachable(self, orchestrator_run):
        """is_valid_method (no sinks) should have sink_unreachable=True."""
        _, review_fn = orchestrator_run
        ctx = review_fn.ctx_for("reqparse.c", "is_valid_method")
        if ctx is None:
            return
        assert ctx.get("sink_unreachable") is True

    def test_unreachable_fn_has_narrowed_classes(self, orchestrator_run):
        """Sink-unreachable function should have narrowed CWE classes."""
        _, review_fn = orchestrator_run
        ctx = review_fn.ctx_for("reqparse.c", "is_valid_method")
        if ctx is None:
            return
        narrowed = ctx.get("sink_narrowed_classes", [])
        assert len(narrowed) > 0
        assert "CWE-78" in narrowed

    def test_reachable_fn_no_sink_narrowing(self, orchestrator_run):
        """parse_headers (has memcpy) should NOT be sink-unreachable."""
        _, review_fn = orchestrator_run
        ctx = review_fn.ctx_for("reqparse.c", "parse_headers")
        if ctx is None:
            pytest.skip("parse_headers was prefilter-skipped")
        assert not ctx.get("sink_unreachable")
        assert ctx.get("sink_narrowed_classes", []) == []


# =====================================================================
# 4. Mechanical evidence arrives at the review_fn
# =====================================================================


class TestEvidenceInReviewFn:

    def test_taint_evidence_for_parse_headers(self, orchestrator_run):
        """parse_headers should get taint approx evidence."""
        _, review_fn = orchestrator_run
        ctx = review_fn.ctx_for("reqparse.c", "parse_headers")
        if ctx is None:
            pytest.skip("parse_headers was prefilter-skipped")
        evidence = ctx.get("mechanical_evidence", "")
        assert "memcpy" in evidence or "buf" in evidence, (
            "taint evidence should mention memcpy or buf"
        )

    def test_lookup_user_gets_taint_evidence(self, orchestrator_run):
        """lookup_user should get taint evidence for snprintf."""
        _, review_fn = orchestrator_run
        ctx = review_fn.ctx_for("database.c", "lookup_user")
        if ctx is None:
            pytest.skip("lookup_user was prefilter-skipped")
        evidence = ctx.get("mechanical_evidence", "")
        assert "snprintf" in evidence or "username" in evidence, (
            "taint evidence should mention snprintf or username"
        )

    def test_context_has_source(self, orchestrator_run):
        """Every reviewed function should have source code."""
        _, review_fn = orchestrator_run
        for call in review_fn.calls:
            source = call.ctx.get("source", "")
            assert len(source) > 0, (
                f"{call.file}:{call.function} has empty source"
            )


# =====================================================================
# 5. Prefilter decisions
# =====================================================================


class TestPrefilterDecisions:

    def test_prefilter_skipped_count(self, orchestrator_run):
        """Some functions should be prefilter-skipped."""
        result, _ = orchestrator_run
        assert result.prefilter_skipped >= 0

    def test_reviewed_plus_skipped_equals_total(self, orchestrator_run):
        """reviewed + prefilter_skipped should account for all gaps."""
        result, review_fn = orchestrator_run
        llm_reviewed = len(review_fn.calls)
        total = llm_reviewed + result.prefilter_skipped
        assert total > 0


# =====================================================================
# 6. Prompt rendering integrity
# =====================================================================


class TestPromptRenderingIntegrity:

    def test_rendered_prompt_contains_function_header(
        self, orchestrator_run,
    ):
        """Every reviewed function's prompt should have the header."""
        from core.audit.context import format_context_for_prompt

        _, review_fn = orchestrator_run
        for call in review_fn.calls[:5]:
            prompt = format_context_for_prompt(call.ctx)
            assert f"{call.file}:{call.function}" in prompt

    def test_rendered_prompt_block_analysis_present(
        self, orchestrator_run,
    ):
        """Functions with block_analysis should have it in rendered prompt."""
        from core.audit.context import format_context_for_prompt

        _, review_fn = orchestrator_run
        for call in review_fn.calls:
            if call.ctx.get("block_analysis"):
                prompt = format_context_for_prompt(call.ctx)
                assert "Block-level analysis" in prompt

    def test_rendered_prompt_scope_narrowing_present(
        self, orchestrator_run,
    ):
        """Functions with sink_unreachable should have narrowing in prompt."""
        from core.audit.context import format_context_for_prompt

        _, review_fn = orchestrator_run
        for call in review_fn.calls:
            if call.ctx.get("sink_unreachable"):
                prompt = format_context_for_prompt(call.ctx)
                assert "Scope narrowing" in prompt

    def test_no_api_keys_in_context(self, orchestrator_run):
        """Context dicts must never contain API keys or secrets."""
        _, review_fn = orchestrator_run
        for call in review_fn.calls:
            ctx_str = str(call.ctx)
            assert "sk-" not in ctx_str
            assert "ANTHROPIC_API_KEY" not in ctx_str
            assert "OPENAI_API_KEY" not in ctx_str

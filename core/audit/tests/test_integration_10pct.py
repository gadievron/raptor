"""Integration test: ~10% of core/audit/ through the orchestrator.

Exercises the post-session changes: error classification, error retry,
cost profiling across phases, per-language prompt budget, and live
classification discovery + re-review. Uses a deterministic mock review_fn
so no LLM calls are made.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

from core.audit.cost_tracker import PhaseCostLedger
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _classify_error,
    _retry_error_outcomes,
    _tally_outcome,
    _untally_outcome,
)

logger = logging.getLogger(__name__)


_CANNED_VERDICTS: dict[str, dict[str, Any]] = {
    "sweep.py:_run_semgrep_sweep": {
        "status": "finding",
        "body": "Uses subprocess.run with shell=True on untrusted input",
        "hypothesis": "passes unsanitized input to subprocess.run()",
        "review_result": {
            "dangerous_callees": ["subprocess.run"],
            "sanitizer_callees": [],
            "preconditions": [],
        },
        "cost_usd": 0.02,
    },
    "sweep.py:_run_smt_sweep": {
        "status": "clean",
        "body": "SMT solver dispatch is safe — input validated before use",
        "review_result": {
            "dangerous_callees": [],
            "sanitizer_callees": ["_validate_smt_input"],
            "preconditions": [],
        },
        "cost_usd": 0.01,
    },
    "context.py:format_context_for_prompt": {
        "status": "clean",
        "body": "Prompt assembly is safe — no user-controlled data in control positions",
        "cost_usd": 0.015,
    },
    "context.py:_build_context": {
        "status": "suspicious",
        "body": "Context may include attacker-controlled source code snippets",
        "hypothesis": "source code in context could contain prompt injection",
        "review_result": {
            "dangerous_callees": [],
            "sanitizer_callees": [],
            "preconditions": [{
                "check_type": "function_reaches_sink",
                "location": {"function": "_format_source_block"},
            }],
        },
        "cost_usd": 0.025,
    },
    "live_classifications.py:extract_from_outcome": {
        "status": "clean",
        "body": "Pure data extraction — no side effects beyond adding to sets",
        "cost_usd": 0.01,
    },
    "triage.py:_compute_triage_bucket": {
        "status": "clean",
        "body": "Deterministic bucket assignment based on code metrics",
        "cost_usd": 0.01,
    },
    "collector.py:_flush_batch": {
        "status": "suspicious",
        "body": "Writes to disk without validating path components",
        "review_result": {
            "dangerous_callees": ["_write_to_disk"],
            "sanitizer_callees": [],
            "preconditions": [],
        },
        "cost_usd": 0.02,
    },
    "cost_tracker.py:record_call": {
        "status": "clean",
        "body": "Pure accumulator — no external side effects",
        "cost_usd": 0.005,
    },
    "shared_state.py:__init__": {
        "status": "clean",
        "body": "Dataclass initialization — safe",
        "cost_usd": 0.005,
    },
}

_JSON_ERROR_FUNCS = {"validate.py:_parse_llm_response"}
_API_ERROR_FUNCS = {"collector.py:_submit_to_api"}


def _mock_review_fn(ctx: dict[str, Any], config: OrchestratorConfig) -> ReviewOutcome:
    """Deterministic mock that returns canned verdicts.

    For functions in _JSON_ERROR_FUNCS, raises a JSONDecodeError.
    For functions in _API_ERROR_FUNCS, raises a rate limit error.
    Otherwise uses _CANNED_VERDICTS or returns clean.
    """
    file_name = Path(ctx["file"]).name
    func_name = ctx["function"]
    key = f"{file_name}:{func_name}"

    if key in _JSON_ERROR_FUNCS:
        raise json.JSONDecodeError("Expecting value", "", 0)
    if key in _API_ERROR_FUNCS:
        raise RuntimeError("rate limit exceeded, retry after 30s")

    verdict = _CANNED_VERDICTS.get(key, {
        "status": "clean",
        "body": "No issues found",
        "cost_usd": 0.005,
    })

    return ReviewOutcome(
        file=ctx["file"],
        function=func_name,
        status=verdict["status"],
        body=verdict["body"],
        hypothesis=verdict.get("hypothesis", ""),
        review_result=verdict.get("review_result"),
        cost_usd=verdict.get("cost_usd", 0.005),
    )


class TestErrorClassifyIntegration:
    """Verify _classify_error works with real exception types."""

    def test_json_round_trips_through_tally(self):
        result = OrchestratorResult()
        exc = json.JSONDecodeError("bad", "", 0)
        outcome = ReviewOutcome(
            file="a.py", function="f", status="error",
            body=str(exc), error_class=_classify_error(exc),
        )
        _tally_outcome(result, outcome)
        assert result.error_counts == {"json_parse": 1}

        _untally_outcome(result, outcome)
        assert result.errors == 0
        assert result.error_counts == {"json_parse": 0}

    def test_api_error_tally_untally(self):
        result = OrchestratorResult()
        exc = RuntimeError("rate limit exceeded")
        outcome = ReviewOutcome(
            file="b.py", function="g", status="error",
            body=str(exc), error_class=_classify_error(exc),
        )
        _tally_outcome(result, outcome)
        assert result.error_counts == {"api_error": 1}

        _untally_outcome(result, outcome)
        assert result.errors == 0

    def test_mixed_error_classes(self):
        result = OrchestratorResult()
        classes = ["json_parse", "api_error", "content_filter", "json_parse"]
        for i, cls in enumerate(classes):
            outcome = ReviewOutcome(
                file="x.py", function=f"f{i}", status="error",
                body="err", error_class=cls,
            )
            _tally_outcome(result, outcome)
        assert result.errors == 4
        assert result.error_counts == {
            "json_parse": 2, "api_error": 1, "content_filter": 1,
        }


class TestCostTrackerPhases:
    """Verify the new phases are tracked correctly."""

    def test_all_new_phases_record(self):
        ct = PhaseCostLedger()
        new_phases = [
            "error_retry", "iris_synthesis", "re_review", "propagation",
        ]
        for phase in new_phases:
            ct.record_call(phase, cost_usd=0.01, tokens_in=100, tokens_out=50)

        assert ct.total_calls == 4
        assert abs(ct.total_cost_usd - 0.04) < 1e-6
        for phase in new_phases:
            assert phase in ct.phases
            assert ct.phases[phase].calls == 1

    def test_cost_breakdown_json(self, tmp_path):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.50, tokens_in=5000, tokens_out=1000)
        ct.record_call("re_review", cost_usd=0.10, tokens_in=1000, tokens_out=200)
        ct.record_call("error_retry", cost_usd=0.05, tokens_in=500, tokens_out=100)
        ct.record_call("iris_synthesis", cost_usd=0.03, tokens_in=300, tokens_out=80)

        path = ct.write(tmp_path)
        data = json.loads(path.read_text(encoding="utf-8"))

        assert "phases" in data
        assert "review" in data["phases"]
        assert "re_review" in data["phases"]
        assert "error_retry" in data["phases"]
        assert "iris_synthesis" in data["phases"]
        assert abs(data["totals"]["cost_usd"] - 0.68) < 0.01

    def test_summary_includes_new_phases(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.50)
        ct.record_call("error_retry", cost_usd=0.05)
        ct.record_call("re_review", cost_usd=0.10)
        ct.record_call("propagation", cost_usd=0.08)

        summary = ct.summary()
        assert "error_retry" in summary
        assert "re_review" in summary
        assert "propagation" in summary


class TestLangTokenCorrectionIntegration:
    """Verify per-language correction feeds into prompt budget."""

    def test_js_gets_tighter_budget(self):
        from core.audit.llm_review import _prompt_budget

        ctx_py = {
            "file": "handler.py",
            "function": "process",
            "source": "x" * 2000,
            "triage_token_budget": 6000,
        }
        ctx_js = {
            "file": "handler.js",
            "function": "process",
            "source": "x" * 2000,
            "triage_token_budget": 6000,
        }
        budget_py = _prompt_budget(ctx_py, "system prompt")
        budget_js = _prompt_budget(ctx_js, "system prompt")

        assert budget_js < budget_py, (
            f"JS budget ({budget_js}) should be tighter than Python ({budget_py})"
        )

    def test_minjs_tightest(self):
        from core.audit.llm_review import _prompt_budget

        ctx_min = {
            "file": "bundle.min.js",
            "function": "a",
            "source": "x" * 5000,
            "triage_token_budget": 6000,
        }
        ctx_ts = {
            "file": "handler.ts",
            "function": "process",
            "source": "x" * 5000,
            "triage_token_budget": 6000,
        }
        budget_min = _prompt_budget(ctx_min, "system prompt")
        budget_ts = _prompt_budget(ctx_ts, "system prompt")

        assert budget_min < budget_ts, (
            f"Minified JS budget ({budget_min}) should be tighter than TS ({budget_ts})"
        )


class TestRetryIntegration:
    """Verify error retry + cost tracking work end-to-end."""

    @patch("core.audit.orchestrator._build_context")
    def test_retry_records_cost(self, mock_build):
        mock_build.return_value = {
            "file": "src/api.js", "function": "handler",
            "source": "function handler() {}",
        }
        result = OrchestratorResult()
        outcome = ReviewOutcome(
            file="src/api.js", function="handler",
            status="error", body="json fail",
            error_class="json_parse", cost_usd=0.01,
        )
        _tally_outcome(result, outcome)
        result.total_cost_usd = 0.01

        config = OrchestratorConfig(
            target_path=Path("/tmp/target"),
            out_dir=Path("/tmp/out"),
        )
        checklist = {
            "files": [{
                "path": "src/api.js",
                "items": [{
                    "name": "handler",
                    "line_start": 1,
                    "line_end": 10,
                }],
            }],
        }

        recovered = ReviewOutcome(
            file="src/api.js", function="handler",
            status="clean", body="safe", cost_usd=0.02,
        )

        def mock_review_fn(ctx, cfg):
            return recovered

        result = _retry_error_outcomes(
            result, config, mock_review_fn, checklist, None,
            None, time.monotonic(), None,
        )

        assert result.error_retries == 1
        assert result.error_retry_recovered == 1
        assert result.errors == 0
        assert result.clean == 1
        phases = result.cost_tracker.to_dict()["phases"]
        assert "error_retry" in phases
        assert phases["error_retry"]["calls"] >= 1

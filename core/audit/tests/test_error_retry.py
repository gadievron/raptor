"""Tests for error classification and retry mechanisms."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _classify_error,
    _error_outcome,
    _retry_error_outcomes,
    _tally_outcome,
)


class TestClassifyError:
    def test_content_filter(self):
        exc = RuntimeError("blocked by content filter policy")
        assert _classify_error(exc) == "content_filter"

    def test_budget_exceeded(self):
        exc = RuntimeError("LLM budget exceeded: $5.00 > $4.50")
        assert _classify_error(exc) == "budget"

    def test_json_decode(self):
        exc = json.JSONDecodeError("Expecting value", "", 0)
        assert _classify_error(exc) == "json_parse"

    def test_truncation(self):
        exc = json.JSONDecodeError(
            "Response truncated (output token limit reached)", "", 0,
        )
        assert _classify_error(exc) == "truncation"

    def test_validation_error(self):
        class ValidationError(Exception):
            pass
        exc = ValidationError("field required")
        assert _classify_error(exc) == "json_parse"

    def test_rate_limit(self):
        exc = RuntimeError("rate limit exceeded, retry after 30s")
        assert _classify_error(exc) == "api_error"

    def test_timeout_is_distinct_class(self):
        # Timeouts classify as their own class (single reduced-context
        # retry inline; re-queued at reduced context + capped timeout
        # by the end-of-run retry pass) — see test_timeout_recovery.py.
        exc = TimeoutError("connection timeout after 30s")
        assert _classify_error(exc) == "timeout"

    def test_connection_error_stays_api_error(self):
        exc = ConnectionError("connection reset by peer")
        assert _classify_error(exc) == "api_error"

    def test_server_error(self):
        exc = RuntimeError("HTTP 502 bad gateway")
        assert _classify_error(exc) == "api_error"

    def test_quota(self):
        exc = RuntimeError("quota exceeded for this billing period")
        assert _classify_error(exc) == "api_error"

    def test_internal(self):
        exc = KeyError("missing_field")
        assert _classify_error(exc) == "internal"

    def test_overloaded(self):
        exc = RuntimeError("The server is overloaded")
        assert _classify_error(exc) == "api_error"


class TestErrorOutcome:
    def test_error_class_set(self):
        gap = {"file": "src/auth.c", "name": "check_pw"}
        exc = json.JSONDecodeError("bad", "", 0)
        outcome = _error_outcome(gap, exc)
        assert outcome.status == "error"
        assert outcome.error_class == "json_parse"
        assert "JSONDecodeError" in outcome.body

    def test_internal_error(self):
        gap = {"file": "src/auth.c", "name": "check_pw"}
        exc = KeyError("oops")
        outcome = _error_outcome(gap, exc)
        assert outcome.error_class == "internal"


class TestTallyErrorCounts:
    def test_error_counts_tracked(self):
        result = OrchestratorResult()
        outcome = ReviewOutcome(
            file="a.py", function="f", status="error",
            body="json fail", error_class="json_parse",
        )
        _tally_outcome(result, outcome)
        assert result.errors == 1
        assert result.error_counts == {"json_parse": 1}

    def test_multiple_classes(self):
        result = OrchestratorResult()
        for cls in ("json_parse", "api_error", "json_parse"):
            outcome = ReviewOutcome(
                file="a.py", function="f", status="error",
                body="fail", error_class=cls,
            )
            _tally_outcome(result, outcome)
        assert result.error_counts == {"json_parse": 2, "api_error": 1}

    def test_no_error_class(self):
        result = OrchestratorResult()
        outcome = ReviewOutcome(
            file="a.py", function="f", status="error",
            body="fail",
        )
        _tally_outcome(result, outcome)
        assert result.errors == 1
        assert result.error_counts == {}


class TestRetryErrorOutcomes:
    @staticmethod
    def _make_config(**kwargs):
        defaults = {
            "target_path": Path("/tmp/target"),
            "out_dir": Path("/tmp/out"),
            "max_cost_usd": 100.0,
            "max_seconds": 3600,
            "propagate_constraints": False,
        }
        defaults.update(kwargs)
        return OrchestratorConfig(**defaults)

    @staticmethod
    def _make_checklist(file_func_pairs):
        by_file: dict = {}
        for f, fn in file_func_pairs:
            by_file.setdefault(f, []).append({
                "name": fn,
                "line_start": 1,
                "line_end": 10,
            })
        return {
            "files": [
                {"path": fp, "items": items}
                for fp, items in by_file.items()
            ],
        }

    @patch("core.audit.orchestrator._build_context")
    def test_retries_recoverable_errors(self, mock_build):
        mock_build.return_value = {
            "file": "src/auth.c", "function": "check_pw",
            "source": "int check_pw(void) {}",
        }
        result = OrchestratorResult()
        error_outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="error", body="json fail",
            error_class="json_parse",
        )
        _tally_outcome(result, error_outcome)
        assert result.errors == 1

        config = self._make_config()
        checklist = self._make_checklist([("src/auth.c", "check_pw")])

        recovered = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="clean", body="looks safe",
        )
        call_count = 0
        def mock_review_fn(ctx, cfg):
            nonlocal call_count
            call_count += 1
            return recovered

        import time
        result = _retry_error_outcomes(
            result, config, mock_review_fn, checklist, None,
            None, time.monotonic(), None,
        )
        assert call_count == 1
        assert result.error_retries == 1
        assert result.error_retry_recovered == 1
        assert result.errors == 0
        assert result.clean == 1

    def test_skips_budget_errors(self):
        result = OrchestratorResult()
        error_outcome = ReviewOutcome(
            file="a.py", function="f",
            status="error", body="budget exceeded",
            error_class="budget",
        )
        _tally_outcome(result, error_outcome)

        config = self._make_config()
        checklist = self._make_checklist([("a.py", "f")])

        def mock_review_fn(ctx, cfg):
            raise AssertionError("should not be called")

        import time
        result = _retry_error_outcomes(
            result, config, mock_review_fn, checklist, None,
            None, time.monotonic(), None,
        )
        assert result.error_retries == 0
        assert result.errors == 1

    def test_skips_internal_errors(self):
        result = OrchestratorResult()
        error_outcome = ReviewOutcome(
            file="a.py", function="f",
            status="error", body="KeyError",
            error_class="internal",
        )
        _tally_outcome(result, error_outcome)

        config = self._make_config()
        checklist = self._make_checklist([("a.py", "f")])

        def mock_review_fn(ctx, cfg):
            raise AssertionError("should not be called")

        import time
        result = _retry_error_outcomes(
            result, config, mock_review_fn, checklist, None,
            None, time.monotonic(), None,
        )
        assert result.error_retries == 0

    @patch("core.audit.orchestrator._build_context")
    def test_strips_context_for_truncation(self, mock_build):
        mock_build.return_value = {
            "file": "src/auth.c", "function": "check_pw",
            "source": "int check_pw(void) {}",
            "block_analysis": {"data": "big"},
            "sibling_ns": ["finding"],
            "type_constraints": {"x": "int"},
        }
        result = OrchestratorResult()
        error_outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="error", body="truncated",
            error_class="truncation",
        )
        _tally_outcome(result, error_outcome)

        config = self._make_config()
        checklist = self._make_checklist([("src/auth.c", "check_pw")])

        captured_ctx = {}
        def mock_review_fn(ctx, cfg):
            captured_ctx.update(ctx)
            return ReviewOutcome(
                file="src/auth.c", function="check_pw",
                status="clean", body="ok",
            )

        import time
        _retry_error_outcomes(
            result, config, mock_review_fn, checklist, None,
            None, time.monotonic(), None,
        )
        assert captured_ctx.get("error_retry") is True
        assert "block_analysis" not in captured_ctx
        assert "sibling_ns" not in captured_ctx
        assert "type_constraints" not in captured_ctx

    @patch("core.audit.orchestrator._build_context")
    def test_retry_still_fails(self, mock_build):
        mock_build.return_value = {
            "file": "a.py", "function": "f",
            "source": "def f(): pass",
        }
        result = OrchestratorResult()
        error_outcome = ReviewOutcome(
            file="a.py", function="f",
            status="error", body="api fail",
            error_class="api_error",
        )
        _tally_outcome(result, error_outcome)

        config = self._make_config()
        checklist = self._make_checklist([("a.py", "f")])

        def mock_review_fn(ctx, cfg):
            raise RuntimeError("still failing")

        import time
        result = _retry_error_outcomes(
            result, config, mock_review_fn, checklist, None,
            None, time.monotonic(), None,
        )
        assert result.error_retries == 0
        assert result.errors == 1

    def test_no_errors_noop(self):
        result = OrchestratorResult()
        clean = ReviewOutcome(
            file="a.py", function="f", status="clean", body="ok",
        )
        _tally_outcome(result, clean)

        config = self._make_config()

        def mock_review_fn(ctx, cfg):
            raise AssertionError("should not be called")

        import time
        result = _retry_error_outcomes(
            result, config, mock_review_fn, {}, None,
            None, time.monotonic(), None,
        )
        assert result.error_retries == 0


class TestRetryGapSpan:
    """The retry must rebuild the gap WITH its line span — a span-less
    gap made the retry review the file's opening lines and re-journal
    a wrong-source verdict as authoritative."""

    _make_config = staticmethod(TestRetryErrorOutcomes._make_config)

    @staticmethod
    def _checklist_with_span(file, fn, line_start, line_end):
        return {
            "files": [{
                "path": file,
                "items": [{
                    "name": fn,
                    "line_start": line_start,
                    "line_end": line_end,
                }],
            }],
        }

    def _run(self, checklist, outcome_line=0):
        import time

        captured_gaps = []

        def fake_build(config, gap, cl, cm, *a, **kw):
            captured_gaps.append(dict(gap))
            return {"file": gap["file"], "function": gap["name"]}

        result = OrchestratorResult()
        error_outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="error", body="json fail",
            error_class="json_parse",
        )
        error_outcome.line = outcome_line
        _tally_outcome(result, error_outcome)

        recovered = ReviewOutcome(
            file="src/auth.c", function="check_pw",
            status="clean", body="looks safe",
        )
        with patch(
            "core.audit.orchestrator._build_context",
            side_effect=fake_build,
        ):
            result = _retry_error_outcomes(
                result, self._make_config(), lambda ctx, cfg: recovered,
                checklist, None, None, time.monotonic(), None,
            )
        return captured_gaps, result

    def test_checklist_span_used(self):
        checklist = self._checklist_with_span("src/auth.c", "check_pw", 42, 90)
        gaps, result = self._run(checklist)
        assert gaps and gaps[0]["line_start"] == 42
        assert gaps[0]["line_end"] == 90
        # The recovered verdict carries the function's line, not 0.
        assert result.outcomes[0].line == 42

    def test_outcome_line_fallback(self):
        # Function missing from the checklist: outcome.line (stamped
        # from the original gap's line_start) restores the start.
        checklist = {"files": []}
        gaps, result = self._run(checklist, outcome_line=57)
        assert gaps and gaps[0].get("line_start") == 57
        assert result.outcomes[0].line == 57


class TestRetryContextReducedTag:
    """Both context-stripping lanes (truncation AND timeout) must tag
    recovered verdicts context_reduced; non-stripping lanes must not."""

    _make_config = staticmethod(TestRetryErrorOutcomes._make_config)
    _make_checklist = staticmethod(TestRetryErrorOutcomes._make_checklist)

    def _recovering_run(self, error_class):
        import time

        result = OrchestratorResult()
        error_outcome = ReviewOutcome(
            file="a.c", function="f",
            status="error", body="fail",
            error_class=error_class,
        )
        _tally_outcome(result, error_outcome)

        recovered = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
        )
        recovered.review_result = {}
        with patch(
            "core.audit.orchestrator._build_context",
            return_value={"file": "a.c", "function": "f"},
        ):
            result = _retry_error_outcomes(
                result, self._make_config(), lambda ctx, cfg: recovered,
                self._make_checklist([("a.c", "f")]), None,
                None, time.monotonic(), None,
            )
        return result.outcomes[0]

    def test_truncation_recovery_tagged(self):
        out = self._recovering_run("truncation")
        assert out.context_reduced is True
        assert out.review_result["context_reduced"] is True

    def test_timeout_recovery_tagged(self):
        out = self._recovering_run("timeout")
        assert out.context_reduced is True

    def test_json_parse_recovery_untagged(self):
        # json_parse retries keep full context — the tag would force a
        # needless full-context re-review next run.
        out = self._recovering_run("json_parse")
        assert not out.context_reduced
        assert "context_reduced" not in out.review_result

"""Timeout retry policy at the orchestrator layer.

A timed-out review call gets ONE immediate retry with reduced context
(the truncation strip set) and a capped per-call timeout. The result
is tagged ``context_reduced`` so deepen re-reviews it at full context.
Timeout-class error outcomes are excluded from the end-of-run error
retry pass — the inline retry is the single permitted one.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from core.audit.orchestrator import (
    _RECOVERABLE_ERROR_CLASSES,
    _TIMEOUT_RETRY_TIMEOUT_S,
    _TRUNCATION_STRIP_KEYS,
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _classify_error,
    _deepen_suspicious,
    _retry_error_outcomes,
    _tally_outcome,
    _timeout_reduced_retry,
)


def _config(tmp_path: Path, **kwargs) -> OrchestratorConfig:
    defaults = {
        "target_path": tmp_path,
        "out_dir": tmp_path,
        "propagate_constraints": False,
        "sweep_validate_findings": False,
        "enable_session_context": False,
        "blind_first_pass": False,
    }
    defaults.update(kwargs)
    return OrchestratorConfig(**defaults)


class TestTimeoutClassification:
    def test_cc_transport_timeout_classifies_as_timeout(self):
        exc = RuntimeError("claude -p timed out after 600s")
        assert _classify_error(exc) == "timeout"

    def test_timeout_error_instance_classifies_as_timeout(self):
        assert _classify_error(TimeoutError("read timed out")) == "timeout"

    def test_rate_limit_stays_api_error(self):
        exc = RuntimeError("rate limit exceeded, retry after 30s")
        assert _classify_error(exc) == "api_error"

    def test_timeout_not_in_recoverable_classes(self):
        # The end-of-run error retry pass must skip timeout outcomes:
        # the inline reduced-context retry is the one permitted retry.
        assert "timeout" not in _RECOVERABLE_ERROR_CLASSES

    def test_end_of_run_pass_skips_timeout_outcomes(self, tmp_path):
        result = OrchestratorResult()
        _tally_outcome(result, ReviewOutcome(
            file="a.c", function="f", status="error",
            body="timed out", error_class="timeout",
        ))

        def review_fn(ctx, cfg):
            raise AssertionError("timeout outcomes must not be retried")

        result = _retry_error_outcomes(
            result, _config(tmp_path), review_fn,
            {"files": [{"path": "a.c", "items": [
                {"name": "f", "line_start": 1, "line_end": 10},
            ]}]},
            None, None, time.monotonic(), None,
        )
        assert result.error_retries == 0
        assert result.errors == 1


class TestTimeoutReducedRetry:
    def _ctx(self):
        return {
            "file": "src/auth.c",
            "function": "check_pw",
            "source": "int check_pw(void) {}",
            "block_analysis": {"data": "big"},
            "sibling_ns": ["x"],
            "type_constraints": {"x": "int"},
        }

    def _gap(self):
        return {"file": "src/auth.c", "name": "check_pw"}

    def test_strips_context_caps_timeout_and_tags(self, tmp_path):
        captured = {}

        def review_fn(ctx, cfg):
            captured.update(ctx)
            return ReviewOutcome(
                file="src/auth.c", function="check_pw",
                status="clean", body="ok",
                review_result={"status": "clean", "body": "ok"},
            )

        outcome = _timeout_reduced_retry(
            self._gap(), self._ctx(),
            RuntimeError("claude -p timed out after 600s"),
            review_fn, _config(tmp_path),
        )

        for key in _TRUNCATION_STRIP_KEYS:
            assert key not in captured
        assert captured["error_retry"] is True
        assert captured["timeout_s"] == _TIMEOUT_RETRY_TIMEOUT_S
        assert outcome.status == "clean"
        assert outcome.context_reduced is True
        assert outcome.review_result["context_reduced"] is True

    def test_retry_failure_degrades_to_timeout_error_outcome(
        self, tmp_path,
    ):
        def review_fn(ctx, cfg):
            raise RuntimeError("reduced retry also timed out")

        outcome = _timeout_reduced_retry(
            self._gap(), self._ctx(),
            RuntimeError("claude -p timed out after 600s"),
            review_fn, _config(tmp_path),
        )
        assert outcome.status == "error"
        # Classified from the ORIGINAL timeout — keeps the outcome
        # excluded from the end-of-run retry pass.
        assert outcome.error_class == "timeout"
        assert outcome.context_reduced is False

    def test_budget_exhaustion_during_retry_reraises(self, tmp_path):
        def review_fn(ctx, cfg):
            raise RuntimeError("LLM budget exceeded: $5 > $4")

        with pytest.raises(RuntimeError, match="budget exceeded"):
            _timeout_reduced_retry(
                self._gap(), self._ctx(),
                RuntimeError("claude -p timed out after 600s"),
                review_fn, _config(tmp_path),
            )


class TestReviewFnTimeoutCapPlumbing:
    """review_fn forwards a per-call ``timeout_s`` to the client:
    ctx['timeout_s'] when the recovery path set one, else the
    review-class default. Review calls also opt out of the client's
    identical timeout retry (``timeout_retry_cap=0``) — their
    recovery is the orchestrator's reduced-context retry."""

    class _FakeClient:
        def __init__(self):
            self.captured_kwargs = None

        def supports_prompt_caching_for(self):
            return False

        def generate_structured(self, prompt, schema,
                                system_prompt=None, **kwargs):
            self.captured_kwargs = dict(kwargs)

            class _Resp:
                def __init__(self):
                    self.result = {"status": "clean", "body": "ok"}
                    self.cost = 0.0
                    self.model = "fake"

            return _Resp()

    def _review(self, ctx):
        from core.audit.llm_review import make_review_fn
        client = self._FakeClient()
        review_fn = make_review_fn(client)
        base = {
            "file": "a.c", "function": "f", "source": "int f(){}",
            "line_start": 1, "line_end": 3,
        }
        base.update(ctx)
        review_fn(base, None)
        return client

    def test_timeout_cap_forwarded(self):
        client = self._review({"timeout_s": 300})
        assert client.captured_kwargs.get("timeout_s") == 300

    def test_review_class_default_timeout(self):
        from core.audit.llm_review import REVIEW_TIMEOUT_S
        client = self._review({})
        assert client.captured_kwargs.get("timeout_s") == REVIEW_TIMEOUT_S

    def test_review_path_disables_identical_timeout_retry(self):
        client = self._review({})
        assert client.captured_kwargs.get("timeout_retry_cap") == 0

    def test_ctx_cap_beats_class_default(self):
        from core.audit.llm_review import REVIEW_TIMEOUT_S
        client = self._review({"timeout_s": 300})
        assert client.captured_kwargs.get("timeout_s") != REVIEW_TIMEOUT_S


class TestDeepenPicksUpReducedOutcomes:
    def _checklist(self):
        return {"files": [{"path": "a.c", "functions": [
            {"name": "foo", "line_start": 1, "line_end": 5},
        ]}]}

    def test_clean_reduced_outcome_re_reviewed_at_full_context(
        self, monkeypatch, tmp_path,
    ):
        import core.audit.orchestrator as _orch

        prior = ReviewOutcome(
            file="a.c", function="foo", status="clean", body="ok",
            review_result={"status": "clean", "body": "ok",
                           "context_reduced": True},
            context_reduced=True,
        )
        result = OrchestratorResult(outcomes=[prior], clean=1)

        full_ctx = {
            "file": "a.c", "function": "foo",
            "block_analysis": {"restored": True},
        }
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: dict(full_ctx),
        )

        seen = []

        def review_fn(ctx, cfg):
            seen.append(ctx)
            return ReviewOutcome(
                file="a.c", function="foo", status="clean",
                body="clean at full context",
                review_result={"status": "clean",
                               "body": "clean at full context"},
            )

        out = _deepen_suspicious(
            result, _config(tmp_path), review_fn, self._checklist(),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )

        # Re-reviewed once, at full (rebuilt) context, deepen-flagged.
        assert len(seen) == 1
        assert seen[0]["deepen"] is True
        assert "block_analysis" in seen[0]
        # Prior reduced verdict replaced; tag cleared on the new one.
        assert len(out.outcomes) == 1
        assert out.outcomes[0].body == "clean at full context"
        assert out.outcomes[0].context_reduced is False

    def test_plain_clean_outcome_not_picked_up(
        self, monkeypatch, tmp_path,
    ):
        import core.audit.orchestrator as _orch

        prior = ReviewOutcome(
            file="a.c", function="foo", status="clean", body="ok",
            review_result={"status": "clean", "body": "ok"},
        )
        result = OrchestratorResult(outcomes=[prior], clean=1)
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {"file": "a.c", "function": "foo"},
        )

        def review_fn(ctx, cfg):
            raise AssertionError("plain clean must not deepen")

        out = _deepen_suspicious(
            result, _config(tmp_path), review_fn, self._checklist(),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )
        assert out.outcomes == [prior]

    def test_error_reduced_outcome_not_picked_up(
        self, monkeypatch, tmp_path,
    ):
        import core.audit.orchestrator as _orch

        prior = ReviewOutcome(
            file="a.c", function="foo", status="error", body="failed",
            error_class="timeout", context_reduced=True,
        )
        result = OrchestratorResult(outcomes=[prior])
        _tally_outcome(result, prior, append=False)
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {"file": "a.c", "function": "foo"},
        )

        def review_fn(ctx, cfg):
            raise AssertionError("error outcomes must not deepen")

        out = _deepen_suspicious(
            result, _config(tmp_path), review_fn, self._checklist(),
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )
        assert out.outcomes == [prior]


class TestReviewOneFunctionTimeoutPath:
    """The main-loop error path routes first timeouts through the
    reduced-context retry (source-level wiring check plus the
    classification gate above give end-to-end coverage; the heavy
    review_one_function scaffolding is exercised in integration
    tests)."""

    def test_wiring_present(self):
        src = (Path(__file__).resolve().parents[1]
               / "orchestrator.py").read_text()
        idx = src.find("def review_one_function")
        assert idx != -1
        end = src.find("\ndef ", idx)
        window = src[idx:end if end != -1 else len(src)]
        assert "_timeout_reduced_retry(" in window
        assert '_classify_error(exc) == "timeout"' in window


class TestMultiPassReviewUnaffected:
    def test_multi_pass_error_still_produces_error_outcome(self, tmp_path):
        from core.audit.orchestrator import _multi_pass_review

        def review_fn(ctx, cfg):
            raise RuntimeError("claude -p timed out after 600s")

        outcome = _multi_pass_review(
            review_fn,
            {"file": "a.c", "function": "f"},
            _config(tmp_path),
            2,
        )
        assert outcome.status == "error"

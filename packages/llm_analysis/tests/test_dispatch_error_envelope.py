"""Error-envelope routing + token telemetry in the generic dispatcher.

Non-raising dispatch paths (the CC subprocess adapter, wrapped
clients) report failures as ``DispatchResult(result={"error": ...})``.
Those must traverse the FAILURE machinery — error classification,
per-model attribution, consecutive-failure circuit breaker — not the
success path (which would reset the failure counter, record
schema-accepted telemetry, and print "done" while a dead transport
burns one full timeout per finding for the whole run).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.dispatch import (  # noqa: E402
    DispatchResult,
    dispatch_task,
)
from packages.llm_analysis.orchestrator import CostTracker  # noqa: E402
from packages.llm_analysis.tasks import AnalysisTask  # noqa: E402


def _make_finding(finding_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "rule_id": "sqli",
        "file_path": "db.py",
        "start_line": 42,
        "end_line": 45,
        "level": "error",
        "message": "Potential sqli",
        "code": "bad()",
        "surrounding_context": "context",
    }


class TestErrorDictRoutedToFailurePath:

    def test_error_envelopes_are_failure_records(self):
        import time

        findings = [_make_finding(f"f-{i:03d}") for i in range(10)]
        calls = []
        tracker = CostTracker(0)

        def dead_transport(prompt, schema, system_prompt, temperature, model):
            n_prior = len(calls)
            calls.append(1)
            # Deterministic drain sync (replaces a sleep-won race with
            # a fixed tolerance band, which a starved CI host could
            # lose): the drain loop books each error envelope's tokens
            # into the cost tracker, so block until every PRIOR
            # failure has been booked — the dead-set is then current
            # before the next worker's dead-check can run. Reaching
            # the breaker threshold is therefore timing-independent.
            # Post-abort stragglers (see the count assertion below)
            # wait on a booking that never comes — give them a short
            # deadline so each stall also gives the drain thread ample
            # time to land cancel_futures, instead of hanging to a
            # long timeout.
            deadline = time.monotonic() + (10.0 if n_prior < 3 else 0.5)
            while (tracker.get_summary()["total_tokens"] < n_prior
                    and time.monotonic() < deadline):
                time.sleep(0.002)
            return DispatchResult(
                result={"error": "timeout after 300s"},
                model="claude-code",
                tokens=1,
            )

        results = dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=dead_transport,
            role_resolution={},  # CC shape: model=None work items
            prior_results={},
            cost_tracker=tracker,
            max_parallel=1,
        )

        # Circuit breaker fired: a never-succeeded model is declared
        # dead after 3 consecutive failures — the whole run must not
        # pay one timeout per finding. One extra call (the worker whose
        # dead-check preceded the third failure's drain) always gets
        # in; when the all-models abort shuts the pool down, at most a
        # couple of already-dequeued futures can slip the
        # cancel-futures window, and each straggler's 0.5s stall gives
        # the drain thread that long to land the cancellation.
        assert 4 <= len(calls) <= 6
        assert len(results) == 10

        errored = [r for r in results if "error" in r]
        assert len(errored) == 10
        # Real failures carry classification + attribution.
        classified = [r for r in errored
                      if r.get("error") == "timeout after 300s"]
        assert classified
        for r in classified:
            assert r["error_type"] == "timeout"
            assert r["analysed_by"] == "claude-code"
        # Remaining findings were abort-backfilled once every model
        # was circuit-broken.
        assert any(
            str(r.get("error", "")).startswith("aborted")
            or r.get("error_type") == "circuit_breaker"
            for r in errored
        )

    def test_empty_error_string_still_routes_to_failure_path(self):
        """{"error": ""} is an error ENVELOPE per _ErrorDictResult's
        contract (dicts with an ``error`` key) — a truthiness check
        let it ride the success path and reset the breaker."""
        findings = [_make_finding("f-000")]

        def empty_error(prompt, schema, system_prompt, temperature, model):
            return DispatchResult(result={"error": ""}, model="claude-code")

        results = dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=empty_error,
            role_resolution={},
            prior_results={},
            cost_tracker=CostTracker(0),
            max_parallel=1,
        )
        assert len(results) == 1
        assert "error" in results[0]
        # The discriminator: only the FAILURE machinery classifies the
        # error — the success path copies the envelope through
        # verbatim (with a _quality stamp) and resets the breaker.
        assert "error_type" in results[0]
        assert "_quality" not in results[0]

    def test_successful_results_still_succeed(self):
        # Two-direction: healthy payloads keep flowing through the
        # success path untouched.
        findings = [_make_finding(f"f-{i:03d}") for i in range(4)]

        def healthy(prompt, schema, system_prompt, temperature, model):
            return DispatchResult(
                result={
                    "is_true_positive": True,
                    "is_exploitable": False,
                    "exploitability_score": 0.1,
                    "reasoning": "fine",
                },
                cost=0.01, tokens=100, model="m1",
            )

        results = dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=healthy,
            role_resolution={},
            prior_results={},
            cost_tracker=CostTracker(0),
            max_parallel=2,
        )
        assert len(results) == 4
        assert all("error" not in r for r in results)

    def test_error_envelope_cost_still_booked(self):
        # A failed CC call can still have billed before dying — the
        # spend must reach the tracker even though the record is a
        # failure.
        findings = [_make_finding("f-000")]
        tracker = CostTracker(0)

        def billed_failure(prompt, schema, system_prompt, temperature, model):
            return DispatchResult(
                result={"error": "exit code 1: boom"},
                cost=0.25, tokens=1234, model="claude-code",
            )

        dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=billed_failure,
            role_resolution={},
            prior_results={},
            cost_tracker=tracker,
            max_parallel=1,
        )
        assert tracker.total_cost == 0.25
        assert tracker.get_summary()["total_tokens"] == 1234


class TestThinkingTokenTelemetry:

    def test_thinking_tokens_flow_to_tracker(self):
        findings = [_make_finding("f-000"), _make_finding("f-001")]
        tracker = CostTracker(0)

        def thinking(prompt, schema, system_prompt, temperature, model):
            return DispatchResult(
                result={
                    "is_true_positive": False,
                    "is_exploitable": False,
                    "exploitability_score": 0.0,
                    "reasoning": "fine",
                },
                cost=0.02, tokens=200, model="m1", thinking_tokens=77,
            )

        dispatch_task(
            task=AnalysisTask(),
            items=findings,
            dispatch_fn=thinking,
            role_resolution={},
            prior_results={},
            cost_tracker=tracker,
            max_parallel=1,
        )
        assert tracker.get_summary()["thinking_tokens"] == 154

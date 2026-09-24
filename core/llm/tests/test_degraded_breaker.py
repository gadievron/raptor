"""Run-level degraded-mode breaker (core/llm/breaker.py).

Covers the trip taxonomy (transport-class failures count, refusals /
quota / auth do not), the two-direction regression pairs for every
tuned threshold (fraction, min-samples floor, sustain span, window
aging), env overrides, pytest gating, and the end-to-end contract
through ``LLMClient.generate``: a sustained 50% transport-failure
stream trips the breaker, the tripping call itself still drains
through its own error path, every NEW dispatch refuses with
``LLMDegradedModeError`` — which classifies as a budget stop (the
run-terminal drain/checkpoint contract consumers key on) — and the
trip evidence persists in the telemetry JSONL.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.llm import breaker as breaker_mod
from core.llm.breaker import (
    DegradedModeBreaker,
    check_degraded_mode,
    note_llm_outcome,
    set_degradation_breaker,
)
from core.llm.client import (
    LLMBudgetExceededError,
    LLMClient,
    LLMDegradedModeError,
    is_budget_exceeded_error,
)
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture(autouse=True)
def _isolated_breaker():
    """No test leaks a singleton (or a trip) into its neighbours."""
    set_degradation_breaker(None)
    yield
    set_degradation_breaker(None)


def _breaker(clock: FakeClock, **overrides) -> DegradedModeBreaker:
    params = {
        "failure_fraction": 0.5,
        "window_s": 600.0,
        "min_samples": 10,
        "sustain_s": 60.0,
        "clock": clock,
    }
    params.update(overrides)
    return DegradedModeBreaker(**params)


def _feed(
    b: DegradedModeBreaker,
    clock: FakeClock,
    dispositions: list[str],
    *,
    step_s: float = 30.0,
) -> None:
    for d in dispositions:
        clock.advance(step_s)
        b.record(d)


class TestTripAndTaxonomy:
    def test_sustained_transport_majority_trips(self):
        clock = FakeClock()
        b = _breaker(clock)
        _feed(b, clock, ["ok", "retryable"] * 5)
        assert b.tripped
        assert "retryable" in b.trip_message
        assert isinstance(b.to_dict()["trip_stats"]["fraction"], float)

    def test_timeout_and_consumed_count(self):
        clock = FakeClock()
        b = _breaker(clock)
        _feed(b, clock, ["ok", "timeout", "ok", "consumed"] * 3)
        assert b.tripped
        # Dominant class named in the message (3 of each — Counter
        # picks one deterministically; both are counted classes).
        assert ("timeout" in b.trip_message
                or "consumed" in b.trip_message)

    def test_blocked_dominated_stream_never_trips(self):
        # Hostile-corpus shape: most calls refused by the model, a few
        # stray transport failures. Refusals are content-driven, not
        # provider-driven — they sit in the denominator only.
        clock = FakeClock()
        b = _breaker(clock)
        _feed(b, clock, (["blocked"] * 8 + ["retryable"] * 2) * 3)
        assert not b.tripped

    def test_quota_and_auth_do_not_count(self):
        # 429s belong to the AdaptiveThrottle; auth streaks to the
        # AuthFailureTracker. Neither may trip the run breaker.
        clock = FakeClock()
        b = _breaker(clock)
        _feed(b, clock, ["quota", "auth", "fatal", "ok"] * 6)
        assert not b.tripped

    def test_trip_latches(self):
        clock = FakeClock()
        b = _breaker(clock)
        _feed(b, clock, ["retryable"] * 10)
        assert b.tripped
        # A flood of later successes does not un-trip.
        _feed(b, clock, ["ok"] * 50)
        assert b.tripped


class TestThresholdBothDirections:
    """Two-direction regression pairs for every tuned limit."""

    def test_fraction_at_threshold_trips(self):
        clock = FakeClock()
        b = _breaker(clock)
        _feed(b, clock, ["ok", "retryable"] * 5)  # exactly 0.50
        assert b.tripped

    def test_fraction_just_below_threshold_does_not_trip(self):
        clock = FakeClock()
        b = _breaker(clock, min_samples=10)
        # 9 counted / 20 samples = 0.45 < 0.50 at the end, and the
        # two leading successes keep every evaluated prefix below the
        # threshold too (the breaker evaluates on each record).
        _feed(b, clock, ["ok", "ok"] + ["ok", "retryable"] * 9)
        assert not b.tripped

    def test_min_samples_floor_blocks_small_runs(self):
        clock = FakeClock()
        b = _breaker(clock, min_samples=10)
        _feed(b, clock, ["retryable"] * 9)  # 100% failing but n=9
        assert not b.tripped

    def test_min_samples_reached_trips(self):
        clock = FakeClock()
        b = _breaker(clock, min_samples=10)
        _feed(b, clock, ["retryable"] * 10)
        assert b.tripped

    def test_short_blip_under_sustain_does_not_trip(self):
        # A concurrency burst: 20 failures within seconds — the shape
        # retry/backoff and the throttle already handle.
        clock = FakeClock()
        b = _breaker(clock, sustain_s=60.0)
        _feed(b, clock, ["retryable"] * 20, step_s=1.0)
        assert not b.tripped

    def test_same_stream_past_sustain_trips(self):
        clock = FakeClock()
        b = _breaker(clock, sustain_s=60.0)
        _feed(b, clock, ["retryable"] * 20, step_s=4.0)  # spans 76s
        assert b.tripped

    def test_window_ages_out_old_failures(self):
        # An old burst followed by a healthy quiet stretch: by the
        # time fresh traffic flows, the burst is outside the window.
        clock = FakeClock()
        b = _breaker(clock, window_s=600.0)
        _feed(b, clock, ["retryable"] * 9, step_s=1.0)
        clock.advance(700.0)
        _feed(b, clock, ["ok"] * 10 + ["retryable"], step_s=10.0)
        assert not b.tripped

    def test_failures_inside_window_still_count(self):
        clock = FakeClock()
        b = _breaker(clock, window_s=600.0)
        _feed(b, clock, ["retryable"] * 9, step_s=10.0)
        clock.advance(100.0)  # still inside the window
        _feed(b, clock, ["ok", "retryable"], step_s=10.0)
        assert b.tripped

    def test_sustain_clamped_to_window(self):
        clock = FakeClock()
        b = _breaker(clock, window_s=100.0, sustain_s=10_000.0)
        # An impossible sustain would make the breaker dead weight;
        # the clamp (90% of the window) keeps it satisfiable.
        assert b.to_dict()["sustain_s"] == 90.0
        _feed(b, clock, ["retryable"] * 15, step_s=8.0)
        assert b.tripped


class TestEnvOverrides:
    def test_threshold_raised_by_env(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_THRESHOLD", "0.8")
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_MIN_SAMPLES", "10")
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_SUSTAIN_S", "0")
        b = DegradedModeBreaker.from_env()
        clock = FakeClock()
        b._clock = clock  # from_env has no clock param; inject for test
        _feed(b, clock, ["ok", "retryable"] * 10)  # 0.5 < 0.8
        assert not b.tripped

    def test_threshold_lowered_by_env(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_THRESHOLD", "0.3")
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_MIN_SAMPLES", "10")
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_SUSTAIN_S", "0")
        b = DegradedModeBreaker.from_env()
        clock = FakeClock()
        b._clock = clock
        _feed(b, clock, ["ok", "ok", "retryable"] * 6)  # ~0.33 >= 0.3
        assert b.tripped

    def test_invalid_env_values_keep_defaults(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_THRESHOLD", "lots")
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_WINDOW_S", "-5")
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_MIN_SAMPLES", "2.5")
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_SUSTAIN_S", "1e9")
        b = DegradedModeBreaker.from_env()
        d = b.to_dict()
        assert d["failure_fraction"] == 0.5
        assert d["window_s"] == 600.0
        assert d["min_samples"] == 20
        assert d["sustain_s"] == 300.0


class TestGatingAndClassification:
    def test_suppressed_under_pytest_without_opt_in(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LLM_BREAKER_TEST", raising=False)
        note_llm_outcome("retryable")
        # The singleton was never even constructed.
        assert breaker_mod._singleton is None

    def test_check_no_raise_when_suppressed(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LLM_BREAKER_TEST", raising=False)
        clock = FakeClock()
        b = _breaker(clock)
        _feed(b, clock, ["retryable"] * 10)
        set_degradation_breaker(b)
        check_degraded_mode()  # no raise: pytest gate active

    def test_kill_switch_disables(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_TEST", "1")
        monkeypatch.setenv("RAPTOR_LLM_BREAKER", "0")
        clock = FakeClock()
        b = _breaker(clock)
        _feed(b, clock, ["retryable"] * 10)
        set_degradation_breaker(b)
        check_degraded_mode()  # no raise: operator kill switch
        note_llm_outcome("retryable")  # and recording is inert too

    def test_raise_if_tripped_is_budget_classified(self):
        clock = FakeClock()
        b = _breaker(clock)
        _feed(b, clock, ["retryable"] * 10)
        with pytest.raises(LLMDegradedModeError) as exc_info:
            b.raise_if_tripped()
        err = exc_info.value
        # The run-terminal contract: consumers' budget-stop predicates
        # (isinstance RuntimeError + is_budget_exceeded_error) engage
        # their graceful drain/checkpoint path on this type.
        assert isinstance(err, LLMBudgetExceededError)
        assert isinstance(err, RuntimeError)
        assert is_budget_exceeded_error(err)
        assert "degraded-mode breaker tripped" in str(err)
        assert "re-run" in str(err)

    def test_untripped_raise_is_noop(self):
        _breaker(FakeClock()).raise_if_tripped()


# ── End-to-end through LLMClient.generate ─────────────────────────────


def _client() -> LLMClient:
    return LLMClient(LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="primary",
            api_key="test-key",
        ),
        fallback_models=[], enable_caching=False,
        enable_fallback=False, max_retries=1,
    ))


def _ok_response() -> LLMResponse:
    # cost=0.0: a nonzero figure would trip the scorecard's
    # paid-call-from-test leak diagnostic on every suite run.
    return LLMResponse(
        content="fine", model="primary", provider="anthropic",
        tokens_used=1, cost=0.0, finish_reason="stop",
    )


class TestThroughGenerate:
    @pytest.fixture(autouse=True)
    def _armed(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_BREAKER_TEST", "1")

    def _install(self, clock: FakeClock, **overrides) -> DegradedModeBreaker:
        b = _breaker(clock, **overrides)
        set_degradation_breaker(b)
        return b

    def _drive(self, client: LLMClient, clock: FakeClock,
               outcomes: list[bool], *, step_s: float = 30.0) -> None:
        """One generate() per outcome: True = success, False =
        transport-class failure (its own RuntimeError drains out —
        never the degraded-mode error mid-call)."""
        for i, succeed in enumerate(outcomes):
            clock.advance(step_s)
            with patch.object(client, "_get_provider") as mock_get:
                prov = MagicMock()
                if succeed:
                    prov.generate.return_value = _ok_response()
                else:
                    prov.generate.side_effect = ConnectionError(
                        "connection reset by peer")
                mock_get.return_value = prov
                if succeed:
                    client.generate(f"prompt {i}")
                else:
                    with pytest.raises(RuntimeError, match="models failed"):
                        client.generate(f"prompt {i}")

    def test_sustained_half_failure_stream_trips_and_drains(
            self, tmp_path: Path):
        from core.llm.telemetry import TelemetrySink, set_sink
        sink_path = tmp_path / "llm-telemetry.jsonl"
        set_sink(TelemetrySink(sink_path))
        try:
            clock = FakeClock()
            breaker = self._install(clock)
            client = _client()
            # 50% of provider attempts failing, sustained well past
            # the sustain span — the brown-out shape.
            self._drive(client, clock, [True, False] * 5)
            assert breaker.tripped

            # Every NEW dispatch refuses with the typed terminal error
            # (the provider is never even consulted — drain semantics).
            with patch.object(client, "_get_provider") as mock_get, \
                    pytest.raises(LLMDegradedModeError) as exc_info:
                client.generate("post-trip prompt")
            assert mock_get.call_count == 0
            assert is_budget_exceeded_error(exc_info.value)

            # Spend evidence persisted: the per-attempt records and
            # the trip verdict are in the run's telemetry JSONL.
            records = [
                json.loads(line)
                for line in sink_path.read_text().splitlines()
            ]
            trip = [r for r in records if r.get("event") == "breaker_tripped"]
            assert len(trip) == 1
            assert trip[0]["failed"] == 5
            assert trip[0]["samples"] == 10
            assert trip[0]["dominant"] == "retryable"
            failed = [
                r for r in records if r.get("event") == "attempt_failed"
            ]
            assert len(failed) == 5
        finally:
            set_sink(None)

    def test_structured_entry_also_refuses_after_trip(self):
        clock = FakeClock()
        breaker = self._install(clock)
        client = _client()
        self._drive(client, clock, [False] * 10)
        assert breaker.tripped
        with pytest.raises(LLMDegradedModeError):
            client.generate_structured("post-trip", {"type": "object"})

    def test_short_blip_does_not_trip(self):
        clock = FakeClock()
        breaker = self._install(clock, sustain_s=60.0)
        client = _client()
        # A burst of failures within seconds, then recovery.
        self._drive(client, clock, [False] * 10, step_s=1.0)
        self._drive(client, clock, [True] * 5, step_s=1.0)
        assert not breaker.tripped
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.return_value = _ok_response()
            mock_get.return_value = prov
            assert client.generate("healthy again").content == "fine"

    def test_low_volume_run_never_trips(self):
        clock = FakeClock()
        breaker = self._install(clock, min_samples=10)
        client = _client()
        self._drive(client, clock, [False] * 6)  # 100% failed, n=6
        assert not breaker.tripped

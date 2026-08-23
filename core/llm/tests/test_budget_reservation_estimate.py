"""Reservation-based budgeting — per-call-class estimates.

The pre-fix reservation was a flat $0.10: with 4 workers and $3-5
review calls in flight, every dispatcher passed the cap check and the
run overshot a $25 cap by 47%. The reservation is now sized from the
call class's observed cost history (local client history first, run
telemetry second, conservative constant last), so a dispatch only
proceeds while spent + reserved + estimate fits under the cap and
overshoot is bounded by the estimate error, not workers × call cost.

No real LLM calls — providers are stubbed.
"""

from __future__ import annotations

import threading
import time

import pytest

from core.llm import telemetry as llm_telemetry
from core.llm.client import (
    _BUDGET_RESERVATION,
    _DEFAULT_CALL_COST_ESTIMATE,
    _RESERVATION_CAP_FRACTION,
    LLMBudgetExceededError,
    LLMClient,
)
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse


class _StubProvider:
    """Fixed-cost provider with an optional in-flight delay."""

    def __init__(self, cost: float = 4.0, delay_s: float = 0.0):
        self.cost = cost
        self.delay_s = delay_s
        self.calls = 0
        self._lock = threading.Lock()

    def generate(self, prompt, system_prompt=None, **kwargs):
        with self._lock:
            self.calls += 1
        if self.delay_s:
            time.sleep(self.delay_s)
        return LLMResponse(
            content="ok",
            model="reservation-stub",
            provider="anthropic",
            tokens_used=10,
            cost=self.cost,
            finish_reason="complete",
        )


def _client(*, cap: float, cost: float = 4.0, delay_s: float = 0.0,
            tracking: bool = True):
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="reservation-stub", api_key="k",
        ),
        enable_caching=False,
        enable_fallback=False,
        enable_cost_tracking=tracking,
        max_cost_per_scan=cap,
        max_retries=1,
    )
    client = LLMClient(config)
    provider = _StubProvider(cost=cost, delay_s=delay_s)
    client._get_provider = lambda model_config: provider
    return client, provider


@pytest.fixture(autouse=True)
def _no_telemetry_sink():
    """Isolate each test from any process-wide sink."""
    prior = llm_telemetry.current_sink()
    llm_telemetry.set_sink(None)
    yield
    llm_telemetry.set_sink(prior)


class TestEstimate:
    def test_default_is_conservative_constant(self):
        client, _ = _client(cap=100.0)
        assert client._estimate_call_cost("review") == pytest.approx(
            _DEFAULT_CALL_COST_ESTIMATE,
        )

    def test_local_history_takes_over(self):
        client, _ = _client(cap=100.0)
        client._note_call_cost("review", 3.0)
        client._note_call_cost("review", 5.0)
        assert client._estimate_call_cost("review") == pytest.approx(4.0)

    def test_history_is_per_class(self):
        client, _ = _client(cap=100.0)
        client._note_call_cost("review", 4.0)
        # Unseen class still gets the conservative default.
        assert client._estimate_call_cost("summary") == pytest.approx(
            _DEFAULT_CALL_COST_ESTIMATE,
        )

    def test_telemetry_sink_seeds_unseen_class(self, tmp_path):
        sink = llm_telemetry.TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "call", "disposition": "ok",
                     "call_class": "review", "cost_usd": 3.0})
        sink.record({"event": "call", "disposition": "ok",
                     "call_class": "review", "cost_usd": 5.0})
        llm_telemetry.set_sink(sink)
        client, _ = _client(cap=100.0)
        assert client._estimate_call_cost("review") == pytest.approx(4.0)

    def test_local_history_beats_telemetry(self, tmp_path):
        sink = llm_telemetry.TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "call", "disposition": "ok",
                     "call_class": "review", "cost_usd": 9.0})
        llm_telemetry.set_sink(sink)
        client, _ = _client(cap=100.0)
        client._note_call_cost("review", 2.0)
        assert client._estimate_call_cost("review") == pytest.approx(2.0)

    def test_estimate_clamped_to_cap_fraction(self):
        # A conservative default must not brick a sub-dollar-cap run.
        client, _ = _client(cap=1.0)
        est = client._estimate_call_cost("review")
        assert est == pytest.approx(
            max(_BUDGET_RESERVATION, 1.0 * _RESERVATION_CAP_FRACTION),
        )

    def test_history_estimate_clamped_below_cap(self):
        # Evidence-based estimates keep their size (unlike the
        # uncertain default) but still leave a fresh client able to
        # admit its first call.
        client, _ = _client(cap=1.0)
        client._note_call_cost("review", 4.0)
        assert client._estimate_call_cost("review") == pytest.approx(0.95)

    def test_estimate_floored(self):
        client, _ = _client(cap=100.0)
        client._note_call_cost("cheap", 0.001)
        assert client._estimate_call_cost("cheap") == pytest.approx(
            _BUDGET_RESERVATION,
        )

    def test_tracking_disabled_returns_zero(self):
        client, _ = _client(cap=1.0, tracking=False)
        assert client._estimate_call_cost("review") == 0.0

    def test_cache_hits_do_not_skew_telemetry_mean(self, tmp_path):
        sink = llm_telemetry.TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "call", "disposition": "ok",
                     "call_class": "review", "cost_usd": 4.0})
        sink.record({"event": "call", "disposition": "cache_hit",
                     "call_class": "review", "cost_usd": 0.0})
        assert sink.mean_call_cost("review") == pytest.approx(4.0)

    def test_failed_attempts_do_not_skew_telemetry_mean(self, tmp_path):
        sink = llm_telemetry.TelemetrySink(tmp_path / "t.jsonl")
        sink.record({"event": "call", "disposition": "ok",
                     "call_class": "review", "cost_usd": 4.0})
        sink.record({"event": "attempt_failed", "disposition": "timeout",
                     "call_class": "review"})
        assert sink.mean_call_cost("review") == pytest.approx(4.0)


class TestReservationDispatch:
    def test_true_up_on_success(self):
        # After completion the ledger holds the ACTUAL cost, not the
        # estimate — the reservation was released and trued-up.
        client, _ = _client(cap=100.0, cost=4.0)
        client._note_call_cost("stress", 4.0)
        client.generate("p1", call_class="stress")
        assert client.total_cost == pytest.approx(4.0)

    def test_release_on_failure(self):
        client, provider = _client(cap=100.0)

        def _boom(prompt, system_prompt=None, **kwargs):
            raise ValueError("provider down")

        provider.generate = _boom
        with pytest.raises(RuntimeError):
            client.generate("p1", call_class="stress")
        # Reservation fully released — no stranded pre-debit.
        assert client.total_cost == pytest.approx(0.0)

    def test_dispatch_refused_when_estimate_would_breach(self):
        # spent + reserved + estimate must fit under the cap.
        client, _ = _client(cap=10.0, cost=4.0)
        client._note_call_cost("stress", 4.0)
        client.generate("p1", call_class="stress")   # $4
        client.generate("p2", call_class="stress")   # $8
        with pytest.raises(LLMBudgetExceededError):
            client.generate("p3", call_class="stress")  # 8 + 4 > 10
        assert client.total_cost == pytest.approx(8.0)

    def test_concurrent_dispatch_no_overshoot(self):
        # 8 workers race $4 calls against a $25 cap with an accurate
        # class estimate. Pre-fix ($0.10 flat reservation) all eight
        # passed the check → $32 spent (28% overshoot). Post-fix only
        # the dispatches whose reservation fits proceed: 6 × $4 = $24.
        client, provider = _client(cap=25.0, cost=4.0, delay_s=0.15)
        for _ in range(3):
            client._note_call_cost("stress", 4.0)

        barrier = threading.Barrier(8)
        outcomes: list[str] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            barrier.wait()
            try:
                client.generate(f"prompt-{i}", call_class="stress")
                res = "ok"
            except LLMBudgetExceededError:
                res = "budget"
            except RuntimeError as exc:
                res = "budget" if "budget exceeded" in str(exc).lower() else "error"
            with lock:
                outcomes.append(res)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert outcomes.count("ok") == 6, outcomes
        assert outcomes.count("budget") == 2, outcomes
        assert provider.calls == 6
        # No overshoot at all with an accurate estimate.
        assert client.total_cost == pytest.approx(24.0)
        assert client.total_cost <= client.config.max_cost_per_scan

    def test_concurrent_overshoot_bounded_by_estimate_error(self):
        # Estimate says $4, calls actually cost $5. Overshoot is
        # bounded by the aggregate estimate error of the admitted
        # in-flight calls — NOT workers × call cost. With cap $25 and
        # 6 admitted calls: spend = $30 = cap + 6 × $1 error, far
        # below the pre-fix ceiling of 8 × $5 = $40.
        client, _provider = _client(cap=25.0, cost=5.0, delay_s=0.15)
        for _ in range(3):
            client._note_call_cost("stress", 4.0)

        barrier = threading.Barrier(8)
        results: list[str] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            barrier.wait()
            try:
                client.generate(f"prompt-{i}", call_class="stress")
                res = "ok"
            except RuntimeError:
                res = "refused"
            with lock:
                results.append(res)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        admitted = results.count("ok")
        cap = client.config.max_cost_per_scan
        per_call_error = 5.0 - 4.0
        assert client.total_cost <= cap + admitted * per_call_error + 1e-9
        # Sanity: dramatically under the unreserved worst case.
        assert client.total_cost < 8 * 5.0

    def test_sequential_history_learns_from_run(self):
        # First call of a class reserves the default; later calls
        # reserve the observed mean.
        client, _ = _client(cap=100.0, cost=0.5)
        assert client._estimate_call_cost("stress") == pytest.approx(
            _DEFAULT_CALL_COST_ESTIMATE,
        )
        client.generate("p1", call_class="stress")
        assert client._estimate_call_cost("stress") == pytest.approx(0.5)

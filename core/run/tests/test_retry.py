"""Tests for core.run.retry — explicit-policy retry loops.

Pins the consolidated engine behaviours the hand-rolled copies relied
on: exponential and explicit schedules, non-retryable exceptions
propagating IMMEDIATELY (the blind except-Exception copies burned the
whole budget on hard failures), Retry-After-style delay overrides,
result-predicate retries returning the last result on exhaustion, and
last-exception re-raise on exhaustion.
"""

from __future__ import annotations

import pytest

from core.run.retry import RetryPolicy, retry_call


class _Transient(Exception):
    pass


class _Hard(Exception):
    pass


def _policy(**kw):
    defaults = {
        "attempts": 3,
        "retryable": lambda e: isinstance(e, _Transient),
        "base_delay": 1.0,
        "multiplier": 2.0,
    }
    defaults.update(kw)
    return RetryPolicy(**defaults)


class TestDelaySchedule:
    def test_exponential(self):
        p = _policy(base_delay=1.0, multiplier=2.0)
        assert [p.delay_for(i) for i in range(4)] == [1.0, 2.0, 4.0, 8.0]

    def test_max_delay_caps_exponential(self):
        p = _policy(base_delay=1.0, multiplier=10.0, max_delay=5.0)
        assert [p.delay_for(i) for i in range(3)] == [1.0, 5.0, 5.0]

    def test_explicit_schedule_wins_and_clamps(self):
        p = _policy(delays=(0.5, 1.0))
        assert [p.delay_for(i) for i in range(4)] == [0.5, 1.0, 1.0, 1.0]

    def test_empty_schedule_means_no_sleep(self):
        p = _policy(delays=())
        assert p.delay_for(0) == 0.0


class TestRetryCall:
    def test_success_first_try_no_sleep(self):
        sleeps: list[float] = []
        out = retry_call(lambda: "ok", policy=_policy(), sleep=sleeps.append)
        assert out == "ok"
        assert sleeps == []

    def test_transient_then_success(self):
        sleeps: list[float] = []
        calls = iter([_Transient(), _Transient(), "ok"])

        def fn():
            item = next(calls)
            if isinstance(item, Exception):
                raise item
            return item

        assert retry_call(fn, policy=_policy(), sleep=sleeps.append) == "ok"
        assert sleeps == [1.0, 2.0]

    def test_non_retryable_propagates_immediately(self):
        # The drift this module exists to end: blind except-Exception
        # loops retried hard failures. A rejected exception must
        # surface on attempt 1.
        attempts = []

        def fn():
            attempts.append(1)
            raise _Hard("auth")

        with pytest.raises(_Hard):
            retry_call(fn, policy=_policy(), sleep=lambda _s: None)
        assert len(attempts) == 1

    def test_exhaustion_reraises_last_exception(self):
        n = []

        def fn():
            n.append(1)
            raise _Transient(len(n))

        with pytest.raises(_Transient) as exc_info:
            retry_call(fn, policy=_policy(attempts=3), sleep=lambda _s: None)
        assert len(n) == 3
        assert exc_info.value.args == (3,)

    def test_attempts_below_one_rejected(self):
        with pytest.raises(ValueError):
            retry_call(lambda: 1, policy=_policy(attempts=0))

    def test_delay_override_honoured_for_exceptions(self):
        # Retry-After semantics: the override sees the scheduled delay
        # and may replace it (max(retry_after, scheduled) at the NVD
        # call site).
        sleeps: list[float] = []
        calls = iter([_Transient(), "ok"])

        def fn():
            item = next(calls)
            if isinstance(item, Exception):
                raise item
            return item

        retry_call(
            fn, policy=_policy(),
            delay_override=lambda exc, scheduled: max(30.0, scheduled),
            sleep=sleeps.append,
        )
        assert sleeps == [30.0]

    def test_retry_result_retries_then_returns(self):
        sleeps: list[float] = []
        results = iter([503, 503, 200])
        out = retry_call(
            lambda: next(results), policy=_policy(),
            retry_result=lambda r: r >= 500,
            sleep=sleeps.append,
        )
        assert out == 200
        assert sleeps == [1.0, 2.0]

    def test_retry_result_exhaustion_returns_last_result(self):
        # Result-retry exhaustion hands back the final value — soft-
        # fail callers inspect it (the NVD client turns it into None).
        out = retry_call(
            lambda: 503, policy=_policy(attempts=2),
            retry_result=lambda r: r >= 500,
            sleep=lambda _s: None,
        )
        assert out == 503

    def test_result_retries_do_not_get_delay_override(self):
        sleeps: list[float] = []
        results = iter([503, 200])
        retry_call(
            lambda: next(results), policy=_policy(),
            retry_result=lambda r: r >= 500,
            delay_override=lambda exc, scheduled: 99.0,
            sleep=sleeps.append,
        )
        assert sleeps == [1.0]

    def test_on_retry_hook(self):
        seen: list[tuple] = []
        calls = iter([_Transient(), "ok"])

        def fn():
            item = next(calls)
            if isinstance(item, Exception):
                raise item
            return item

        retry_call(
            fn, policy=_policy(),
            on_retry=lambda i, exc, delay: seen.append((i, type(exc), delay)),
            sleep=lambda _s: None,
        )
        assert seen == [(0, _Transient, 1.0)]

    def test_zero_delay_skips_sleep(self):
        sleeps: list[float] = []
        calls = iter([_Transient(), "ok"])

        def fn():
            item = next(calls)
            if isinstance(item, Exception):
                raise item
            return item

        retry_call(
            fn, policy=_policy(base_delay=0.0), sleep=sleeps.append)
        assert sleeps == []

    def test_default_sleep_is_looked_up_at_call_time(self, monkeypatch):
        # Consumers' test suites patch time.sleep globally; the
        # default must honour that (no early binding).
        recorded: list[float] = []
        monkeypatch.setattr("time.sleep", recorded.append)
        calls = iter([_Transient(), "ok"])

        def fn():
            item = next(calls)
            if isinstance(item, Exception):
                raise item
            return item

        retry_call(fn, policy=_policy())
        assert recorded == [1.0]

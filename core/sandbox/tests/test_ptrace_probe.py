"""Tests for core.sandbox.ptrace_probe — environment-detection probe.

The probe forks a sentinel child that calls PTRACE_TRACEME and SIGSTOPs
itself; the parent attempts PTRACE_CONT. Tests cover:
- The probe returns SOMETHING coherent on the test host (without hard-
  coding True or False, since CI environments vary).
- The cache layer prevents duplicate probes within a process.
- The degradation warning fires once-per-process when ptrace is blocked.
- Cleanup: probe failures don't leave zombie children.

We deliberately don't assert "ptrace IS available" — the test environment
may not permit it (Yama scope 3, container without SYS_PTRACE, etc.).
What we assert is correctness of the probe's behaviour given whatever
the kernel reports.
"""

import logging
import os

import pytest

from core.sandbox import ptrace_probe
from core.sandbox import state


@pytest.fixture(autouse=True)
def reset_probe_cache():
    """Each test starts with no cached probe result.

    The autouse conftest fixture restores the cache at TEST END, but
    we also need it cleared at TEST START — multiple probes within a
    test should observe a consistent starting point.
    """
    state._ptrace_available_cache = None
    state._ptrace_unavailable_warned = False
    yield


class TestProbeReturnsBoolean:
    def test_returns_bool(self):
        result = ptrace_probe.check_ptrace_available()
        assert isinstance(result, bool), \
            f"probe returned {type(result).__name__}, expected bool"

    def test_does_not_raise_on_repeated_call(self):
        # Pin the contract: probe is safe to call repeatedly without
        # explosions, even if the underlying syscall sequence fails.
        for _ in range(5):
            ptrace_probe.check_ptrace_available()


class TestProbeCache:
    def test_caches_result_after_first_call(self):
        result_1 = ptrace_probe.check_ptrace_available()
        # The cache attribute should be populated to whatever was returned.
        cached = state._ptrace_available_cache
        assert cached is result_1
        assert cached is not None

    def test_subsequent_calls_use_cache(self, monkeypatch):
        # First call populates the cache.
        first = ptrace_probe.check_ptrace_available()
        # Counter-pattern detection (NOT exception-based): the H1
        # try/except in check_ptrace_available catches Exception, so a
        # raised AssertionError would be silently swallowed and the
        # cache-broken case would fail with a less-informative
        # `assert second is first` rather than the original assertion.
        # Counting invocations is direct and immune to that masking.
        call_count = [0]
        def counting_probe():
            call_count[0] += 1
            return False
        monkeypatch.setattr(ptrace_probe, "_run_probe", counting_probe)
        # Subsequent call: cache hit, no re-probe.
        second = ptrace_probe.check_ptrace_available()
        assert second is first
        assert call_count[0] == 0, (
            f"cache not honoured — _run_probe ran {call_count[0]} times"
        )

    def test_explicit_cache_invalidation_re_probes(self, monkeypatch):
        # Set the cache to a known value.
        state._ptrace_available_cache = False
        # Patch _run_probe so we can detect re-probes.
        called = []
        def fake_probe():
            called.append(True)
            return True
        monkeypatch.setattr(ptrace_probe, "_run_probe", fake_probe)

        # Cache hit: no re-probe.
        assert ptrace_probe.check_ptrace_available() is False
        assert called == []

        # Invalidate, re-probe.
        state._ptrace_available_cache = None
        assert ptrace_probe.check_ptrace_available() is True
        assert called == [True]


class TestProbeWarning:
    def test_warning_fires_when_unavailable(self, monkeypatch, caplog):
        # Force the probe to report unavailable.
        monkeypatch.setattr(ptrace_probe, "_run_probe", lambda: False)

        with caplog.at_level(logging.WARNING, logger="core.sandbox.ptrace_probe"):
            result = ptrace_probe.check_ptrace_available()

        assert result is False
        warning_messages = [r.message for r in caplog.records
                            if r.levelno == logging.WARNING]
        assert any("ptrace unavailable" in m for m in warning_messages), (
            f"expected ptrace-unavailable warning, got: {warning_messages}"
        )
        # Helpful workaround pointers should appear so operators know
        # what to do.
        joined = "\n".join(warning_messages)
        assert "Yama" in joined or "yama" in joined
        assert "kernel.yama.ptrace_scope" in joined

    def test_warning_fires_only_once_per_process(self, monkeypatch, caplog):
        monkeypatch.setattr(ptrace_probe, "_run_probe", lambda: False)

        with caplog.at_level(logging.WARNING, logger="core.sandbox.ptrace_probe"):
            ptrace_probe.check_ptrace_available()
            # Invalidate cache so the probe runs again — should still
            # not re-log the warning thanks to warn_once.
            state._ptrace_available_cache = None
            ptrace_probe.check_ptrace_available()

        warning_count = sum(
            1 for r in caplog.records
            if r.levelno == logging.WARNING and "ptrace unavailable" in r.message
        )
        assert warning_count == 1, (
            f"expected exactly 1 ptrace-unavailable warning, got {warning_count}"
        )

    def test_no_warning_when_available(self, monkeypatch, caplog):
        monkeypatch.setattr(ptrace_probe, "_run_probe", lambda: True)

        with caplog.at_level(logging.WARNING, logger="core.sandbox.ptrace_probe"):
            ptrace_probe.check_ptrace_available()

        unavailable_warnings = [r for r in caplog.records
                                if r.levelno == logging.WARNING
                                and "ptrace unavailable" in r.message]
        assert unavailable_warnings == [], (
            f"unexpected unavailable warning when probe succeeded: "
            f"{[r.message for r in unavailable_warnings]}"
        )


class TestEintrSafe:
    """G1 regression: a transient signal during the probe must not be
    misinterpreted as 'ptrace unavailable'. The waitpid call retries on
    EINTR rather than failing through to the False-return path."""

    def test_waitpid_retries_on_interrupted_error(self, monkeypatch):
        # Simulate one EINTR (raised by InterruptedError, which is what
        # Python translates EINTR into) followed by a successful return.
        call_count = [0]
        sentinel_status = (12345, 0x137f)  # WIFSTOPPED-shaped status

        def fake_waitpid(pid, options):
            call_count[0] += 1
            if call_count[0] == 1:
                raise InterruptedError("simulated EINTR from unrelated signal")
            return sentinel_status

        monkeypatch.setattr(os, "waitpid", fake_waitpid)

        result = ptrace_probe._waitpid_eintr_safe(12345, 0)
        assert result == sentinel_status
        assert call_count[0] == 2, \
            f"expected 1 EINTR retry + 1 success, got {call_count[0]} calls"

    def test_waitpid_propagates_non_eintr_oserror(self, monkeypatch):
        # ECHILD / EINVAL / etc. must propagate; only EINTR is retried.
        def fake_waitpid(pid, options):
            raise ChildProcessError("ECHILD: no child")

        monkeypatch.setattr(os, "waitpid", fake_waitpid)

        with pytest.raises(ChildProcessError):
            ptrace_probe._waitpid_eintr_safe(12345, 0)


class TestProbeNeverRaises:
    """H1 regression: a future change that introduces an unexpected
    raise in _run_probe must not crash sandbox setup. The public API
    must always return a bool, even when the internals misbehave."""

    def test_run_probe_raising_routes_to_false(self, monkeypatch):
        def boom():
            raise RuntimeError("simulated future bug in _run_probe")
        monkeypatch.setattr(ptrace_probe, "_run_probe", boom)

        # Must not propagate; cache is set to False.
        result = ptrace_probe.check_ptrace_available()
        assert result is False
        assert state._ptrace_available_cache is False


class TestProbeNoZombies:
    """Probe failure paths must not leak child processes."""

    def test_no_zombies_after_repeated_probes(self, monkeypatch):
        # Force-fail every probe via the libc-missing path so we exercise
        # the fast-failure branch without requiring fork to fail.
        monkeypatch.setattr(ptrace_probe, "_get_libc", lambda: None)

        before = _count_children()
        for _ in range(5):
            state._ptrace_available_cache = None  # invalidate to re-probe
            ptrace_probe.check_ptrace_available()
        after = _count_children()
        # Allow one transient — a previous probe may still be reaping.
        assert after - before <= 1, (
            f"probe leaked children: before={before}, after={after}"
        )

    def test_real_probe_does_not_leak_children(self):
        # Use the real probe — whether it returns True or False, no
        # zombies should remain.
        before = _count_children()
        ptrace_probe.check_ptrace_available()
        after = _count_children()
        # Same one-transient tolerance.
        assert after - before <= 1, (
            f"real probe leaked children: before={before}, after={after}"
        )


def _count_children() -> int:
    """Count this process's child PIDs via /proc/self/task/*/children.

    Linux-specific. Used to detect probe-induced child leaks. Skips the
    test (rather than returning 0) on systems without /proc/self/task,
    so a future-test-environment regression that breaks the interface
    doesn't silently mask leak-detection.
    """
    if not os.path.isdir("/proc/self/task"):
        pytest.skip(
            "/proc/self/task not available — cannot detect probe child leaks"
        )
    total = 0
    try:
        for tid in os.listdir("/proc/self/task"):
            try:
                with open(f"/proc/self/task/{tid}/children") as f:
                    pids = f.read().split()
                    total += len(pids)
            except (FileNotFoundError, PermissionError):
                continue
    except (FileNotFoundError, PermissionError):
        pytest.skip(
            "/proc/self/task became unreadable — cannot detect leaks"
        )
    return total

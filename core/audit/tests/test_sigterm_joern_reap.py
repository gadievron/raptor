"""Forced-exit Joern reap hook registration and invocation.

run_orchestrator's ``finally`` stops the run's Joern server, but the
FORCED-exit paths (SIGTERM-grace watchdog expiry, second TERM) run
only ``_sigterm_flush_hooks`` before ``os._exit`` — so a run-private
server needs an entry there, and ONLY the run-private one: killing a
lifecycle-recorded or caller-owned server on forced exit is cross-run
collateral.

Unit layer only — the hook decision and the flush-hook plumbing are
driven directly with fake server handles (no JVM, no signals).
"""

from __future__ import annotations

import signal

import pytest

import core.audit.orchestrator as orch


@pytest.fixture(autouse=True)
def _reset_term_state():
    """Never leak TERM/shutdown/hook state into other tests."""
    yield
    orch._sigterm_event.clear()
    orch._shutdown_event.clear()
    orch._sigterm_state["count"] = 0
    orch._sigterm_flush_hooks.clear()


class _FakeServer:
    """Shape of a run-private JoernServer handle."""

    def __init__(self, *, proc: object | None = object(),
                 token: str | None = None) -> None:
        self._proc = proc
        self._lifecycle_token = token
        self.stop_fast_calls = 0

    def stop_fast(self) -> bool:
        self.stop_fast_calls += 1
        return True


class TestRegistration:
    def test_run_private_registers(self):
        srv = _FakeServer()
        assert orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        ) is True
        assert len(orch._sigterm_flush_hooks) == 1

    def test_caller_owned_refused(self):
        srv = _FakeServer()
        assert orch._register_private_joern_reap_hook(
            srv, caller_owns=True, lifecycle_shared=False,
        ) is False
        assert orch._sigterm_flush_hooks == []

    def test_lifecycle_reuse_handle_refused(self):
        # Reuse handle: no owned process (connect_existing).
        srv = _FakeServer(proc=None)
        assert orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=True,
        ) is False
        assert orch._sigterm_flush_hooks == []

    def test_lifecycle_fresh_server_refused(self):
        # Freshly acquired via the lifecycle: owns a process BUT is
        # recorded in the state file (token set) — later runs can
        # re-acquire it warm and a concurrent session may hold a
        # reference, so forced exit must not kill it.
        srv = _FakeServer(token="abc123")
        assert orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        ) is False
        assert orch._sigterm_flush_hooks == []

    def test_no_server_refused(self):
        assert orch._register_private_joern_reap_hook(
            None, caller_owns=False, lifecycle_shared=False,
        ) is False
        assert orch._sigterm_flush_hooks == []


class TestInvocation:
    def test_flush_hooks_invoke_stop_fast(self):
        srv = _FakeServer()
        orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        )
        orch._run_sigterm_flush_hooks()
        assert srv.stop_fast_calls == 1

    def test_watchdog_expiry_reaps_then_exits(self, monkeypatch):
        exits: list[int] = []
        monkeypatch.setattr(orch.os, "_exit", lambda c: exits.append(c))
        srv = _FakeServer()
        orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        )
        orch._sigterm_watchdog(0.0)
        assert exits == [130]
        assert srv.stop_fast_calls == 1

    def test_second_term_reaps_then_exits(self, monkeypatch):
        exits: list[int] = []
        monkeypatch.setattr(orch.os, "_exit", lambda c: exits.append(c))
        monkeypatch.setattr(
            orch._threading, "Thread",
            lambda **kw: type("T", (), {"start": lambda self: None})(),
        )
        srv = _FakeServer()
        orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        )
        orch._handle_sigterm(signal.SIGTERM, None)
        assert exits == []
        orch._handle_sigterm(signal.SIGTERM, None)
        assert exits == [130]
        assert srv.stop_fast_calls == 1

    def test_hook_exception_never_escapes(self):
        class _Raising(_FakeServer):
            def stop_fast(self) -> bool:
                raise RuntimeError("teardown blew up")

        orch._register_private_joern_reap_hook(
            _Raising(), caller_owns=False, lifecycle_shared=False,
        )
        orch._run_sigterm_flush_hooks()  # must not raise

    def test_graceful_clear_disarms_the_hook(self):
        # The graceful finally clears the registry before its normal
        # stop — a later (stray) flush run must find nothing.
        srv = _FakeServer()
        orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        )
        orch._sigterm_flush_hooks.clear()
        orch._run_sigterm_flush_hooks()
        assert srv.stop_fast_calls == 0

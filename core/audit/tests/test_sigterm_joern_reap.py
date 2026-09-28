"""Forced-exit Joern reap hook registration and invocation.

run_orchestrator's ``finally`` stops the run's Joern server, but the
FORCED-exit paths (SIGTERM-grace watchdog expiry, second TERM) run
only ``_sigterm_flush_hooks`` before ``os._exit`` — so every server
whose forwarder ``Popen`` handle the run owns needs an entry there:
run-private servers AND fresh lifecycle-recorded ones. Reuse handles
and caller-owned servers stay refused (another owner's process).

Unit layer only — the hook decision and the flush-hook plumbing are
driven directly with fake server handles (no JVM, no signals).
"""

from __future__ import annotations

import logging
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
    """Shape of a run-started JoernServer handle."""

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

    def test_procless_server_refused_even_when_not_shared(self) -> None:
        # No owned Popen handle must refuse on its own — even when
        # the call-site's lifecycle_shared computation wrongly says
        # this handle is not shared, there is no process of ours to
        # signal.
        srv = _FakeServer(proc=None)
        assert orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        ) is False
        assert orch._sigterm_flush_hooks == []

    def test_lifecycle_fresh_server_registers(self):
        # Freshly started via the lifecycle: recorded in the state
        # file (token set) but the forwarder Popen handle is OURS —
        # this run started the process, and the graceful finally
        # stops it, so forced exit must reap it too. Refusing this
        # class leaked one forwarder+JVM pair per SIGTERM-drained
        # segment (the drain normally concludes through the
        # watchdog, the only teardown of which is the hook registry).
        srv = _FakeServer(token="abc123")
        assert orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        ) is True
        assert len(orch._sigterm_flush_hooks) == 1
        orch._run_sigterm_flush_hooks()
        assert srv.stop_fast_calls == 1

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
        # The graceful finally clears the registry once its own
        # release is done — a later (stray) flush run must find
        # nothing.
        srv = _FakeServer()
        orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        )
        orch._sigterm_flush_hooks.clear()
        orch._run_sigterm_flush_hooks()
        assert srv.stop_fast_calls == 0


class TestTierAttribution:
    """The reap log names the supervision tier via the getattr
    contract: ``getattr(server, "_supervision_tier", "group")`` — the
    attribute does not exist on servers booted before the pidns
    supervision tier stamps it, and an unstamped server IS the group
    tier. The per-tier kill mechanics themselves live in the server's
    own stop machinery (stop_fast), never re-implemented here."""

    def test_unstamped_server_reaps_as_group_tier(self, caplog):
        srv = _FakeServer()  # no _supervision_tier attribute at all
        orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        )
        with caplog.at_level(logging.INFO, logger=orch.logger.name):
            orch._run_sigterm_flush_hooks()
        assert srv.stop_fast_calls == 1
        assert "supervision tier=group" in caplog.text

    def test_pidns_stamped_server_reaps_as_pidns_tier(self, caplog):
        srv = _FakeServer()
        srv._supervision_tier = "pidns"
        orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        )
        with caplog.at_level(logging.INFO, logger=orch.logger.name):
            orch._run_sigterm_flush_hooks()
        assert srv.stop_fast_calls == 1
        assert "supervision tier=pidns" in caplog.text


class TestBackstopWindow:
    """The reap hook is the UNGUARDED backstop beside the lock-guarded
    bounded release: when the watchdog's flush walk runs while the
    graceful release still holds the exactly-once lock, the guarded
    hook no-ops — the pair's only teardown in that window is this
    hook's ``stop_fast``."""

    def test_reap_fires_when_guarded_release_is_locked_out(self):
        import threading

        srv = _FakeServer(token="tok-fresh")
        release_guard = threading.Lock()
        release_ran: list[bool] = []

        def _guarded_release() -> None:
            # Same shape as run_orchestrator's _release_joern_for_exit:
            # non-blocking acquire, silent no-op when already held.
            if not release_guard.acquire(blocking=False):
                return
            release_ran.append(True)

        assert orch._register_private_joern_reap_hook(
            srv, caller_owns=False, lifecycle_shared=False,
        ) is True
        orch._sigterm_flush_hooks.append(_guarded_release)

        # Graceful teardown mid-flight: it owns the lock.
        release_guard.acquire()
        try:
            orch._run_sigterm_flush_hooks()
        finally:
            release_guard.release()

        assert release_ran == []          # the guarded hook no-oped
        assert srv.stop_fast_calls == 1   # the backstop still reaped

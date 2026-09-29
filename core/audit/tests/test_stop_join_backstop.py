"""Graceful-stop join-timeout backstop in stop_joern_server.

``stop_joern_server`` runs ``server.stop()`` on a daemon thread with
a bounded join. A stop that wedges (TERM-ignoring JVM, stuck
transport) used to be abandoned outright — on non-TERM runs nothing
else tears the pair down, so the JVM + forwarder leaked for the life
of the host. On join timeout the function now escalates to the
server's own ``stop_fast()`` — but ONLY for a server whose forwarder
``Popen`` handle this run owns; caller-owned servers,
lifecycle-shared servers, and reuse handles (``_proc is None``) are
another owner's processes and keep the abandon-with-warning
behaviour unchanged.

Unit layer only — the escalation decision is driven with fake server
handles (no JVM). One test spawns a real child process to prove the
escalation actually kills what the fake ``stop_fast`` owns; it kills
only the pid it spawned and verified alive.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import threading

import pytest

import core.audit.joern_backend as jb

_ABANDON_TEXT = "abandoning"
_ESCALATE_TEXT = "escalating to stop_fast"


@pytest.fixture(autouse=True)
def _short_grace(monkeypatch: pytest.MonkeyPatch):
    """Shrink the join grace for the tests only.

    The shipped 30s default is never changed — the constant is
    overridden per-test so a wedged fake stop() times out in
    milliseconds instead of half a minute. ``raising=False``: on a
    tree without the constant the join budget is hardcoded and the
    tests exercise the full 30s — slow but still behavioral.
    """
    monkeypatch.setattr(jb, "_STOP_JOIN_GRACE_S", 0.05, raising=False)
    yield


class _WedgedServer:
    """Run-started JoernServer shape whose stop() blocks past the grace."""

    def __init__(self, *, proc: object | None = object()) -> None:
        self._proc = proc
        self._release = threading.Event()
        self.stop_fast_calls = 0
        self.stop_returned = False

    def stop(self) -> None:
        # Wedge until the test releases us (daemon thread — a leaked
        # waiter cannot block interpreter exit). The bound comfortably
        # exceeds any join grace so the wedge never wins the race.
        self._release.wait(timeout=120)
        self.stop_returned = True

    def stop_fast(self) -> bool:
        self.stop_fast_calls += 1
        return True

    def release(self) -> None:
        self._release.set()


class _PromptServer(_WedgedServer):
    """Server whose stop() completes well inside the grace."""

    def stop(self) -> None:
        self.stop_returned = True


class TestEscalation:
    def test_owned_server_escalates_to_stop_fast(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        srv = _WedgedServer()
        try:
            with caplog.at_level(logging.WARNING, logger=jb.logger.name):
                jb.stop_joern_server(srv)
            assert srv.stop_fast_calls == 1
            assert _ESCALATE_TEXT in caplog.text
            assert "supervision tier=group" in caplog.text
            assert _ABANDON_TEXT not in caplog.text
        finally:
            srv.release()

    def test_pidns_stamped_tier_attributed(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        srv = _WedgedServer()
        srv._supervision_tier = "pidns"
        try:
            with caplog.at_level(logging.WARNING, logger=jb.logger.name):
                jb.stop_joern_server(srv)
            assert srv.stop_fast_calls == 1
            assert "supervision tier=pidns" in caplog.text
        finally:
            srv.release()

    def test_escalation_kills_the_real_owned_child(self) -> None:
        # stop_fast() here does what the real one does at its core:
        # kill a process THIS test spawned and verified alive.
        child = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", "import time; time.sleep(60)"],
        )

        class _ChildOwner(_WedgedServer):
            def stop_fast(self) -> bool:
                self.stop_fast_calls += 1
                if child.poll() is None:  # verified alive, our spawn
                    child.kill()
                child.wait(timeout=10)
                return True

        srv = _ChildOwner(proc=child)
        try:
            assert child.poll() is None  # alive before the stop
            jb.stop_joern_server(srv)
            assert srv.stop_fast_calls == 1
            assert child.poll() is not None  # escalation reaped it
        finally:
            srv.release()
            if child.poll() is None:  # never leak our own spawn
                child.kill()
                child.wait(timeout=10)

    def test_stop_fast_exception_never_escapes(self) -> None:
        class _Raising(_WedgedServer):
            def stop_fast(self) -> bool:
                raise RuntimeError("teardown blew up")

        srv = _Raising()
        try:
            jb.stop_joern_server(srv)  # must not raise
        finally:
            srv.release()

    def test_late_stop_completion_after_escalation_is_benign(
        self,
    ) -> None:
        # The wedged stop() may complete AFTER stop_fast fired (the
        # server contract makes the double-fire a no-op: no instance
        # state mutated, both entries early-return once _proc
        # clears). The call-site side of that contract: escalation
        # neither joins on nor cancels the still-running stop thread.
        srv = _WedgedServer()
        jb.stop_joern_server(srv)
        assert srv.stop_fast_calls == 1
        assert srv.stop_returned is False  # still wedged at return
        srv.release()
        deadline = threading.Event()
        deadline.wait(timeout=0.2)
        assert srv.stop_returned is True  # completed later, no error


class TestRefusal:
    """Refused classes keep abandon-with-warning, never stop_fast."""

    def _assert_abandoned(
        self, srv: _WedgedServer, caplog: pytest.LogCaptureFixture,
    ) -> None:
        assert srv.stop_fast_calls == 0
        assert _ABANDON_TEXT in caplog.text
        assert _ESCALATE_TEXT not in caplog.text

    def test_caller_owned_abandons_only(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        srv = _WedgedServer()
        try:
            with caplog.at_level(logging.WARNING, logger=jb.logger.name):
                jb.stop_joern_server(srv, caller_owns=True)
            self._assert_abandoned(srv, caplog)
        finally:
            srv.release()

    def test_lifecycle_shared_abandons_only(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        srv = _WedgedServer()
        try:
            with caplog.at_level(logging.WARNING, logger=jb.logger.name):
                jb.stop_joern_server(srv, lifecycle_shared=True)
            self._assert_abandoned(srv, caplog)
        finally:
            srv.release()

    def test_procless_reuse_handle_abandons_only(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Reuse handle (connect_existing): no owned process. Refused
        # via the independent _proc re-check — no flags needed.
        srv = _WedgedServer(proc=None)
        try:
            with caplog.at_level(logging.WARNING, logger=jb.logger.name):
                jb.stop_joern_server(srv)
            self._assert_abandoned(srv, caplog)
        finally:
            srv.release()

    def test_procless_even_when_flags_claim_owned(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        # The _proc is None re-check must refuse on its own, even
        # when the call site's flags wrongly say the handle is ours.
        srv = _WedgedServer(proc=None)
        try:
            with caplog.at_level(logging.WARNING, logger=jb.logger.name):
                jb.stop_joern_server(
                    srv, caller_owns=False, lifecycle_shared=False,
                )
            self._assert_abandoned(srv, caplog)
        finally:
            srv.release()


class TestNoEscalationNeeded:
    def test_prompt_stop_never_escalates(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        srv = _PromptServer()
        with caplog.at_level(logging.WARNING, logger=jb.logger.name):
            jb.stop_joern_server(srv)
        assert srv.stop_returned is True
        assert srv.stop_fast_calls == 0
        assert _ABANDON_TEXT not in caplog.text
        assert _ESCALATE_TEXT not in caplog.text

    def test_none_server_is_a_noop(self) -> None:
        jb.stop_joern_server(None)  # must not raise

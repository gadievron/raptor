"""Cancelled proxy construction must not leave a listener thread behind."""

import asyncio
import threading
from unittest.mock import Mock

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture(autouse=True)
def parser_stub(monkeypatch):
    monkeypatch.setattr(proxy_mod.parser_jail, "get_parser_jail", lambda: Mock())


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_thread_start_failure_preserves_original_error(monkeypatch, failure_type):
    proxy = object.__new__(proxy_mod.EgressProxy)
    failure = failure_type("thread start failed")
    thread = Mock()
    thread.start.side_effect = failure
    thread.join.side_effect = RuntimeError("cannot join unstarted thread")
    monkeypatch.setattr(proxy_mod.threading, "Thread", Mock(return_value=thread))
    with pytest.raises(failure_type) as raised:
        proxy.__init__([])
    assert raised.value is failure
    assert proxy._startup_cancelled.is_set()
    thread.join.assert_called_once_with(timeout=2.0)


def test_worker_starting_after_timeout_never_creates_a_loop(monkeypatch):
    deferred = []

    class DeferredThread:
        def __init__(self, target, **kwargs):
            self.target = target
            deferred.append(self)

        def start(self):
            pass

        def join(self, timeout):
            pass

    monkeypatch.setattr(proxy_mod.threading, "Thread", DeferredThread)
    monkeypatch.setattr(proxy_mod, "_PROXY_CONNECT_TIMEOUT_S", 0.01)
    proxy = object.__new__(proxy_mod.EgressProxy)
    with pytest.raises(RuntimeError, match="did not become ready"):
        proxy.__init__([])
    create = Mock(side_effect=AssertionError("cancelled worker must not bind"))
    monkeypatch.setattr(proxy_mod.asyncio, "new_event_loop", create)
    deferred[0].target()
    create.assert_not_called()
    assert proxy._loop is None


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_readiness_failure_cancels_pending_listener_creation(monkeypatch, failure_type):
    entered, cancelled = threading.Event(), threading.Event()
    failure = failure_type("readiness interrupted")
    proxy = object.__new__(proxy_mod.EgressProxy)

    async def stalled_bind(*args, **kwargs):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    real_start = threading.Thread.start

    def start(thread):
        real_start(thread)
        assert entered.wait(5)
        monkeypatch.setattr(proxy._ready, "wait", Mock(side_effect=failure))

    monkeypatch.setattr(proxy_mod.asyncio, "start_server", stalled_bind)
    monkeypatch.setattr(proxy_mod.threading.Thread, "start", start)
    try:
        with pytest.raises(failure_type) as raised:
            proxy.__init__([])
        assert raised.value is failure
        assert cancelled.is_set()
        assert not proxy._thread.is_alive()
        assert proxy._startup_task.cancelled()
        assert proxy._loop.is_closed()
    finally:
        if proxy._thread is not None and proxy._thread.is_alive():
            proxy._stop_thread_best_effort()


def test_listener_creation_error_is_reported_and_loop_closed(monkeypatch):
    proxy = object.__new__(proxy_mod.EgressProxy)
    failure = OSError("bind failed")

    async def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(proxy_mod.asyncio, "start_server", fail)
    with pytest.raises(RuntimeError, match="failed to start") as raised:
        proxy.__init__([])
    assert raised.value.__cause__ is failure
    assert not proxy._thread.is_alive()
    assert proxy._loop.is_closed()


def test_normal_start_and_stop_still_release_listener():
    proxy = proxy_mod.EgressProxy([])
    try:
        assert proxy.port > 0
        assert proxy.is_alive()
    finally:
        proxy.stop(drain_timeout=0)
    assert not proxy.is_alive()
    assert proxy._loop.is_closed()


def test_worker_resuming_after_cleanup_closes_new_loop_without_binding(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    proxy = object.__new__(proxy_mod.EgressProxy)
    created, joins = [], []
    failure = KeyboardInterrupt("cancel loop startup")
    real_new_loop = asyncio.new_event_loop
    real_start = threading.Thread.start

    def delayed_loop():
        loop = real_new_loop()
        created.append(loop)
        entered.set()
        assert release.wait(5)
        return loop

    def start(thread):
        real_start(thread)
        assert entered.wait(5)
        joins.append(thread.join)
        monkeypatch.setattr(thread, "join", lambda timeout: None)
        monkeypatch.setattr(proxy._ready, "wait", Mock(side_effect=failure))

    bind = Mock(side_effect=AssertionError("cancelled startup must not bind"))
    monkeypatch.setattr(proxy_mod.asyncio, "new_event_loop", delayed_loop)
    monkeypatch.setattr(proxy_mod.asyncio, "start_server", bind)
    monkeypatch.setattr(proxy_mod.threading.Thread, "start", start)
    try:
        with pytest.raises(KeyboardInterrupt) as raised:
            proxy.__init__([])
        assert raised.value is failure
        assert proxy._loop is None
        release.set()
        joins[0](5)
        assert not proxy._thread.is_alive()
        assert created[0].is_closed()
        bind.assert_not_called()
    finally:
        release.set()
        for join in joins:
            join(5)
        for loop in created:
            if not loop.is_closed():
                loop.close()

"""Rejected loop submissions must close the coroutine that was submitted."""

import asyncio
import inspect
import threading
from unittest.mock import AsyncMock, Mock

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import proxy as proxy_mod


def proxy_handle():
    proxy = object.__new__(proxy_mod.EgressProxy)
    proxy._loop = Mock()
    proxy._loop.is_running.return_value = True
    proxy._thread = None
    proxy._server = Mock()
    proxy._unix_lock = threading.Lock()
    proxy._lanes_lock = threading.Lock()
    proxy._unix_servers = {}
    proxy._unix_lanes = {}
    proxy._tcp_lane_servers = {}
    proxy._tcp_lanes = {}
    proxy._unix_tasks = set()
    proxy._client_tasks = set()
    proxy._summary_emitted = True
    proxy._stopping = False
    return proxy


@pytest.mark.parametrize("operation", [
    "bind_unix", "bind_tcp", "close_tcp", "unbind_unix", "stop_graceful", "stop_abrupt",
])
def test_loop_shutdown_race_closes_actual_coroutine(tmp_path, monkeypatch, operation):
    proxy = proxy_handle()
    path = str(tmp_path / "proxy.sock")
    failure = RuntimeError("event loop is closed")
    submitted = []

    def reject(coroutine, loop):
        submitted.append(coroutine)
        raise failure

    patch_module_attribute(monkeypatch, proxy_mod, "asyncio", "run_coroutine_threadsafe", reject)
    if operation == "bind_unix":
        with pytest.raises(RuntimeError) as raised:
            proxy.bind_unix(path)
        assert raised.value is failure
        assert proxy._unix_lanes == {}
        assert proxy._unix_servers == {}
    elif operation == "bind_tcp":
        with pytest.raises(RuntimeError) as raised:
            proxy.bind_tcp_lane()
        assert raised.value is failure
    elif operation == "close_tcp":
        proxy._tcp_lane_servers[1234] = Mock()
        proxy._tcp_lanes[1234] = object()
        proxy.close_tcp_lane(1234)
    elif operation == "unbind_unix":
        proxy._unix_servers[path] = Mock()
        proxy._unix_lanes[path] = object()
        proxy.unbind_unix(path)
    else:
        proxy.stop(drain_timeout=1 if operation == "stop_graceful" else 0)
    assert len(submitted) == 1
    assert inspect.getcoroutinestate(submitted[0]) == inspect.CORO_CLOSED


def test_real_closed_loop_preserves_runtime_error_and_closes_coroutine():
    loop = asyncio.new_event_loop()
    loop.close()

    async def work():
        return 7

    coroutine = work()
    with pytest.raises(RuntimeError, match="closed"):
        proxy_mod._submit_to_loop(coroutine, loop)
    assert inspect.getcoroutinestate(coroutine) == inspect.CORO_CLOSED


def test_successful_submission_still_executes():
    loop = asyncio.new_event_loop()

    async def work():
        return 7

    try:
        future = proxy_mod._submit_to_loop(work(), loop)
        loop.run_until_complete(asyncio.sleep(0))
        assert future.result(timeout=1) == 7
    finally:
        loop.close()


def test_failed_unix_bind_keeps_existing_lane(tmp_path, monkeypatch):
    proxy = proxy_handle()
    path = str(tmp_path / "existing.sock")
    existing = object()
    proxy._unix_lanes[path] = existing
    proxy._unix_servers[path] = Mock()
    patch_module_attribute(monkeypatch, proxy_mod, "asyncio", "run_coroutine_threadsafe", Mock(side_effect=RuntimeError("loop closed")))
    with pytest.raises(RuntimeError):
        proxy.bind_unix(path)
    assert proxy._unix_lanes[path] is existing



@pytest.mark.parametrize("fails", [False, True])
def test_unix_lane_is_published_only_after_successful_bind(tmp_path, monkeypatch, fails):
    proxy = proxy_handle()
    path = str(tmp_path / "proxy.sock")
    server = Mock()
    binding = AsyncMock(side_effect=OSError("bind failed")) if fails else AsyncMock(return_value=server)

    def submit(coroutine, loop):
        future = Mock()

        def result(timeout):
            # Execute on result(), as a completed cross-thread operation:
            # coroutine failures belong to the future, not submission.
            return asyncio.run(coroutine)

        future.result.side_effect = result
        return future

    patch_module_attribute(monkeypatch, proxy_mod, "asyncio", "run_coroutine_threadsafe", submit)
    patch_module_attribute(monkeypatch, proxy_mod, "asyncio", "start_unix_server", binding)
    if fails:
        with pytest.raises(OSError, match="bind failed"):
            proxy.bind_unix(path)
        assert proxy._unix_lanes == {}
        assert proxy._unix_servers == {}
    else:
        proxy.bind_unix(path)
        assert path in proxy._unix_lanes
        assert proxy._unix_servers[path] is server

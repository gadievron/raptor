"""The private proxy loop retires accepted sockets and asynchronous cleanup."""

import asyncio
import concurrent.futures
import logging
import socket
import threading
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from core.sandbox import proxy as proxy_mod
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def proxy(monkeypatch):
    patch_module_attribute(monkeypatch, proxy_mod, "parser_jail", "get_parser_jail",
                           lambda: Mock(landlocked=True))
    instance = proxy_mod.EgressProxy([])
    clients = []
    try:
        yield instance, clients
    finally:
        # Owned clients are always closed, including on a baseline failure.
        for client in clients:
            client.close()
        instance.stop(drain_timeout=0)
        assert not instance.is_alive()


@pytest.fixture
def socket_path():
    # AF_UNIX paths have a kernel byte limit independent of pytest's
    # basetemp/scenario-name lengths. Own a short disposable directory.
    with tempfile.TemporaryDirectory(prefix="r72-", dir="/tmp") as directory:
        yield str(Path(directory) / "proxy.sock")


def submit(instance, coroutine):
    return asyncio.run_coroutine_threadsafe(coroutine, instance._loop).result(5)


def shutdown(instance, mode):
    if mode == "unexpected":
        instance._loop.call_soon_threadsafe(instance._loop.stop)
        instance._thread.join(5)
    else:
        instance.stop(drain_timeout=0 if mode == "abrupt" else 0.1)
    assert not instance.is_alive()
    assert instance._loop.is_closed()


@pytest.mark.parametrize("mode", ["unexpected", "abrupt", "graceful"])
@pytest.mark.parametrize("transport", ["main", "tcp-lane", "unix-lane"])
@pytest.mark.parametrize("phase", ["peer-lookup", "handshake"])
def test_accepted_socket_is_closed_when_cancelled_during_peer_lookup(
    proxy, monkeypatch, socket_path, mode, transport, phase,
):
    instance, clients = proxy
    entered = threading.Event()

    async def peer_lookup(*args):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(instance, "_lookup_peer_uid", peer_lookup)
    if phase == "handshake":
        async def own_uid(*args):
            return proxy_mod.os.geteuid()
        monkeypatch.setattr(instance, "_lookup_peer_uid", own_uid)
        real_serve = instance._serve_tunnel
        async def serve(*args, **kwargs):
            entered.set()
            await real_serve(*args, **kwargs)
        monkeypatch.setattr(instance, "_serve_tunnel", serve)
    if transport == "unix-lane":
        # Unix peers skip the TCP UID lookup. Stall at the same early
        # handler boundary, before its tunnel cleanup region exists.
        async def before_handler(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()
        if phase == "peer-lookup":
            monkeypatch.setattr(instance, "_handle_client", before_handler)
        path = socket_path
        instance.bind_unix(path)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        clients.append(client)
        client.connect(path)
    else:
        port = instance.port if transport == "main" else instance.bind_tcp_lane()
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        clients.append(client)
    assert entered.wait(5), transport
    shutdown(instance, mode)
    client.settimeout(1)
    assert client.recv(1) == b""
    assert instance._client_tasks == instance._unix_tasks == set()
    assert instance._active_tunnels == 0


@pytest.mark.parametrize("mode", ["unexpected", "abrupt", "graceful"])
@pytest.mark.parametrize("lane", [False, True])
def test_handler_and_child_finally_blocks_finish_before_loop_closes(proxy, mode, lane):
    instance, _ = proxy
    finalized = []

    async def child():
        try:
            await asyncio.Event().wait()
        finally:
            for _ in range(5):
                await asyncio.sleep(0)
            finalized.append("child")

    async def handler():
        task = asyncio.create_task(child())
        try:
            await task
        finally:
            for _ in range(5):
                await asyncio.sleep(0)
            finalized.append("handler")

    async def install():
        task = asyncio.create_task(handler())
        (instance._unix_tasks if lane else instance._client_tasks).add(task)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return task

    task = submit(instance, install())
    shutdown(instance, mode)
    assert task.done() and finalized == ["child", "handler"]
    assert instance._client_tasks == instance._unix_tasks == set()


@pytest.mark.parametrize("transport", ["main", "tcp-lane", "unix-lane"])
def test_grace_window_applies_to_handlers_on_every_listener(proxy, socket_path, transport):
    instance, _ = proxy
    if transport == "tcp-lane":
        instance.bind_tcp_lane()
    elif transport == "unix-lane":
        instance.bind_unix(socket_path)
    completed = threading.Event()

    async def install():
        async def handler():
            # Deterministically complete only once shutdown closed listeners;
            # no wallclock ratio or timer race decides the assertion.
            while instance._server.is_serving():
                await asyncio.sleep(0)
            completed.set()
        task = asyncio.create_task(handler())
        (instance._client_tasks if transport == "main" else instance._unix_tasks).add(task)
        task.add_done_callback((instance._client_tasks if transport == "main"
                                else instance._unix_tasks).discard)
    submit(instance, install())
    instance.stop(drain_timeout=1)
    assert completed.is_set()
    assert instance._shutdown_complete


def test_stop_from_loop_thread_does_not_join_itself(proxy):
    instance, _ = proxy
    called = concurrent.futures.Future()

    def stop():
        try:
            instance.stop(drain_timeout=0)
        except BaseException as exc:
            called.set_exception(exc)
        else:
            called.set_result(None)
    instance._loop.call_soon_threadsafe(stop)
    called.result(5)
    instance._thread.join(5)
    assert not instance.is_alive()
    assert instance._shutdown_complete


def test_concurrent_stops_share_one_shutdown_and_one_summary(proxy, caplog):
    instance, _ = proxy
    with caplog.at_level(logging.INFO, logger=proxy_mod.__name__):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = [pool.submit(instance.stop, drain_timeout=0) for _ in range(4)]
            for result in results:
                result.result(5)
    assert not instance.is_alive() and instance._shutdown_complete
    lines = [record for record in caplog.records if "egress proxy summary:" in record.getMessage()]
    assert len(lines) == 1


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf"), -float("inf"),
                                 True, "1", None, 10 ** 1000],
                         ids=["negative", "nan", "inf", "negative-inf", "bool", "string", "none", "huge"])
def test_invalid_drain_budget_is_rejected_before_mutation(proxy, value):
    instance, _ = proxy
    with pytest.raises(ValueError, match="finite nonnegative"):
        instance.stop(drain_timeout=value)
    assert instance.is_alive() and not instance._stopping


def test_client_cancelled_before_coroutine_entry_still_closes_writer(proxy, monkeypatch):
    instance, _ = proxy
    writer = Mock()
    entered = []

    async def handle(*args):
        entered.append(True)
    monkeypatch.setattr(instance, "_handle_client", handle)

    async def cancel_before_entry():
        instance._on_client_connected(None, writer)
        task = next(iter(instance._client_tasks))
        task.cancel()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return task
    task = submit(instance, cancel_before_entry())
    assert task.cancelled() and entered == []
    writer.close.assert_called_once()
    assert not instance._client_tasks and not instance._client_writers


def test_accept_after_shutdown_closes_without_starting_handler(proxy):
    instance, _ = proxy
    writer = Mock()
    async def late_accept():
        instance._stopping = True
        instance._on_client_connected(None, writer)
    submit(instance, late_accept())
    writer.close.assert_called_once()
    assert not instance._client_tasks


def test_second_cancellation_retires_suspended_cleanup(proxy):
    instance, _ = proxy
    cancelled = []
    async def handler():
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.append("first")
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.append("retired")
    async def install():
        task = asyncio.create_task(handler())
        instance._client_tasks.add(task)
        await asyncio.sleep(0)
        return task
    task = submit(instance, install())
    instance.stop(drain_timeout=0)
    assert task.done() and cancelled == ["first", "retired"]
    assert instance._shutdown_complete


def test_all_listener_types_close_before_graceful_wait(proxy, socket_path):
    instance, _ = proxy
    port = instance.bind_tcp_lane()
    path = socket_path
    instance.bind_unix(path)
    servers = [instance._server, instance._tcp_lane_servers[port], instance._unix_servers[path]]
    observed = []
    async def install():
        async def handler():
            while instance._server.is_serving():
                await asyncio.sleep(0)
            observed.extend(server.is_serving() for server in servers)
        task = asyncio.create_task(handler())
        instance._client_tasks.add(task)
        task.add_done_callback(instance._client_tasks.discard)
    submit(instance, install())
    instance.stop(drain_timeout=1)
    assert observed == [False, False, False]
    assert not Path(socket_path).exists()


def test_unexpected_exit_during_grace_does_not_interrupt_final_retirement(proxy):
    instance, _ = proxy
    finalized = []
    async def install():
        async def handler():
            try:
                await asyncio.Event().wait()
            finally:
                await asyncio.sleep(0)
                finalized.append(True)
        task = asyncio.create_task(handler())
        instance._client_tasks.add(task)
        async def stop_during_grace():
            while instance._server.is_serving():
                await asyncio.sleep(0)
            instance._loop.stop()
        asyncio.create_task(stop_during_grace())
        await asyncio.sleep(0)
        return task
    task = submit(instance, install())
    instance.stop(drain_timeout=1)
    assert task.done() and finalized == [True]
    assert instance._shutdown_complete


def test_explicit_stop_after_unexpected_exit_releases_unix_path(proxy, socket_path):
    instance, _ = proxy
    instance.bind_unix(socket_path)
    shutdown(instance, "unexpected")
    instance.stop(drain_timeout=0)
    assert not Path(socket_path).exists()
    assert instance._unix_servers == instance._unix_lanes == {}

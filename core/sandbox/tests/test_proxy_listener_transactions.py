"""Per-context listeners keep ownership through activation and retirement."""

import asyncio
import concurrent.futures
import gc
import os
import socket
import stat
import tempfile
import threading
from pathlib import Path
from unittest.mock import Mock

import pytest

from core.sandbox import proxy as proxy_mod
from core.testing.module_bindings import patch_module_attribute
from core.testing.proxy_scope import isolated_proxy_scope


@pytest.fixture
def owner():
    with isolated_proxy_scope(), tempfile.TemporaryDirectory(prefix="r76-", dir="/tmp") as directory:
        with pytest.MonkeyPatch.context() as setup:
            patch_module_attribute(setup, proxy_mod, "parser_jail", "get_parser_jail",
                                   lambda: Mock(landlocked=True))
            created = []
            for name in ("start_server", "start_unix_server"):
                original = getattr(proxy_mod.asyncio, name)
                def wrap(factory):
                    async def record(*args, **kwargs):
                        server = await factory(*args, **kwargs)
                        created.append(server)
                        return server
                    return record
                patch_module_attribute(setup, proxy_mod, "asyncio", name, wrap(original))
            instance = proxy_mod.EgressProxy([])
            loop_errors = []
            async def capture_errors():
                instance._loop.set_exception_handler(lambda loop, context: loop_errors.append(context))
            on_loop(instance, capture_errors())
            try:
                yield instance, str(Path(directory) / "lane.sock")
            finally:
                # Retain actual socket owners even if a baseline regression
                # replaces a registry entry or loses a returned server.
                sockets = [sock for server in created for sock in server._sockets or ()]
                try:
                    instance.stop(drain_timeout=0)
                finally:
                    for sock in sockets:
                        sock.close()
                assert not instance.is_alive()
                # Collect abandoned task/future cycles while their private
                # loop still has its owned error recorder, even after close.
                gc.collect()
                assert loop_errors == [], loop_errors



@pytest.fixture
def monkeypatch(owner):
    # Body faults undo before the owner stops its real private loop.
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def on_loop(instance, coroutine):
    return asyncio.run_coroutine_threadsafe(coroutine, instance._loop).result(5)


def barrier(instance):
    async def ready():
        await asyncio.sleep(0)
    on_loop(instance, ready())


def bind(instance, path, transport):
    return instance.bind_unix(path) if transport == "unix" else instance.bind_tcp_lane()


def close(instance, path, transport, port):
    return instance.unbind_unix(path) if transport == "unix" else instance.close_tcp_lane(port)


def servers(instance):
    return [*instance._unix_servers.values(), *instance._tcp_lane_servers.values()]


@pytest.mark.parametrize("transport", ["unix", "tcp"])
@pytest.mark.parametrize("failure_type", [TimeoutError, KeyboardInterrupt])
def test_abandoned_completed_bind_is_rolled_back(owner, monkeypatch, transport, failure_type):
    instance, path = owner
    submit = proxy_mod._submit_to_loop
    created = []
    failure = failure_type("owned result delivery failure")

    def late_result(coroutine, loop):
        real = submit(coroutine, loop)
        class Delivery:
            def result(self, timeout):
                real.result(5)
                created.extend(servers(instance))
                raise failure
            def cancel(self):
                return real.cancel()
        return Delivery()

    with monkeypatch.context() as fault:
        fault.setattr(proxy_mod, "_submit_to_loop", late_result)
        with pytest.raises(failure_type) as raised:
            bind(instance, path, transport)
    assert raised.value is failure
    barrier(instance)
    assert len(created) == 1 and not created[0].is_serving()
    assert servers(instance) == [] and not Path(path).exists()
    port = bind(instance, path, transport)
    close(instance, path, transport, port)


@pytest.mark.parametrize("transport", ["unix", "tcp"])
def test_late_creation_after_cancellation_cannot_publish_a_listener(owner, monkeypatch, transport):
    instance, path = owner
    name = "start_unix_server" if transport == "unix" else "start_server"
    original = getattr(proxy_mod.asyncio, name)
    entered, cancelled, closed = threading.Event(), threading.Event(), threading.Event()
    gate = asyncio.Event()
    created = []
    submit = proxy_mod._submit_to_loop

    async def delayed(*args, **kwargs):
        server = await original(*args, **kwargs)
        created.append(server)
        real_close = server.close
        def record_close():
            real_close()
            closed.set()
        server.close = record_close
        entered.set()
        try:
            await gate.wait()
        except asyncio.CancelledError:
            cancelled.set()
            await gate.wait()
        return server

    def forced_timeout(coroutine, loop):
        real = submit(coroutine, loop)
        class Delivery:
            def result(self, timeout):
                assert entered.wait(5), "listener creation never entered"
                raise TimeoutError("owned bind deadline")
            def cancel(self):
                return real.cancel()
        return Delivery()

    try:
        with monkeypatch.context() as fault:
            patch_module_attribute(fault, proxy_mod, "asyncio", name, delayed)
            fault.setattr(proxy_mod, "_submit_to_loop", forced_timeout)
            with pytest.raises(TimeoutError):
                bind(instance, path, transport)
            assert cancelled.wait(5), "abandoned creation was not cancelled"
            instance._loop.call_soon_threadsafe(gate.set)
            assert closed.wait(5), "late listener was not retired"
            barrier(instance)
        assert len(created) == 1 and not created[0].is_serving()
        assert servers(instance) == [] and not Path(path).exists()
    finally:
        instance._loop.call_soon_threadsafe(gate.set)


@pytest.mark.parametrize("transport", ["unix", "tcp"])
@pytest.mark.parametrize("failure_type", [OSError, RuntimeError, asyncio.CancelledError])
def test_failure_after_server_creation_retires_the_real_listener(owner, monkeypatch, transport, failure_type):
    instance, path = owner
    name = "start_unix_server" if transport == "unix" else "start_server"
    original = getattr(proxy_mod.asyncio, name)
    created = []
    async def failing(*args, **kwargs):
        server = await original(*args, **kwargs)
        created.append(server)
        async def start():
            raise failure_type("owned start_serving failure")
        server.start_serving = start
        return server
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "asyncio", name, failing)
        expected = concurrent.futures.CancelledError if failure_type is asyncio.CancelledError else failure_type
        with pytest.raises(expected):
            bind(instance, path, transport)
    barrier(instance)
    assert len(created) == 1 and created[0].sockets == ()
    assert servers(instance) == [] and not Path(path).exists()


def test_duplicate_bind_keeps_the_original_lane_and_listener(owner):
    instance, path = owner
    instance.bind_unix(path, label="original", allowed_hosts={"owned.invalid"})
    server, lane = instance._unix_servers[path], instance._unix_lanes[path]
    with pytest.raises(RuntimeError, match="already owned"):
        instance.bind_unix(path, label="replacement")
    assert instance._unix_servers[path] is server and instance._unix_lanes[path] is lane
    assert server.is_serving() and lane.label == "original"


def test_pending_bind_reserves_its_unix_name(owner, monkeypatch):
    instance, path = owner
    entered = threading.Event()
    gate = asyncio.Event()
    original = proxy_mod.asyncio.start_unix_server
    failures = []
    async def delayed(*args, **kwargs):
        entered.set()
        await gate.wait()
        return await original(*args, **kwargs)
    def caller():
        try:
            instance.bind_unix(path, label="original")
        except BaseException as exc:
            failures.append(exc)
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "asyncio", "start_unix_server", delayed)
        worker = threading.Thread(target=caller)
        worker.start()
        try:
            assert entered.wait(5)
            with pytest.raises(RuntimeError, match="already owned"):
                instance.bind_unix(path, label="replacement")
        finally:
            instance._loop.call_soon_threadsafe(gate.set)
            worker.join(5)
            assert not worker.is_alive()
    assert failures == [] and instance._unix_lanes[path].label == "original"


@pytest.mark.parametrize("kind", ["file", "socket"])
def test_bind_never_replaces_an_existing_filesystem_entry(owner, kind):
    instance, path = owner
    external = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if kind == "file":
            Path(path).write_text("owned fixture data")
        else:
            external.bind(path)
            external.listen()
        before = os.lstat(path)
        with pytest.raises(OSError):
            instance.bind_unix(path)
        after = os.lstat(path)
        assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
        if kind == "file":
            assert Path(path).read_text() == "owned fixture data"
        else:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(path)
                accepted, _ = external.accept()
                accepted.close()
    finally:
        external.close()


@pytest.mark.parametrize("kind", ["file", "socket"])
@pytest.mark.parametrize("operation", ["unbind", "stop", "unexpected-then-stop"])
def test_teardown_preserves_a_replacement_inode(owner, kind, operation):
    instance, path = owner
    instance.bind_unix(path)
    os.unlink(path)
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if kind == "file":
            Path(path).write_text("replacement")
        else:
            replacement.bind(path)
        before = os.lstat(path)
        if operation == "unbind":
            instance.unbind_unix(path)
        else:
            if operation == "unexpected-then-stop":
                instance._loop.call_soon_threadsafe(instance._loop.stop)
                instance._thread.join(5)
                assert not instance.is_alive()
            instance.stop(drain_timeout=0)
        after = os.lstat(path)
        assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    finally:
        replacement.close()


@pytest.mark.parametrize("fails", [False, True])
def test_unix_bind_sets_private_permissions_without_mutating_umask(owner, monkeypatch, fails):
    instance, path = owner
    original = proxy_mod.asyncio.start_unix_server
    observed = []
    async def inspect(*args, **kwargs):
        observed.append(stat.S_IMODE(os.lstat(path).st_mode))
        if fails:
            raise OSError("owned bind adapter failure")
        return await original(*args, **kwargs)
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "os", "umask", Mock(side_effect=AssertionError("global umask changed")))
        patch_module_attribute(fault, proxy_mod, "asyncio", "start_unix_server", inspect)
        if fails:
            with pytest.raises(OSError, match="owned bind"):
                instance.bind_unix(path)
        else:
            instance.bind_unix(path)
    assert observed == [0o600]
    if fails:
        assert not Path(path).exists()


def test_chmod_failure_releases_the_bound_socket_and_path(owner, monkeypatch):
    instance, path = owner
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "os", "chmod", Mock(side_effect=OSError("owned chmod failure")))
        with pytest.raises(OSError, match="owned chmod"):
            instance.bind_unix(path)
    assert not Path(path).exists() and servers(instance) == []
    instance.bind_unix(path)


@pytest.mark.parametrize("transport", ["unix", "tcp"])
def test_failed_close_submission_keeps_the_registered_owner_for_retry(owner, monkeypatch, transport):
    instance, path = owner
    port = bind(instance, path, transport)
    server = servers(instance)[0]
    with monkeypatch.context() as fault:
        # Exercise the real submission helper's coroutine ownership separately.
        # This seam rejects before accepting ownership of the coroutine.
        def reject(coroutine, loop):
            coroutine.close()
            raise RuntimeError("owned loop rejection")
        fault.setattr(proxy_mod, "_submit_to_loop", reject)
        close(instance, path, transport, port)
    assert servers(instance) == [server] and server.is_serving()
    close(instance, path, transport, port)
    assert servers(instance) == [] and not server.is_serving()


@pytest.mark.parametrize("transport", ["unix", "tcp"])
def test_close_failure_keeps_ownership_until_a_successful_retry(owner, monkeypatch, transport):
    instance, path = owner
    port = bind(instance, path, transport)
    server = servers(instance)[0]
    with monkeypatch.context() as fault:
        fault.setattr(server, "close", Mock(side_effect=OSError("owned close failure")))
        close(instance, path, transport, port)
    assert servers(instance) == [server] and server.is_serving()
    close(instance, path, transport, port)
    assert servers(instance) == [] and not server.is_serving()


@pytest.mark.parametrize("transport", ["unix", "tcp"])
def test_lane_close_from_the_proxy_loop_does_not_block_on_itself(owner, transport):
    instance, path = owner
    port = bind(instance, path, transport)
    server = servers(instance)[0]
    async def closing():
        close(instance, path, transport, port)
        assert servers(instance) == [] and not server.is_serving()
    on_loop(instance, closing())


@pytest.mark.parametrize("transport", ["unix", "tcp"])
def test_blocking_bind_from_proxy_loop_is_rejected_before_scheduling(owner, monkeypatch, transport):
    instance, path = owner
    # Bound the old behavior without relying on an elapsed-time ratio.
    monkeypatch.setattr(proxy_mod, "_PROXY_CONNECT_TIMEOUT_S", 0.01)
    async def calling():
        with pytest.raises(RuntimeError, match="proxy loop"):
            bind(instance, path, transport)
    on_loop(instance, calling())
    barrier(instance)
    assert servers(instance) == []


@pytest.mark.parametrize("transport", ["unix", "tcp"])
def test_closed_diagnostic_stream_does_not_lose_a_successful_lane(owner, monkeypatch, transport):
    instance, path = owner
    logger = proxy_mod.logger
    class LoggerView:
        def __getattr__(self, name):
            return getattr(logger, name)
        def debug(self, *args, **kwargs):
            raise OSError("owned closed diagnostic stream")
        def info(self, *args, **kwargs):
            raise OSError("owned closed diagnostic stream")
    with monkeypatch.context() as fault:
        fault.setattr(proxy_mod, "logger", LoggerView())
        port = bind(instance, path, transport)
    assert len(servers(instance)) == 1
    close(instance, path, transport, port)


@pytest.mark.parametrize("transport", ["unix", "tcp"])
def test_delayed_close_keeps_ownership_until_the_loop_runs_it(owner, monkeypatch, transport):
    instance, path = owner
    port = bind(instance, path, transport)
    server = servers(instance)[0]
    entered, release = threading.Event(), threading.Event()
    submitted = []
    submit = proxy_mod._submit_to_loop
    def block():
        entered.set()
        assert release.wait(5), "test did not release its owned loop"
    def timeout_result(coroutine, loop):
        real = submit(coroutine, loop)
        submitted.append(real)
        class Delivery:
            def result(self, timeout):
                raise TimeoutError("owned delayed close")
        return Delivery()
    instance._loop.call_soon_threadsafe(block)
    try:
        assert entered.wait(5)
        with monkeypatch.context() as fault:
            fault.setattr(proxy_mod, "_submit_to_loop", timeout_result)
            close(instance, path, transport, port)
        assert servers(instance) == [server]
    finally:
        release.set()
    for future in submitted:
        future.result(5)
    assert servers(instance) == [] and not server.is_serving()


@pytest.mark.parametrize("transport", ["unix", "tcp"])
def test_partial_close_error_is_retained_until_retry_finishes_cleanup(owner, monkeypatch, transport):
    instance, path = owner
    port = bind(instance, path, transport)
    server = servers(instance)[0]
    original = server.close
    def close_then_fail():
        original()
        raise OSError("owned post-close failure")
    with monkeypatch.context() as fault:
        fault.setattr(server, "close", close_then_fail)
        close(instance, path, transport, port)
    assert servers(instance) == [server] and not server.is_serving()
    close(instance, path, transport, port)
    assert servers(instance) == [] and not Path(path).exists()


def test_unbind_cancels_publication_of_a_pending_unix_lane(owner, monkeypatch):
    instance, path = owner
    entered = threading.Event()
    gate = asyncio.Event()
    original = proxy_mod.asyncio.start_unix_server
    failures = []
    async def delayed(*args, **kwargs):
        entered.set()
        await gate.wait()
        return await original(*args, **kwargs)
    def caller():
        try:
            instance.bind_unix(path)
        except BaseException as exc:
            failures.append(exc)
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "asyncio", "start_unix_server", delayed)
        worker = threading.Thread(target=caller)
        worker.start()
        try:
            assert entered.wait(5)
            instance.unbind_unix(path)
        finally:
            instance._loop.call_soon_threadsafe(gate.set)
            worker.join(5)
            assert not worker.is_alive()
    assert len(failures) == 1 and isinstance(failures[0], RuntimeError)
    assert servers(instance) == [] and not Path(path).exists()

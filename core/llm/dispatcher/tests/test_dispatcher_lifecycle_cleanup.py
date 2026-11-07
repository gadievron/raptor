"""Dispatcher ownership covers partial listener setup and failed teardown."""

import socketserver
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

from core.llm.dispatcher import server
from core.llm.dispatcher.auth import CredentialStore


import core.llm.dispatcher.server as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def creds():
    result = CredentialStore.__new__(CredentialStore)
    result._keys = {}
    return result


@contextmanager
def tracked_listeners(monkeypatch):
    servers, threads, directories = [], [], []
    real_init = socketserver.TCPServer.__init__
    real_thread = threading.Thread
    real_mkdtemp = server.tempfile.mkdtemp

    def initialize(instance, *args, **kwargs):
        real_init(instance, *args, **kwargs)
        servers.append(instance)

    def thread(*args, **kwargs):
        result = real_thread(*args, **kwargs)
        if kwargs.get("name", "").startswith("raptor-llm-dispatcher"):
            threads.append(result)
        return result

    def directory(*args, **kwargs):
        result = real_mkdtemp(*args, **kwargs)
        directories.append(Path(result))
        return result

    with monkeypatch.context() as fault:
        fault.setattr(socketserver.TCPServer, "__init__", initialize)
        fault.setattr(threading, "Thread", thread)
        patch_module_attribute(fault, server, 'tempfile', "mkdtemp", directory)
        try:
            yield servers, threads, directories
        finally:
            # The fixture also contains regressions in the code under test.
            for listener in servers:
                owning = [
                    t
                    for t in threads
                    if getattr(t, "_target", None) == listener.serve_forever
                ]
                if any(t.is_alive() for t in owning):
                    socketserver.BaseServer.shutdown(listener)
                socketserver.TCPServer.server_close(listener)
            for instance in threads:
                if instance.ident is not None:
                    instance.join(timeout=5)
            from core.atomic_fs import rmtree_hardened

            for path in directories:
                rmtree_hardened(path)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "stage",
    [
        "first-construction",
        "first-start",
        "child-handler",
        "second-construction",
        "second-start",
        "audit",
    ],
)
def test_partial_constructor_retires_all_acquired_listeners(
    creds, monkeypatch, stage, error
):
    failure = error("setup failed")
    with (
        tracked_listeners(monkeypatch) as (listeners, threads, directories),
        monkeypatch.context() as fault,
    ):
        real_thread = threading.Thread

        def thread(*args, **kwargs):
            number = 2 if "-child-" in kwargs.get("name", "") else 1
            target = "first" if number == 1 else "second"
            if stage == target + "-construction":
                raise failure
            instance = real_thread(*args, **kwargs)
            if stage == target + "-start":

                def fail():
                    raise failure

                instance.start = fail
            return instance

        fault.setattr(threading, "Thread", thread)
        handler = server._make_request_handler

        def make_handler(*args, **kwargs):
            if stage == "child-handler" and kwargs.get("plane") == "child_uds":
                raise failure
            return handler(*args, **kwargs)

        fault.setattr(server, "_make_request_handler", make_handler)
        if stage == "audit":

            def fail(*args):
                raise failure

            fault.setattr(server.LLMDispatcher, "_audit", fail)
        with pytest.raises(error) as caught:
            server.LLMDispatcher(run_id="lifecycle-case", creds=creds)
        assert caught.value is failure
        assert listeners and all(s.socket.fileno() == -1 for s in listeners)
        assert all(not t.is_alive() for t in threads)
        assert directories and all(not p.exists() for p in directories)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "stage",
    ["chmod", "marker", "pin-open", "finalizer", "mac-base", "compact-allocation"],
)
def test_early_allocation_failure_reclaims_directory_and_pin(
    creds, tmp_path, monkeypatch, error, stage
):
    import os
    import weakref

    failure = error("early setup failed")
    descriptors = []
    with (
        tracked_listeners(monkeypatch) as (listeners, threads, directories),
        monkeypatch.context() as fault,
    ):
        # Pin/finalizer faults exercise the Linux descriptor-address branch.
        # A zero budget deliberately forces that branch; on Darwin it would
        # reject even the compact path before reaching the injected fault.
        patch_module_attribute(fault, server, 'sys', "platform", "linux")
        fault.setattr(server, "_SUN_PATH_BUDGET", 0)
        real_open = os.open
        failed_open = False

        def open_directory(path, flags, *args, **kwargs):
            nonlocal failed_open
            ours = (
                isinstance(path, (str, Path))
                and Path(path).name.startswith("raptor-llm-")
                and flags & os.O_DIRECTORY
            )
            if ours and stage == "pin-open" and not failed_open:
                failed_open = True
                raise failure
            fd = real_open(path, flags, *args, **kwargs)
            if ours and not descriptors:
                descriptors.append(fd)
            return fd

        patch_module_attribute(fault, _os_fault_consumer, "os", "open", open_directory)
        if stage in ("mac-base", "compact-allocation"):
            base = tmp_path / "mac-base"
            base.mkdir(mode=0o700)
            patch_module_attribute(fault, server, 'sys', "platform", "darwin")
            fault.setattr(server, "_SERVICE_TMP_BASE", str(base))
            if stage == "mac-base":
                stat = Path.stat

                def failed_stat(path, *args, **kwargs):
                    if path == base:
                        raise failure
                    return stat(path, *args, **kwargs)

                fault.setattr(Path, "stat", failed_stat)
            else:
                mkdtemp = server.tempfile.mkdtemp

                def failed_compact(*args, **kwargs):
                    if kwargs.get("prefix") == "rll-":
                        raise failure
                    return mkdtemp(*args, **kwargs)

                patch_module_attribute(fault, server, 'tempfile', "mkdtemp", failed_compact)
        elif stage == "marker":

            def failed_marker(*args):
                raise failure

            fault.setattr(server, "write_owner_marker", failed_marker)
        elif stage == "chmod":
            chmod = os.chmod
            failed = False

            def failed_chmod(path, *args, **kwargs):
                nonlocal failed
                if (
                    not failed
                    and isinstance(path, (str, Path))
                    and Path(path).name.startswith("raptor-llm-")
                ):
                    failed = True
                    raise failure
                return chmod(path, *args, **kwargs)

            patch_module_attribute(fault, _os_fault_consumer, "os", "chmod", failed_chmod)
        elif stage == "finalizer":
            finalize = weakref.finalize

            def failed_finalizer(obj, *args, **kwargs):
                if isinstance(obj, server.LLMDispatcher):
                    raise failure
                return finalize(obj, *args, **kwargs)

            fault.setattr(weakref, "finalize", failed_finalizer)
        with pytest.raises(error) as caught:
            server.LLMDispatcher(run_id="early-case", creds=creds)
        assert caught.value is failure
        assert not listeners
        assert directories and all(not p.exists() for p in directories)
        for fd in descriptors:
            with pytest.raises(OSError):
                os.fstat(fd)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stage", ["construction", "start", "audit"])
def test_failed_optional_tcp_setup_is_retired_and_can_be_retried(
    creds, monkeypatch, error, stage
):
    failure = error("loopback setup failed")
    with tracked_listeners(monkeypatch) as (listeners, threads, directories):
        dispatcher = server.LLMDispatcher(run_id="tcp-retry", creds=creds)
        try:
            with monkeypatch.context() as fault:
                thread = threading.Thread

                def failed_thread(*args, **kwargs):
                    tcp = kwargs.get("name", "").startswith(
                        "raptor-llm-dispatcher-tcp-"
                    )
                    if tcp and stage == "construction":
                        raise failure
                    instance = thread(*args, **kwargs)
                    if tcp and stage == "start":

                        def fail():
                            raise failure

                        instance.start = fail
                    return instance

                fault.setattr(threading, "Thread", failed_thread)
                audit = dispatcher._audit

                def failed_audit(event):
                    if stage == "audit" and event.event == "server.loopback_start":
                        raise failure
                    return audit(event)

                fault.setattr(dispatcher, "_audit", failed_audit)
                with pytest.raises(error) as caught:
                    dispatcher.enable_loopback_listener()
                assert caught.value is failure
                assert listeners[-1].socket.fileno() == -1
                assert dispatcher._thread.is_alive()
                assert dispatcher._child_thread.is_alive()
            assert dispatcher.enable_loopback_listener() > 0
        finally:
            dispatcher.shutdown()
        assert all(s.socket.fileno() == -1 for s in listeners)
        assert all(not t.is_alive() for t in threads)
        assert all(not p.exists() for p in directories)


@pytest.mark.parametrize("plane", ["worker", "child", "tcp"])
@pytest.mark.parametrize("operation", ["shutdown", "close"])
def test_shutdown_continues_after_each_listener_failure_and_can_retry(
    creds, monkeypatch, plane, operation
):
    with tracked_listeners(monkeypatch) as (listeners, threads, directories):
        dispatcher = server.LLMDispatcher(run_id="shutdown-retry", creds=creds)
        dispatcher.enable_loopback_listener()
        listener = {
            "worker": dispatcher._server,
            "child": dispatcher._child_server,
            "tcp": dispatcher._tcp_server,
        }[plane]
        events = []
        method = "shutdown" if operation == "shutdown" else "server_close"
        original = getattr(listener, method)
        try:
            with monkeypatch.context() as fault:
                fault.setattr(dispatcher, "_audit", events.append)

                def failed():
                    original()
                    raise OSError("retirement failed")

                fault.setattr(listener, method, failed)
                dispatcher.shutdown()
                assert not dispatcher._shutdown_done
                assert all(s.socket.fileno() == -1 for s in listeners)
                assert all(not t.is_alive() for t in threads)
                assert events[-1].status == "partial"
            dispatcher.shutdown()
            assert dispatcher._shutdown_done
            assert all(not p.exists() for p in directories)
        finally:
            dispatcher.shutdown()


def test_socket_directory_failure_keeps_cleanup_pending(creds, monkeypatch):
    dispatcher = server.LLMDispatcher(run_id="storage-retry", creds=creds)
    storage = dispatcher._sock_dir
    try:
        with monkeypatch.context() as fault:
            fault.setattr(server, "rmtree_hardened", lambda path: False)
            dispatcher.shutdown()
            assert not dispatcher._shutdown_done
            assert storage.exists()
            assert dispatcher._socket_dirs == [storage]
        dispatcher.shutdown()
        assert dispatcher._shutdown_done
        assert not storage.exists()
        assert dispatcher._socket_dirs == []
    finally:
        dispatcher.shutdown()


def test_upstream_close_failure_retries_without_reopening_listeners(creds):
    from unittest.mock import Mock

    dispatcher = server.LLMDispatcher(run_id="upstream-retry", creds=creds)
    upstream = Mock()
    upstream.close.side_effect = [OSError("busy"), None]
    dispatcher._upstream_shards = upstream
    try:
        dispatcher.shutdown()
        assert not dispatcher._shutdown_done
        assert not dispatcher._thread.is_alive()
        dispatcher.shutdown()
        assert dispatcher._shutdown_done
        assert upstream.close.call_count == 2
        dispatcher.shutdown()
        assert upstream.close.call_count == 2
    finally:
        upstream.close.side_effect = None
        dispatcher.shutdown()


@pytest.mark.parametrize("mode", [0, 0o500, 0o555])
def test_shutdown_reclaims_restricted_owned_leftovers(creds, mode):
    from core.testing.restricted_tree import restricted_tree

    dispatcher = server.LLMDispatcher(run_id="restricted-storage", creds=creds)
    storage = dispatcher._sock_dir
    try:
        with restricted_tree(storage / "leftover", mode):
            dispatcher.shutdown()
            assert not storage.exists()
            assert dispatcher._shutdown_done
    finally:
        dispatcher.shutdown()


def test_completed_shutdown_refuses_new_listeners_and_pools(creds):
    dispatcher = server.LLMDispatcher(run_id="closed-owner", creds=creds)
    dispatcher.shutdown()
    with pytest.raises(RuntimeError, match="shutting down"):
        dispatcher.enable_loopback_listener()
    with pytest.raises(RuntimeError, match="shutting down"):
        dispatcher._upstream_client_shards()
    assert not dispatcher._sock_dir.exists()


def test_concurrent_shutdown_waits_for_cleanup_and_runs_once(creds, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    dispatcher = server.LLMDispatcher(run_id="serialized-close", creds=creds)
    entered, release, second_entered, second_done = (
        threading.Event() for _ in range(4)
    )
    original = dispatcher._server.shutdown
    events = []

    def held():
        entered.set()
        assert release.wait(5)
        original()

    def second():
        second_entered.set()
        dispatcher.shutdown()
        second_done.set()

    with monkeypatch.context() as fault:
        fault.setattr(dispatcher._server, "shutdown", held)
        fault.setattr(dispatcher, "_audit", events.append)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(dispatcher.shutdown)
            try:
                assert entered.wait(5)
                other = pool.submit(second)
                assert second_entered.wait(5)
                assert not second_done.is_set()
            finally:
                release.set()
            first.result(timeout=5)
            other.result(timeout=5)
    assert dispatcher._shutdown_done
    assert len(events) == 1
    assert not dispatcher._sock_dir.exists()

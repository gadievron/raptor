"""Raw upstreams release sockets and threads across setup and shutdown."""

import contextlib
import importlib
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from core.sandbox.tests import socket_server
from core.testing.module_bindings import patch_module_attribute

_HELPERS = [
    ("test_orphan_cancel", "_CaptiveUpstream", "json_quick"),
    ("test_stream_stall_watchdog", "_WedgedUpstream", "head_wedge"),
]


@pytest.mark.parametrize("module_name,class_name,mode", _HELPERS)
@pytest.mark.parametrize("fault", ["bind", "listen", "construction", "start"])
def test_raw_upstream_startup_closes_listener(
    module_name,
    class_name,
    mode,
    fault,
    monkeypatch,
):
    module = importlib.import_module(f"core.llm.dispatcher.tests.{module_name}")
    listeners = []
    real_socket = socket.socket
    real_thread = threading.Thread

    class Listener(real_socket):
        def bind(self, address):
            if fault == "bind":
                raise OSError("injected listener bind failure")
            return super().bind(address)

        def listen(self, backlog):
            if fault == "listen":
                raise OSError("injected listener listen failure")
            return super().listen(backlog)

    def create_socket(*args, **kwargs):
        listener = Listener(*args, **kwargs)
        listeners.append(listener)
        return listener

    class StartFailure(real_thread):
        def start(self):
            raise RuntimeError("injected thread start failure")

    def create_thread(*args, **kwargs):
        if fault == "construction":
            raise RuntimeError("injected thread construction failure")
        return StartFailure(*args, **kwargs)

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                module,
                "socket",
                SimpleNamespace(
                    **(vars(socket) | {"socket": create_socket}),
                ),
            )
            patch_module_attribute(patcher, socket_server, "threading", "Thread", create_thread)
            with pytest.raises((OSError, RuntimeError), match="injected .* failure"):
                getattr(module, class_name)(mode)
        assert len(listeners) == 1
        assert listeners[0].fileno() == -1, "startup failure left listener open"
    finally:
        for listener in listeners:
            listener.close()


@pytest.mark.parametrize("module_name,class_name,mode", _HELPERS)
@pytest.mark.parametrize("fault", ["construction", "start"])
def test_raw_upstream_handler_failure_releases_connection(
    module_name,
    class_name,
    mode,
    fault,
    monkeypatch,
):
    module = importlib.import_module(f"core.llm.dispatcher.tests.{module_name}")
    threads = []
    connections = []
    errors = []
    finished = threading.Event()
    real_thread = threading.Thread

    class StartFailure(real_thread):
        def start(self):
            raise RuntimeError("injected handler start failure")

    def create_thread(*args, **kwargs):
        if kwargs.get("args"):
            connections.append(kwargs["args"][0])
            if fault == "construction":
                raise RuntimeError("injected handler construction failure")
            return StartFailure(*args, **kwargs)
        target = kwargs["target"]

        def observe():
            try:
                target()
            except RuntimeError as error:
                errors.append(str(error))
            finally:
                finished.set()

        instance = real_thread(*args, **(kwargs | {"target": observe}))
        threads.append(instance)
        return instance

    with monkeypatch.context() as patcher:
        patch_module_attribute(patcher, socket_server, "threading", "Thread", create_thread)
        upstream = getattr(module, class_name)(mode)
        try:
            with socket.create_connection(upstream._listener.getsockname(), timeout=5):
                assert finished.wait(5), "accept loop did not report injected failure"
                assert errors == [f"injected handler {fault} failure"]
                assert len(connections) == 1
                assert connections[0].fileno() == -1, (
                    "failed handler left connection open"
                )
                upstream.shutdown()
                assert all(not t.is_alive() for t in threads)
        finally:
            # Reclaim owned resources without joining an unstarted handler.
            for conn in connections:
                conn.close()
            with contextlib.suppress(OSError):
                upstream._listener.shutdown(socket.SHUT_RDWR)
            upstream._listener.close()
            for t in threads:
                t.join(timeout=3)


@pytest.mark.parametrize(
    "phase",
    [
        "idle",
        "empty-reader",
        "partial-head",
        "partial-body",
        "sse-wedge",
        "slow-body",
    ],
)
def test_wedged_upstream_shutdown_retires_threads(phase, monkeypatch):
    from core.llm.dispatcher.tests import test_stream_stall_watchdog as module

    threads = []
    release = threading.Event()
    entered = threading.Event()
    real_thread = threading.Thread

    def create_thread(*args, **kwargs):
        instance = real_thread(*args, **kwargs)
        threads.append(instance)
        return instance

    # Preserve long waits in the old helper until independent cleanup releases
    # them, so this regression does not itself leave sleeping daemon threads.
    monkeypatch.setattr(
        module,
        "time",
        SimpleNamespace(
            **(vars(time) | {"sleep": release.wait}),
        ),
    )
    patch_module_attribute(monkeypatch, socket_server, "threading", "Thread", create_thread)
    mode = "sse_wedge" if phase == "sse-wedge" else "slow_body"
    upstream = module._WedgedUpstream(mode, wedge_s=60, quiet_s=60)
    original_handle = upstream._handle

    def handle(conn):
        entered.set()
        return original_handle(conn)

    monkeypatch.setattr(upstream, "_handle", handle)
    # A duplicate can wake the old helper's blocked accept even after it closes
    # its own descriptor; it is private to this controlled regression.
    wake = upstream._listener.dup()
    client = None
    try:
        if phase != "idle":
            client = socket.create_connection(
                upstream._listener.getsockname(), timeout=5
            )
            payload = {
                "empty-reader": b"",
                "partial-head": b"POST / HTTP/1.1\r\n",
                "partial-body": b"POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\nx",
            }.get(phase, b"GET / HTTP/1.1\r\n\r\n")
            if payload:
                client.sendall(payload)
            assert entered.wait(5), "handler did not enter request reader"
            if phase in ("sse-wedge", "slow-body"):
                assert client.recv(4096), "response did not reach its silent phase"
        upstream.shutdown()
        assert upstream._listener.fileno() == -1
        assert all(not t.is_alive() for t in threads), (
            "shutdown left upstream threads running"
        )
        upstream.shutdown()  # Idempotent after the first complete teardown.
    finally:
        release.set()
        with contextlib.suppress(OSError):
            wake.shutdown(socket.SHUT_RDWR)
        wake.close()
        if client is not None:
            client.close()
        upstream._listener.close()
        for t in threads:
            t.join(timeout=3)


@pytest.mark.parametrize(
    "method_name",
    [
        "test_mid_stream_wedge_trips_within_the_window",
        "test_head_wedge_trips_and_is_not_retried",
        "test_slow_start_stream_survives_past_stall_window",
        "test_slow_head_start_survives_past_stall_window",
    ],
)
def test_watchdog_setup_failure_reclaims_upstream(method_name, tmp_path, monkeypatch):
    from core.llm.dispatcher.auth import CredentialStore
    from core.llm.dispatcher.tests import test_stream_stall_watchdog as module

    upstreams = []
    wakes = []
    threads = []
    real_upstream = module._WedgedUpstream
    real_thread = threading.Thread

    def thread(*args, **kwargs):
        instance = real_thread(*args, **kwargs)
        threads.append(instance)
        return instance

    def upstream(*args, **kwargs):
        instance = real_upstream(*args, **kwargs)
        upstreams.append(instance)
        wakes.append(instance._listener.dup())
        return instance

    def fail(*args, **kwargs):
        raise RuntimeError("injected dispatcher setup failure")

    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {"anthropic": "fixture-key", "openai": None, "gemini": None}
    try:
        with monkeypatch.context() as patcher:
            patch_module_attribute(patcher, socket_server, "threading", "Thread", thread)
            patcher.setattr(module, "_WedgedUpstream", upstream)
            patcher.setattr(module, "_make_dispatcher", fail)
            method = getattr(module.TestWatchdogTrips(), method_name)
            with pytest.raises(RuntimeError, match="injected dispatcher setup failure"):
                method(creds, tmp_path, patcher)
        assert len(upstreams) == 1
        assert upstreams[0]._listener.fileno() == -1, "later setup left upstream open"
        for t in threads:
            t.join(timeout=2)
        assert all(not t.is_alive() for t in threads)
    finally:
        for instance in upstreams:
            instance.shutdown()
        for wake in wakes:
            with contextlib.suppress(OSError):
                wake.shutdown(socket.SHUT_RDWR)
            wake.close()
        for t in threads:
            t.join(timeout=3)

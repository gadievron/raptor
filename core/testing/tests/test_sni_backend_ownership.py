"""SNI test backends and callers own setup and teardown failures."""

from contextlib import suppress
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox.tests import socket_server as support
from core.sandbox.tests import test_proxy_sni_gate as module


CALLERS = [
    ("TestSniMismatchDenied", "test_fronted_client_hello_closes_tunnel"),
    ("TestSniMismatchDenied", "test_sni_match_is_case_insensitive"),
    ("TestPassThroughUnchanged", "test_matching_sni_tunnel_is_byte_identical"),
    ("TestPassThroughUnchanged", "test_non_tls_first_bytes_pass_through"),
    ("TestPassThroughUnchanged", "test_sni_less_client_hello_passes_through"),
    ("TestPassThroughUnchanged", "test_inconclusive_fragment_passes_after_peek_deadline"),
]


@pytest.mark.parametrize("owner,name", CALLERS)
@pytest.mark.parametrize("stage", ["proxy", "stop", "client"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_caller_failure_releases_backend_and_client(owner, name, stage, error, monkeypatch):
    _caller(owner, name, stage, error, monkeypatch)


@pytest.mark.parametrize("owner,name", CALLERS)
def test_handshake_failure_still_releases_backend(owner, name, monkeypatch):
    _caller(owner, name, "handshake", OSError, monkeypatch)


def _caller(owner, name, stage, error, monkeypatch):
    backend = Mock(port=1)
    proxy = Mock(port=2)
    client = Mock()
    failure = error("injected SNI caller failure")
    if stage == "stop":
        proxy.stop.side_effect = failure
    if stage == "client":
        client.sendall.side_effect = failure
        client.settimeout.side_effect = failure
    with monkeypatch.context() as patcher:
        patcher.setattr(module, "_Backend", Mock(return_value=backend))
        patcher.setattr(module.proxy_mod, "EgressProxy", Mock(
            side_effect=failure if stage == "proxy" else None, return_value=proxy,
        ))
        patcher.setattr(module, "_open_tunnel", Mock(
            side_effect=failure if stage in ("stop", "handshake") else None,
            return_value=client,
        ))
        with pytest.raises(error, match="injected SNI caller failure"):
            caller = getattr(getattr(module, owner)(), name)
            if name == "test_inconclusive_fragment_passes_after_peek_deadline":
                caller(None, None, patcher)
            else:
                caller(None, None)
    backend.close.assert_called_once()
    if stage != "proxy":
        proxy.stop.assert_called_once()
    if stage == "client":
        client.close.assert_called()


@pytest.mark.parametrize("stage", ["bind", "listen", "getsockname", "Event", "Thread", "start"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_backend_setup_failure_closes_listener(stage, error, monkeypatch):
    listener = socket.socket()
    failure = error("injected backend failure")

    class Listener:
        def __getattr__(self, name):
            if name == stage:
                return lambda *a, **kw: fail()
            return getattr(listener, name)

        def close(self):
            listener.close()

    def fail(*args, **kwargs):
        raise failure

    threads = SimpleNamespace(**vars(threading))
    fake_thread = Mock(ident=None)
    fake_thread.is_alive.return_value = False
    threads.Thread = Mock(return_value=fake_thread)
    if stage in ("Event", "Thread"):
        setattr(threads, stage, fail)
    elif stage == "start":
        fake_thread.start.side_effect = failure
    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = lambda *a, **kw: Listener()
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", sockets)
            patcher.setattr(module, "threading", threads)
            patcher.setattr(support, "threading", threads)
            with pytest.raises(error, match="injected backend failure"):
                module._Backend()
        assert listener.fileno() == -1, "backend setup leaked listener"
    finally:
        listener.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_backend_start_then_raise_retires_real_worker(error, monkeypatch):
    real_socket, real_thread = socket.socket, threading.Thread
    listeners, workers = [], []
    entered = threading.Event()

    class Listener:
        def __init__(self):
            self.sock = real_socket()
            listeners.append(self.sock)

        def __getattr__(self, name):
            return getattr(self.sock, name)

        def accept(self):
            entered.set()
            return self.sock.accept()

    def thread(*args, **kwargs):
        worker = real_thread(*args, **kwargs)
        start = worker.start

        def start_then_raise():
            start()
            assert entered.wait(2)
            raise error("injected backend post-start failure")
        worker.start = start_then_raise
        workers.append(worker)
        return worker

    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = lambda *a, **kw: Listener()
    threads = SimpleNamespace(**vars(threading))
    threads.Thread = thread
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", sockets)
            patcher.setattr(module, "threading", threads)
            patcher.setattr(support, "threading", threads)
            with pytest.raises(error, match="injected backend post-start failure"):
                module._Backend()
        assert workers and not workers[0].is_alive(), "backend worker escaped setup"
        assert listeners[0].fileno() == -1
    finally:
        for listener in listeners:
            with suppress(OSError):
                listener.shutdown(socket.SHUT_RDWR)
            listener.close()
        for worker in workers:
            worker.join(3)


@pytest.mark.parametrize("connected", [False, True])
def test_real_backend_close_retires_idle_and_connected_workers(connected):
    backend = module._Backend(reply=b"reply")
    client = None
    try:
        if connected:
            client = socket.create_connection(("127.0.0.1", backend.port), timeout=2)
            client.sendall(b"payload")
            assert client.recv(5) == b"reply"
            assert backend.accepted.is_set()
        backend.close()
        assert backend._srv.fileno() == -1
        assert not backend._server._accept_thread.is_alive()
        assert all(not worker.is_alive() for worker in backend._server._threads)
        assert not backend._server._clients
        if connected:
            assert client.recv(1) == b""
            assert backend.received == b"payload"
    finally:
        if client is not None:
            client.close()
        backend.close()

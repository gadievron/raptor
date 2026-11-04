"""Fake upstream workers and their callers retain failure ownership."""

from contextlib import suppress
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox.tests import test_proxy_upstream_errors as errors_mod
from core.sandbox.tests import test_proxy_upstream_gate2 as gate_mod


CALLERS = [
    ("TestUpstreamHeaderDrainReset", "test_reset_during_header_drain_yields_502", "_RstUpstream"),
    ("TestUpstreamHeaderDrainReset", "test_repeated_resets_do_not_grow_fd_count", "_RstUpstream"),
    ("TestPost200EscapeClosesUpstreamLeg", "test_escape_after_200_closes_upstream_leg", "_HoldingUpstream"),
]
UPSTREAMS = [(errors_mod, "_RstUpstream"), (errors_mod, "_HoldingUpstream"), (gate_mod, "_FakeUpstream")]


@pytest.mark.parametrize("owner,name,kind", CALLERS)
@pytest.mark.parametrize("stage", ["start", "proxy", "stop", "body"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_caller_failure_stops_upstream(owner, name, kind, stage, error, monkeypatch):
    upstream = Mock(port=1)
    proxy = Mock(port=2)
    failure = error("injected upstream caller failure")
    if stage == "start":
        upstream.start.side_effect = failure
    if stage == "stop":
        proxy.stop.side_effect = failure
    with monkeypatch.context() as patcher:
        patcher.setattr(errors_mod, kind, Mock(return_value=upstream))
        patcher.setattr(errors_mod.proxy_mod, "EgressProxy", Mock(
            side_effect=failure if stage == "proxy" else None, return_value=proxy,
        ))
        patcher.setattr(errors_mod, "_send_connect", Mock(side_effect=failure))
        caller = getattr(getattr(errors_mod, owner)(), name)
        with pytest.raises(error, match="injected upstream caller failure"):
            if kind == "_HoldingUpstream":
                caller(None, patcher, None)
            else:
                caller(None, None)
    upstream.stop.assert_called_once()
    if stage not in ("start", "proxy"):
        proxy.stop.assert_called_once()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_fixture_start_failure_stops_upstream(error, monkeypatch):
    upstream = Mock()
    upstream.start.side_effect = error("injected fixture start failure")
    with monkeypatch.context() as patcher:
        patcher.setattr(gate_mod, "_FakeUpstream", Mock(return_value=upstream))
        fixture = gate_mod.fake_upstream.__wrapped__()
        try:
            with pytest.raises(error, match="injected fixture start failure"):
                next(fixture)
            upstream.stop.assert_called_once()
        finally:
            fixture.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, GeneratorExit])
def test_fixture_body_abort_stops_upstream(error, monkeypatch):
    upstream = Mock()
    with monkeypatch.context() as patcher:
        patcher.setattr(gate_mod, "_FakeUpstream", Mock(return_value=upstream))
        fixture = gate_mod.fake_upstream.__wrapped__()
        try:
            assert next(fixture) is upstream
            if error is GeneratorExit:
                fixture.close()
            else:
                with pytest.raises(error, match="injected fixture abort"):
                    fixture.throw(error("injected fixture abort"))
            upstream.stop.assert_called_once()
        finally:
            fixture.close()


def test_fixture_normal_completion_stops_upstream(monkeypatch):
    upstream = Mock()
    with monkeypatch.context() as patcher:
        patcher.setattr(gate_mod, "_FakeUpstream", Mock(return_value=upstream))
        fixture = gate_mod.fake_upstream.__wrapped__()
        try:
            assert next(fixture) is upstream
            with pytest.raises(StopIteration):
                next(fixture)
            upstream.stop.assert_called_once()
        finally:
            fixture.close()


@pytest.mark.parametrize("module,kind", UPSTREAMS, ids=["reset", "holding", "gate"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_start_then_raise_retires_real_upstream_acceptor(module, kind, error, monkeypatch):
    real_socket = socket.socket
    real_start = threading.Thread.start
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

    def start_then_raise(worker):
        workers.append(worker)
        real_start(worker)
        assert entered.wait(2)
        raise error("injected upstream post-start failure")

    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = lambda *a, **kw: Listener()
    upstream = None
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", sockets)
            patcher.setattr(threading.Thread, "start", start_then_raise)
            upstream = getattr(module, kind)()
            with pytest.raises(error, match="injected upstream post-start failure"):
                upstream.start()
        assert workers and not workers[0].is_alive(), "upstream worker escaped failed setup"
        assert listeners[0].fileno() == -1
    finally:
        if upstream is not None:
            upstream.stop()
        for listener in listeners:
            with suppress(OSError):
                listener.shutdown(socket.SHUT_RDWR)
            listener.close()
        for worker in workers:
            worker.join(3)


@pytest.mark.parametrize("module,kind", UPSTREAMS, ids=["reset", "holding", "gate"])
@pytest.mark.parametrize("phase", ["unstarted", "idle", "partial"])
def test_real_upstream_stop_releases_every_worker(module, kind, phase):
    upstream = getattr(module, kind)()
    client = None
    entered = threading.Event()
    serve = upstream._serve

    def observed(conn):
        entered.set()
        serve(conn)

    upstream._serve = observed
    try:
        if phase != "unstarted":
            upstream.start()
        if phase == "partial":
            client = socket.create_connection(("127.0.0.1", upstream.port), timeout=2)
            client.sendall(b"CONNECT incomplete")
            assert entered.wait(2), "upstream handler did not start"
        upstream.stop()
        assert upstream.sock.fileno() == -1
        if phase != "unstarted":
            assert not upstream._server._accept_thread.is_alive()
            assert all(not worker.is_alive() for worker in upstream._server._threads)
            assert not upstream._server._clients
    finally:
        if client is not None:
            client.close()
        upstream.stop()


def test_real_holding_upstream_stop_closes_established_connection():
    upstream = errors_mod._HoldingUpstream()
    held = threading.Event()

    class Connections(list):
        def append(self, conn):
            super().append(conn)
            held.set()

    upstream.held = Connections()
    client = None
    try:
        upstream.start()
        client = socket.create_connection(("127.0.0.1", upstream.port), timeout=2)
        client.sendall(b"CONNECT unused.invalid:443 HTTP/1.1\r\n\r\n")
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = client.recv(4096)
            assert chunk
            response += chunk
        assert response.startswith(b"HTTP/1.1 200 ")
        assert held.wait(2), "upstream did not retain its connection"
        upstream.stop()
        assert all(conn.fileno() == -1 for conn in upstream.held)
        assert not upstream._server._accept_thread.is_alive()
        assert all(not worker.is_alive() for worker in upstream._server._threads)
        assert client.recv(1) == b""
    finally:
        if client is not None:
            client.close()
        upstream.stop()

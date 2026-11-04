"""Peer-identity socket groups and captive listeners release every owner."""

import os
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox.tests import test_proxy_peer_uid as peer
from core.sandbox.tests import test_proxy_sock_diag as diag
from packages.joern.tests import test_netns_forwarder as forwarder


@pytest.mark.parametrize("kind", ["fixture", "ipv6", "peer"])
@pytest.mark.parametrize("role", ["accepted", "client", "listener"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_peer_close_failure_releases_remaining_sockets(kind, role, error, monkeypatch):
    _peer_case(kind, "close", role, error, monkeypatch)


@pytest.mark.parametrize("kind", ["fixture", "ipv6", "peer"])
@pytest.mark.parametrize("stage", ["bind", "listen", "connect", "accept"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_peer_setup_failure_releases_acquired_sockets(kind, stage, error, monkeypatch):
    _peer_case(kind, stage, None, error, monkeypatch)


def _peer_case(kind, stage, role, error, monkeypatch):
    module = peer if kind == "peer" else diag
    real_socket, real_connect = socket.socket, socket.create_connection
    retained = []
    fixture = None

    def fail():
        raise error("injected peer socket failure")

    class OwnedSocket:
        def __init__(self, sock, owner):
            self.sock, self.owner = sock, owner
            retained.append(self)

        def __getattr__(self, name):
            if name == stage and stage in ("bind", "listen"):
                return lambda *a, **kw: fail()
            return getattr(self.sock, name)

        def accept(self):
            if stage == "accept":
                fail()
            accepted, address = self.sock.accept()
            return OwnedSocket(accepted, "accepted"), address

        def close(self):
            self.sock.close()
            if stage == "close" and role == self.owner:
                fail()

    def connect(*args, **kwargs):
        if stage == "connect":
            fail()
        return OwnedSocket(real_connect(*args, **kwargs), "client")

    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = lambda *a, **kw: OwnedSocket(real_socket(*a, **kw), "listener")
    sockets.create_connection = connect
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", sockets)
            patcher.setattr(diag, "_sock_diag_skip_reason", lambda: None)
            patcher.setattr(
                diag.proxy_mod, "_sock_diag_peer_uid", lambda *a: os.geteuid()
            )
            patcher.setattr(
                peer.proxy_mod, "_loopback_peer_uid", lambda *a: os.geteuid()
            )
            expected = (
                pytest.skip.Exception
                if kind == "ipv6" and stage != "close" and error is OSError
                else error
            )
            with pytest.raises(expected):
                if kind == "fixture":
                    fixture = diag.loopback_pair.__wrapped__()
                    next(fixture)
                    fixture.close()
                elif kind == "ipv6":
                    diag.TestSockDiagPrimitive().test_v6_pair_reports_own_uid()
                else:
                    peer.TestLoopbackPeerUidLookup().test_established_loopback_pair_reports_own_uid()
        assert retained and all(s.fileno() == -1 for s in retained), (
            "peer socket leaked"
        )
    finally:
        if fixture is not None:
            fixture.close()
        for owned in retained:
            owned.sock.close()


@pytest.mark.parametrize("kind", ["_EchoServer", "_BlastServer"])
@pytest.mark.parametrize("stage", ["bind", "listen", "getsockname", "server"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_forwarder_backend_setup_failure_closes_listener(
    kind, stage, error, monkeypatch
):
    _backend_case(kind, stage, error, monkeypatch)


@pytest.mark.parametrize("kind", ["_EchoServer", "_BlastServer"])
def test_forwarder_backend_success_transfers_listener(kind, monkeypatch):
    _backend_case(kind, "none", None, monkeypatch)


def _backend_case(kind, stage, error, monkeypatch):
    listener = socket.socket()

    def fail():
        raise error("injected captive listener failure")

    class Listener:
        def __getattr__(self, name):
            return (
                (lambda *a, **kw: fail()) if name == stage else getattr(listener, name)
            )

        def close(self):
            listener.close()

    server = Mock()
    server.close.side_effect = listener.close
    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = lambda *a, **kw: Listener()
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(forwarder, "socket", sockets)
            patcher.setattr(
                forwarder,
                "SocketServer",
                Mock(
                    side_effect=error("injected captive listener failure")
                    if stage == "server"
                    else None,
                    return_value=server,
                ),
            )
            args = (4096,) if kind == "_BlastServer" else ()
            if error is not None:
                with pytest.raises(error, match="injected captive listener failure"):
                    getattr(forwarder, kind)(*args)
                assert listener.fileno() == -1, "backend setup leaked listener"
            else:
                backend = getattr(forwarder, kind)(*args)
                assert listener.fileno() != -1
                backend.close()
                assert listener.fileno() == -1
    finally:
        listener.close()


@pytest.mark.parametrize("kind", ["_EchoServer", "_BlastServer"])
@pytest.mark.parametrize("connected", [False, True])
def test_real_captive_backend_retires_idle_and_connected_workers(kind, connected):
    backend = (
        getattr(forwarder, kind)(4096)
        if kind == "_BlastServer"
        else forwarder._EchoServer()
    )
    client = None
    entered = threading.Event()
    handler = backend._server._handler

    def observed(conn):
        entered.set()
        handler(conn)

    backend._server._handler = observed
    try:
        if connected:
            client = socket.create_connection(("127.0.0.1", backend.port), timeout=2)
            if kind == "_EchoServer":
                # Leave the peer open while its handler waits for EOF.
                client.sendall(b"payload")
            else:
                received = b""
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    received += chunk
                assert received == b"\xab" * 4096
            assert entered.wait(2), "backend did not start its connection handler"
        backend.close()
        assert backend._listener.fileno() == -1
        assert not backend._server._accept_thread.is_alive()
        assert all(not thread.is_alive() for thread in backend._server._threads)
        assert not backend._server._clients
    finally:
        if client is not None:
            client.close()
        backend.close()

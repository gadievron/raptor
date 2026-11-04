"""Failed test-client setup retains ownership of its socket."""

import importlib
import socket
from types import SimpleNamespace

import pytest


TUNNELS = ["test_proxy_sni_gate", "test_proxy_observability", "test_proxy_teardown"]


@pytest.mark.parametrize("name", TUNNELS)
@pytest.mark.parametrize("stage", ["sendall", "recv"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_tunnel_io_failure_closes_socket(name, stage, error, monkeypatch):
    _tunnel(name, stage, error, monkeypatch)


@pytest.mark.parametrize("name", TUNNELS)
@pytest.mark.parametrize("stage", ["eof", "status"])
def test_tunnel_bad_response_closes_socket(name, stage, monkeypatch):
    _tunnel(name, stage, AssertionError, monkeypatch)


@pytest.mark.parametrize("name", TUNNELS[1:])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_tunnel_timeout_setup_closes_socket(name, error, monkeypatch):
    _tunnel(name, "settimeout", error, monkeypatch)


@pytest.mark.parametrize("name", TUNNELS)
def test_successful_tunnel_transfers_live_socket(name, monkeypatch):
    _tunnel(name, "none", None, monkeypatch)


def _tunnel(name, stage, error, monkeypatch):
    module = importlib.import_module("core.sandbox.tests." + name)
    owned = socket.socket()

    class Client:
        def settimeout(self, value):
            if stage == "settimeout":
                raise error("injected client failure")

        def sendall(self, data):
            if stage == "sendall":
                raise error("injected client failure")

        def recv(self, size):
            if stage == "recv":
                raise error("injected client failure")
            return b"" if stage == "eof" else (
                b"HTTP/1.1 502 Failed\r\n\r\n" if stage == "status"
                else b"HTTP/1.1 200 OK\r\n\r\n"
            )

        def close(self):
            owned.close()

    client = Client()
    proxy = SimpleNamespace(**vars(socket))
    proxy.create_connection = lambda *a, **kw: client
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", proxy)
            args = (1, "example.invalid:443") if name == TUNNELS[0] else (1, 2)
            if error is None:
                assert module._open_tunnel(*args) is client
                assert owned.fileno() != -1
            else:
                with pytest.raises(error):
                    module._open_tunnel(*args)
                assert owned.fileno() == -1, "failed tunnel leaked its client"
    finally:
        owned.close()


@pytest.mark.parametrize("stage", ["settimeout", "connect"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_unix_client_setup_closes_socket(stage, error, monkeypatch):
    from core.sandbox.tests import test_proxy_lanes as module

    owned = socket.socket()

    class Client:
        def settimeout(self, value):
            if stage == "settimeout":
                raise error("injected client failure")

        def connect(self, path):
            raise error("injected client failure")

        def close(self):
            owned.close()

    proxy = SimpleNamespace(**vars(socket))
    proxy.socket = lambda *a, **kw: Client()
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", proxy)
            with pytest.raises(error, match="injected client failure"):
                module._connect_unix("unused", "example.invalid:443")
        assert owned.fileno() == -1, "failed Unix connect leaked its client"
    finally:
        owned.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_reset_option_failure_still_closes_socket(error):
    from core.sandbox.tests import test_proxy_teardown as module

    owned = socket.socket()

    class Client:
        def setsockopt(self, *args):
            raise error("injected reset option failure")

        def close(self):
            owned.close()

    try:
        with pytest.raises(error, match="injected reset option failure"):
            module._rst_close(Client())
        assert owned.fileno() == -1, "reset option failure leaked its client"
    finally:
        owned.close()

"""Captive listener setup owns its socket before fallible configuration."""

import importlib
import socket
import threading
from types import SimpleNamespace

import pytest


CASES = [
    ("test_proxy_observability", "_serve_echo_forever"),
    ("test_proxy_teardown", "_serve_echo_forever"),
    ("test_proxy_upstream_errors", "_RstUpstream"),
    ("test_proxy_upstream_errors", "_HoldingUpstream"),
    ("test_proxy_upstream_gate2", "_FakeUpstream"),
]
STAGES = [
    (name, factory, stage)
    for name, factory in CASES
    for stage in (["bind", "listen", "getsockname", "server"]
                  if factory == "_serve_echo_forever"
                  else ["bind", "listen", "getsockname", "settimeout", "event"])
]


@pytest.mark.parametrize("name,factory,stage", STAGES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_listener_setup_failure_closes_owned_socket(name, factory, stage, error, monkeypatch):
    _exercise(name, factory, stage, error, monkeypatch)


@pytest.mark.parametrize("name,factory", CASES)
def test_successful_setup_transfers_listener(name, factory, monkeypatch):
    _exercise(name, factory, "none", None, monkeypatch)


def _exercise(name, factory, stage, error, monkeypatch):
    module = importlib.import_module("core.sandbox.tests." + name)
    real_socket = socket.socket
    real_event = threading.Event
    retained = []

    def fail():
        raise error("injected listener setup failure")

    class Listener:
        def __init__(self):
            self.sock = real_socket()
            retained.append(self)

        def __getattr__(self, key):
            if key == stage:
                return lambda *a, **kw: fail()
            return getattr(self.sock, key)

        def close(self):
            self.sock.close()

    class Server:
        def __init__(self, listener, handler):
            if stage == "server":
                fail()
            self.listener = listener

        def close(self):
            self.listener.close()

    proxy = SimpleNamespace(**vars(socket))
    proxy.socket = lambda *a, **kw: Listener()
    threads = SimpleNamespace(**vars(threading))
    threads.Event = fail if stage == "event" else real_event
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", proxy)
            patcher.setattr(module, "threading", threads, raising=False)
            if factory == "_serve_echo_forever":
                patcher.setattr(module, "SocketServer", Server)
            if error is not None:
                with pytest.raises(error, match="injected listener setup failure"):
                    getattr(module, factory)()
                assert retained and all(s.fileno() == -1 for s in retained), "listener leaked"
            else:
                result = getattr(module, factory)()
                assert len(retained) == 1 and retained[0].fileno() != -1
                if factory == "_serve_echo_forever":
                    port, close = result
                    assert port == retained[0].getsockname()[1]
                    close()
                else:
                    assert result.port == retained[0].getsockname()[1]
                    result.sock.close()
                assert retained[0].fileno() == -1
    finally:
        for listener in retained:
            listener.sock.close()

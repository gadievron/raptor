"""Actual keepalive caller fault tests leave the shared Thread factory alone."""
from contextlib import contextmanager
import socket
import threading
from types import FunctionType, ModuleType

import pytest

from core.testing.tests import test_progress_backend_ownership as native


@pytest.mark.parametrize("stage", ["proxy", "stop", "client"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_actual_keepalive_fault_scope_preserves_borrowed_bindings(monkeypatch, stage, error, outcome):
    listeners, publications = [], []
    missing = object()
    module, proxy = native.keepalive, native.progress.proxy_mod
    borrowed = {name: getattr(module, name) for name in ("socket", "SocketServer")}
    borrowed_threading = vars(module).get("threading", missing)
    borrowed_proxy = {name: getattr(proxy, name) for name in ("EgressProxy", "_enable_tcp_keepalive", "_ip_is_blocked")}
    borrowed_thread, borrowed_socket = threading.Thread, socket.socket
    original = native.test_keepalive_caller_releases_listener_and_client
    failure_type = {"normal": None, "error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]
    failure = failure_type("owned keepalive fault-scope boundary") if failure_type else None

    def create(*args, **kwargs):
        value = borrowed_socket(*args, **kwargs)
        listeners.append(value)
        return value

    private_socket = ModuleType("socket")
    vars(private_socket).update(vars(socket))
    private_socket.socket = create

    class Patch:
        @contextmanager
        def context(self):
            with monkeypatch.context() as actual:
                class Scope:
                    def __getattr__(self, name):
                        return getattr(actual, name)

                    def setattr(self, target, name, value, *args, **kwargs):
                        actual.setattr(target, name, value, *args, **kwargs)
                        publications.append((target, name))
                        assert threading.Thread is borrowed_thread

                yield Scope()
                assert threading.Thread is borrowed_thread
                assert module.socket is not borrowed["socket"]
                assert module.SocketServer is not borrowed["SocketServer"]
                assert vars(module).get("threading", missing) is borrowed_threading
                if failure is not None:
                    raise failure

    body = FunctionType(original.__code__, {**original.__globals__, "socket": private_socket})
    try:
        if failure is None:
            body(stage, error, Patch())
        else:
            with pytest.raises(failure_type) as caught:
                body(stage, error, Patch())
            assert caught.value is failure
        assert len(listeners) == 1 and listeners[0].fileno() == -1
        assert not any(target is threading for target, _ in publications)
        assert all(getattr(module, name) is value for name, value in borrowed.items())
        assert all(getattr(proxy, name) is value for name, value in borrowed_proxy.items())
        assert vars(module).get("threading", missing) is borrowed_threading
        assert threading.Thread is borrowed_thread and socket.socket is borrowed_socket
        assert native.test_keepalive_caller_releases_listener_and_client is original
    finally:
        for listener in listeners:
            listener.close()

"""Backend fault hooks preserve borrowed Thread factories throughout scope."""
from contextlib import contextmanager
import socket
import threading
from types import FunctionType, ModuleType

import pytest

from core.testing.tests import test_progress_backend_ownership as native


@pytest.mark.parametrize("kind", ["progress", "keepalive"])
@pytest.mark.parametrize("stage", ["bind", "listen", "getsockname", "server"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_actual_backend_fault_scope_preserves_borrowed_factory(monkeypatch, kind, stage, error, outcome):
    listeners, publications = [], []
    module = native.progress if kind == "progress" else native.keepalive
    missing = object()
    borrowed = (module.socket, module.SocketServer, vars(module).get("threading", missing))
    borrowed_thread, borrowed_socket = threading.Thread, socket.socket
    original = native.test_backend_setup_failure_closes_listener
    failure_type = {"normal": None, "error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]
    failure = failure_type("owned fault-scope boundary") if failure_type else None

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
                assert module.socket is not borrowed[0]
                assert module.SocketServer is not borrowed[1]
                assert vars(module).get("threading", missing) is borrowed[2]
                if failure is not None:
                    raise failure

    body = FunctionType(original.__code__, {**original.__globals__, "socket": private_socket})
    try:
        if failure is None:
            body(kind, stage, error, Patch())
        else:
            with pytest.raises(failure_type) as caught:
                body(kind, stage, error, Patch())
            assert caught.value is failure
        assert len(listeners) == 1 and listeners[0].fileno() == -1
        assert [name for target, name in publications if target is module] == ["socket", "SocketServer"]
        assert module.socket is borrowed[0] and module.SocketServer is borrowed[1]
        assert vars(module).get("threading", missing) is borrowed[2]
        assert threading.Thread is borrowed_thread and socket.socket is borrowed_socket
        assert native.test_backend_setup_failure_closes_listener is original
    finally:
        for listener in listeners:
            listener.close()

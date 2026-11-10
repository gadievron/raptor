"""The actual SocketServer regression caller owns its native setup socket."""
import socket
from types import FunctionType, ModuleType

import pytest

from core.testing.tests import test_socket_server_retirement as native


@pytest.mark.parametrize("phase", ["bind", "listen"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_listener_setup_failure_retires_socket(monkeypatch, phase, after, error):
    sockets, effects = [], []
    failure = error("owned listener fixture setup fault")
    original = native.test_constructor_failure_closes_listener
    borrowed_socket, borrowed_threads = socket.socket, native.module.threading

    class Listener:
        def __init__(self, raw):
            self.raw = raw

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def bind(self, *args, **kwargs):
            if phase == "bind" and not after:
                raise failure
            result = self.raw.bind(*args, **kwargs)
            effects.append("bind")
            if phase == "bind":
                raise failure
            return result

        def listen(self, *args, **kwargs):
            if not after:
                raise failure
            self.raw.listen(*args, **kwargs)
            effects.append("listen")
            raise failure

    def create(*args, **kwargs):
        raw = borrowed_socket(*args, **kwargs)
        sockets.append(raw)
        return Listener(raw)

    private = ModuleType("socket")
    vars(private).update(vars(socket))
    private.socket = create
    body = FunctionType(original.__code__, {**original.__globals__, "socket": private})
    try:
        with pytest.raises(error) as caught:
            body("Event", OSError, monkeypatch)
        assert caught.value is failure
        assert len(sockets) == 1
        assert sockets[0].fileno() == -1
        expected = ([] if not after else ["bind"]) if phase == "bind" else (["bind"] if not after else ["bind", "listen"])
        assert effects == expected
        assert socket.socket is borrowed_socket
        assert native.module.threading is borrowed_threads
        assert native.test_constructor_failure_closes_listener is original
    finally:
        for raw in sockets:
            raw.close()

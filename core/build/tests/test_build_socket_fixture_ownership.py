"""Native build-node socket fixtures close descriptors across bind faults."""

import builtins
import socket
from types import FunctionType, ModuleType

import pytest

from core.build.tests import test_build_artifact_lifecycle as native


@pytest.mark.parametrize("after,error", [(after, error) for after in (False, True)
                                        for error in (OSError, KeyboardInterrupt, SystemExit)]
                         + [(None, None)])
def test_native_socket_node_closes_on_bind_failure(tmp_path, after, error):
    sockets, closed = [], []
    failure = error("owned native bind failure") if error else None

    class Socket(socket.socket):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            sockets.append(self)

        def bind(self, address):
            if after or not error:
                super().bind(address)
            if error:
                raise failure

        def close(self):
            super().close()
            closed.append(self)

    view = ModuleType("socket")
    vars(view).update(vars(socket))
    view.socket = Socket

    def importing(name, *args, **kwargs):
        if name == "socket":
            return view
        return builtins.__import__(name, *args, **kwargs)

    original = native.test_cleanup_handles_each_owned_node_without_following_links
    namespace = dict(vars(native), __builtins__=dict(vars(builtins), __import__=importing))
    invoke = FunctionType(original.__code__, namespace, original.__name__,
                          original.__defaults__, original.__closure__)
    borrowed_factory = socket.socket
    try:
        if error:
            with pytest.raises(error) as caught:
                invoke(tmp_path, "socket")
            assert caught.value is failure
        else:
            invoke(tmp_path, "socket")
        assert len(sockets) == 1 and sockets[0].fileno() == -1
        assert closed == sockets
        assert socket.socket is borrowed_factory
        assert (tmp_path / "outside" / "keep").read_text() == "keep"
    finally:
        # Native closure is observed above. External safety closure retains
        # the actual object, never a stale descriptor number that may recycle.
        for owned in sockets:
            socket.socket.close(owned)

"""Actual helper-unwind test owns native sockets before event construction."""
import socket
import threading
from types import FunctionType, ModuleType

import pytest

from core.testing.tests import test_helper_unwind_cleanup as native


@pytest.mark.parametrize("position", [1, 2])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_socket_fixture_event_failure_retires_pair(monkeypatch, position, after, error):
    pairs, events, workers = [], [], []
    calls = 0
    failure = error("owned socket fixture event fault")
    original = native.test_socket_worker_unwind_joins_after_shutdown_failure
    borrowed_pair, borrowed_event, borrowed_thread = socket.socketpair, threading.Event, threading.Thread
    borrowed_helper_socket, borrowed_helper_threads = native.sockets.socket, native.sockets.threading

    def pair():
        value = borrowed_pair()
        pairs.append(value)
        return value

    def event(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == position:
            if after:
                events.append(borrowed_event(*args, **kwargs))
            raise failure
        value = borrowed_event(*args, **kwargs)
        events.append(value)
        return value

    def thread(*args, **kwargs):
        value = borrowed_thread(*args, **kwargs)
        workers.append(value)
        return value

    private_socket = ModuleType("socket")
    vars(private_socket).update(vars(socket))
    private_socket.socketpair = pair
    private_threads = ModuleType("threading")
    vars(private_threads).update(vars(threading))
    private_threads.Event, private_threads.Thread = event, thread
    body = FunctionType(original.__code__, {**original.__globals__, "socket": private_socket, "threading": private_threads})
    try:
        with pytest.raises(error) as caught:
            body("none", OSError, monkeypatch)
        assert caught.value is failure
        assert calls == position
        assert len(events) == position - 1 + int(after)
        assert workers == [], "setup fault reached worker construction"
        assert len(pairs) == 1
        assert all(stream.fileno() == -1 for stream in pairs[0])
        assert native.sockets.socket is borrowed_helper_socket
        assert native.sockets.threading is borrowed_helper_threads
        assert socket.socketpair is borrowed_pair
        assert threading.Event is borrowed_event and threading.Thread is borrowed_thread
        assert native.test_socket_worker_unwind_joins_after_shutdown_failure is original
    finally:
        for pair in pairs:
            for stream in pair:
                stream.close()

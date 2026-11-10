"""Native header-drip test owns its listener and returned server during setup."""
import builtins
import socket
import threading
import time
from types import FunctionType, ModuleType

import pytest

from core.env.tests import test_verify_engine as native


@pytest.mark.parametrize("phase", ["setsockopt", "bind", "listen", "getsockname", "event", "clock"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_watchdog_setup_fault_retires_native_owners(phase, after, error):
    listeners, servers, events, effects = [], [], [], []
    failure = error("owned header-drip fixture setup fault")
    original = native.test_http_exchange_watchdog_stops_dripping_headers
    borrowed_socket, borrowed_event, borrowed_clock = socket.socket, threading.Event, time.monotonic
    borrowed_server, borrowed_exchange, borrowed_import = native.SocketServer, native.ev._http_exchange, builtins.__import__
    fired = False

    def operation(name, action, *args, **kwargs):
        nonlocal fired
        if phase == name and not after:
            fired = True
            raise failure
        result = action(*args, **kwargs)
        effects.append(name)
        if phase == name:
            fired = True
            raise failure
        return result

    class Listener:
        def __init__(self, raw):
            self.raw = raw

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def setsockopt(self, *args, **kwargs):
            return operation("setsockopt", self.raw.setsockopt, *args, **kwargs)

        def bind(self, *args, **kwargs):
            return operation("bind", self.raw.bind, *args, **kwargs)

        def listen(self, *args, **kwargs):
            return operation("listen", self.raw.listen, *args, **kwargs)

        def getsockname(self):
            return operation("getsockname", self.raw.getsockname)

    def create(*args, **kwargs):
        raw = borrowed_socket(*args, **kwargs)
        listeners.append(raw)
        return Listener(raw)

    def server(*args, **kwargs):
        value = borrowed_server(*args, **kwargs)
        servers.append(value)
        return value

    def event(*args, **kwargs):
        def created():
            value = borrowed_event(*args, **kwargs)
            events.append(value)
            return value
        return operation("event", created)

    def clock():
        return operation("clock", borrowed_clock)

    private_socket = ModuleType("socket")
    vars(private_socket).update(vars(socket))
    private_socket.socket = create
    private_time = ModuleType("time")
    vars(private_time).update(vars(time))
    private_time.monotonic = clock
    private_threads = ModuleType("threading")
    vars(private_threads).update(vars(threading))
    private_threads.Event = event

    def imported(name, *args, **kwargs):
        replacements = {"socket": private_socket, "time": private_time, "threading": private_threads}
        return replacements[name] if name in replacements else borrowed_import(name, *args, **kwargs)

    body = FunctionType(original.__code__, {**original.__globals__, "SocketServer": server,
                                          "__builtins__": {**vars(builtins), "__import__": imported}})
    try:
        with pytest.raises(error) as caught:
            body()
        assert caught.value is failure and fired
        assert (phase in effects) is after
        assert len(listeners) == 1 and listeners[0].fileno() == -1
        assert len(servers) == int(phase == "clock")
        for value in servers:
            assert value._stop.is_set()
            assert not value._accept_thread.is_alive()
            assert all(not worker.is_alive() for worker in value._threads)
        if phase == "clock":
            assert len(events) == 1 and events[0].is_set()
        assert socket.socket is borrowed_socket
        assert threading.Event is borrowed_event and time.monotonic is borrowed_clock
        assert builtins.__import__ is borrowed_import
        assert native.SocketServer is borrowed_server and native.ev._http_exchange is borrowed_exchange
        assert native.test_http_exchange_watchdog_stops_dripping_headers is original
    finally:
        for value in servers:
            value.close()
        for raw in listeners:
            raw.close()

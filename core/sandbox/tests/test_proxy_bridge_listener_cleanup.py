"""Bridge listeners release socket ownership on every exit path."""

import os
import socket

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import _proxy_bridge as bridge


@pytest.mark.parametrize("exit_path", ["shutdown", "bind", "ready"])
def test_listener_objects_are_closed(tmp_path, monkeypatch, exit_path):
    real_socket = socket.socket
    listeners = []

    def tracked_socket(*args, **kwargs):
        sock = real_socket(*args, **kwargs)
        listeners.append(sock)
        return sock

    failure = RuntimeError("readiness failed")

    def ready(_):
        if exit_path == "ready":
            raise failure

    with real_socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        bridges = [(0, str(tmp_path / "unused.sock"))]
        if exit_path == "bind":
            bridges.append((occupied.getsockname()[1], "unused"))
        death_r, death_w = os.pipe()
        os.close(death_w)
        try:
            with monkeypatch.context() as patch:
                patch_module_attribute(patch, bridge, 'socket', "socket", tracked_socket)
                if exit_path == "shutdown":
                    bridge._run_bridges(bridges, death_r, ready_cb=ready)
                elif exit_path == "bind":
                    with pytest.raises(OSError):
                        bridge._run_bridges(bridges, death_r, ready_cb=ready)
                else:
                    with pytest.raises(RuntimeError) as raised:
                        bridge._run_bridges(bridges, death_r, ready_cb=ready)
                    assert raised.value is failure
            assert len(listeners) == (2 if exit_path == "bind" else 1)
            assert all(sock.fileno() == -1 for sock in listeners)
            # A fresh fd must remain valid when retained socket objects
            # are explicitly closed again (as their destructors would).
            with real_socket() as fresh:
                for listener in listeners:
                    listener.close()
                fresh.bind(("127.0.0.1", 0))
        finally:
            os.close(death_r)
            for listener in listeners:
                if listener.fileno() >= 0:
                    listener.close()

"""Cleanup failures must not leak controller resources or the process umask."""

import os
import socket
from types import SimpleNamespace

import pytest

from packages.joern.tests import broker_server


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("started", [False, True])
@pytest.mark.parametrize("fault", ["stop", "none"])
def test_stop_signal_failure_still_joins_and_closes(error, started, fault, monkeypatch):
    listener = socket.socket()
    calls = []

    def stop():
        calls.append("stop")
        if fault == "stop":
            raise error("injected stop failure")

    thread = SimpleNamespace(
        ident=1,
        start=lambda: calls.append("start"),
        join=lambda **kwargs: calls.append("join"),
        is_alive=lambda: False,
    )
    owner = SimpleNamespace(
        listener=listener,
        stopping=SimpleNamespace(set=stop),
        services=SimpleNamespace(close=lambda: calls.append("services")),
        serve=lambda: None,
    )
    monkeypatch.setattr(
        broker_server, "threading", SimpleNamespace(Thread=lambda **kwargs: thread)
    )

    def invoke():
        with broker_server.controller_server(owner) as start:
            if started:
                start()

    try:
        if fault == "stop":
            with pytest.raises(error, match="injected stop failure"):
                invoke()
        else:
            invoke()
        assert listener.fileno() == -1
        assert calls.count("services") == 1
        assert calls.count("join") == int(started)
    finally:
        listener.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("fault", ["create", "close", "mask-mismatch"])
def test_umask_probe_restores_original_after_failure(
    error, fault, monkeypatch, tmp_path
):
    from packages.joern.tests import test_netns_forwarder as module

    original = os.umask(0o027)
    listener = socket.socket()
    probe_mask = 0o027

    class Listener:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def close(self):
            listener.close()
            if fault == "close":
                raise error("injected listener failure")

    def create(path):
        if fault != "close":
            os.umask(0o077)
        if fault == "create":
            raise error("injected listener failure")
        return Listener()

    try:
        monkeypatch.setattr(module, "create_listener", create)
        expected = AssertionError if fault == "mask-mismatch" else error
        with pytest.raises(expected):
            module.TestListenerPermissions().test_umask_restored(str(tmp_path))
        observed = os.umask(probe_mask)
        assert observed == probe_mask, "failed probe leaked its changed umask"
        if fault != "create":
            assert listener.fileno() == -1
    finally:
        listener.close()
        os.umask(original)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_stop_failure_after_signal_joins_real_serving_thread(error):
    import threading

    event = threading.Event()
    listener = socket.socket()
    closed = []
    serving = None

    def stop():
        event.set()
        raise error("injected post-signal failure")

    owner = SimpleNamespace(
        listener=listener,
        stopping=SimpleNamespace(set=stop),
        services=SimpleNamespace(close=lambda: closed.append(True)),
        serve=event.wait,
    )
    try:
        with pytest.raises(error, match="injected post-signal failure"):
            with broker_server.controller_server(owner) as start:
                serving = start()
                assert serving.is_alive()
        assert not serving.is_alive()
        assert listener.fileno() == -1
        assert closed == [True]
    finally:
        event.set()
        if serving is not None and serving.ident is not None:
            serving.join(3)
        listener.close()

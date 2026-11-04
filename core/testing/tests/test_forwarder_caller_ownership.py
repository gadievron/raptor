"""Forwarder test setup and callers retire listeners, clients, and workers."""

import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from packages.joern.tests import test_netns_forwarder as module


CALLERS = [
    ("TestForwarderSplice", "test_roundtrip_with_half_close"),
    ("TestForwarderSplice", "test_concurrent_connections"),
    ("TestForwarderSplice", "test_large_response_splice"),
    ("TestForwarderStop", "test_stop_unlinks_socket_and_refuses_new_connections"),
    ("TestForwarderStop", "test_track_after_stop_refuses_and_closes"),
    ("TestForwarderStop", "test_handle_after_stop_returns_cleanly"),
    ("TestForwarderStop", "test_stop_closes_inflight_connections"),
]
CLIENTS = [
    CALLERS[0],
    CALLERS[2],
    CALLERS[-1],
    ("TestForwarderSplice", "test_upstream_down_drops_client"),
]


@pytest.mark.parametrize("owner,name", CALLERS)
@pytest.mark.parametrize("stage", ["forwarder", "stop"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_caller_failure_closes_upstream(
    owner, name, stage, error, tmp_path, monkeypatch
):
    upstream = Mock(port=1)
    forwarder = Mock()
    path = tmp_path / "joern.sock"
    path.touch()
    failure = error("injected caller setup failure")
    if stage == "stop":
        forwarder.stop.side_effect = failure
    threads = SimpleNamespace(**vars(threading))
    threads.Thread = Mock(side_effect=failure)
    with monkeypatch.context() as patcher:
        patcher.setattr(module, "_EchoServer", Mock(return_value=upstream))
        patcher.setattr(module, "_BlastServer", Mock(return_value=upstream))
        patcher.setattr(
            module,
            "_forwarder_to",
            Mock(
                side_effect=failure if stage == "forwarder" else None,
                return_value=(forwarder, str(path)),
            ),
        )
        patcher.setattr(module, "_uds_client", Mock(side_effect=failure))
        patcher.setattr(module, "threading", threads)
        with pytest.raises(error, match="injected caller setup failure"):
            getattr(getattr(module, owner)(), name)(str(tmp_path))
    assert upstream.close.called, "caller abandoned upstream cleanup"


@pytest.mark.parametrize("owner,name", CLIENTS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_client_io_failure_closes_client(owner, name, error, tmp_path, monkeypatch):
    owned = socket.socket()
    failure = error("injected client IO failure")
    client = Mock()
    client.sendall.side_effect = failure
    client.recv.side_effect = failure
    client.close.side_effect = owned.close
    upstream = Mock(port=1)
    forwarder = Mock()
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "_EchoServer", Mock(return_value=upstream))
            patcher.setattr(module, "_BlastServer", Mock(return_value=upstream))
            patcher.setattr(
                module, "_forwarder_to", Mock(return_value=(forwarder, "unused"))
            )
            patcher.setattr(module, "_uds_client", Mock(return_value=client))
            with pytest.raises(error, match="injected client IO failure"):
                getattr(getattr(module, owner)(), name)(str(tmp_path))
        assert owned.fileno() == -1, "caller left client open after IO failure"
    finally:
        owned.close()


@pytest.mark.parametrize(
    "name",
    [
        "test_track_after_stop_refuses_and_closes",
        "test_handle_after_stop_returns_cleanly",
    ],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_pair_close_failure_attempts_both_ends(name, error, tmp_path, monkeypatch):
    left, right = socket.socketpair()

    class Left:
        def close(self):
            left.close()
            raise error("injected pair close failure")

    class Right:
        def settimeout(self, value):
            right.settimeout(value)

        def recv(self, size):
            return b""

        def close(self):
            right.close()

    sockets = SimpleNamespace(**vars(socket))
    sockets.socketpair = lambda: (Left(), Right())
    forwarder = Mock()
    forwarder._track.side_effect = OSError("already stopped")
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", sockets)
            patcher.setattr(module, "_EchoServer", Mock(return_value=Mock(port=1)))
            patcher.setattr(
                module, "_forwarder_to", Mock(return_value=(forwarder, "unused"))
            )
            if error is KeyboardInterrupt:
                with pytest.raises(error, match="injected pair close failure"):
                    getattr(module.TestForwarderStop(), name)(str(tmp_path))
            else:
                getattr(module.TestForwarderStop(), name)(str(tmp_path))
        assert left.fileno() == right.fileno() == -1, "pair cleanup abandoned its peer"
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("stage", ["construct", "start"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_forwarder_setup_failure_releases_listener_and_path(
    stage, error, tmp_path, monkeypatch
):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    path = tmp_path / "joern.sock"
    listener.bind(str(path))
    listener.listen()
    failure = error("injected forwarder setup failure")
    forwarder = Mock()

    def stop():
        listener.close()
        path.unlink(missing_ok=True)

    forwarder.stop.side_effect = stop
    forwarder.start.side_effect = failure
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "create_listener", Mock(return_value=listener))
            patcher.setattr(
                module,
                "Forwarder",
                Mock(
                    side_effect=failure if stage == "construct" else None,
                    return_value=forwarder,
                ),
            )
            with pytest.raises(error, match="injected forwarder setup failure"):
                module._forwarder_to(1, str(tmp_path))
        assert listener.fileno() == -1, "setup left listener open"
        assert not path.exists(), "setup stranded the socket path"
    finally:
        stop()


@pytest.mark.parametrize("stage", ["settimeout", "connect"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_uds_client_setup_releases_socket(stage, error, monkeypatch):
    owned = socket.socket()
    client = Mock()
    getattr(client, stage).side_effect = error("injected UDS setup failure")
    client.close.side_effect = owned.close
    sockets = SimpleNamespace(**vars(socket))
    sockets.socket = lambda *a, **kw: client
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", sockets)
            with pytest.raises(error, match="injected UDS setup failure"):
                module._uds_client("unused")
        assert owned.fileno() == -1, "client setup leaked socket"
    finally:
        owned.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_real_forwarder_start_then_raise_retires_thread(error, tmp_path, monkeypatch):
    real_forwarder = module.Forwarder
    owners, workers = [], []

    class StartFailure(real_forwarder):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            owners.append(self)

        def start(self):
            super().start()
            workers.append(self._accept_thread)
            raise error("injected post-start failure")

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "Forwarder", StartFailure)
            with pytest.raises(error, match="injected post-start failure"):
                module._forwarder_to(1, str(tmp_path))
        assert owners and owners[0]._stopping.is_set(), (
            "failed helper did not stop forwarder"
        )
        assert not workers[0].is_alive()
        assert owners[0]._listener.fileno() == -1
        assert not (tmp_path / "joern.sock").exists()
    finally:
        for owner in owners:
            owner.stop()


@pytest.mark.parametrize("stage", ["before", "after"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_partial_client_thread_start_joins_every_started_worker(
    stage, error, tmp_path, monkeypatch
):
    real_thread = threading.Thread
    workers = []
    release = threading.Event()
    upstream = Mock(port=1)
    forwarder = Mock()
    forwarder.stop.side_effect = release.set

    def client(*args, **kwargs):
        state = {"payload": b""}
        owned = Mock()
        owned.sendall.side_effect = lambda payload: state.update(payload=payload)

        def recv(size):
            payload, state["payload"] = state["payload"], b""
            return payload

        owned.recv.side_effect = recv
        return owned

    def thread(*, target, args):
        entered = threading.Event()

        def run():
            try:
                target(*args)
            finally:
                entered.set()
                release.wait(3)

        worker = real_thread(target=run)
        start, join = worker.start, worker.join
        worker.join_attempted = False
        index = len(workers)

        def start_or_fail():
            if index == 1 and stage == "before":
                raise error("injected partial client start failure")
            start()
            assert entered.wait(2)
            if index == 1:
                raise error("injected partial client start failure")

        def joined(*args, **kwargs):
            worker.join_attempted = True
            return join(*args, **kwargs)

        worker.start, worker.join = start_or_fail, joined
        workers.append(worker)
        return worker

    threads = SimpleNamespace(**vars(threading))
    threads.Thread = thread
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", threads)
            patcher.setattr(module, "_EchoServer", Mock(return_value=upstream))
            patcher.setattr(
                module, "_forwarder_to", Mock(return_value=(forwarder, "unused"))
            )
            patcher.setattr(module, "_uds_client", client)
            with pytest.raises(error, match="injected partial client start failure"):
                module.TestForwarderSplice().test_concurrent_connections(str(tmp_path))
        started = [worker for worker in workers if worker.ident is not None]
        assert started and all(worker.join_attempted for worker in started), (
            "started client worker was never joined"
        )
        assert all(not worker.is_alive() for worker in started)
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                real_thread.join(worker, 3)


def test_concurrent_io_errors_close_every_owned_client(tmp_path, monkeypatch):
    real_thread = threading.Thread
    clients, workers = [], []
    lock = threading.Lock()

    class Client:
        def __init__(self):
            self.sock = socket.socket()
            with lock:
                clients.append(self)

        def sendall(self, data):
            raise OSError("injected concurrent client failure")

        def close(self):
            self.sock.close()

    def thread(*args, **kwargs):
        worker = real_thread(*args, **kwargs)
        workers.append(worker)
        return worker

    threads = SimpleNamespace(**vars(threading))
    threads.Thread = thread
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "threading", threads)
            patcher.setattr(module, "_EchoServer", Mock(return_value=Mock(port=1)))
            patcher.setattr(
                module, "_forwarder_to", Mock(return_value=(Mock(), "unused"))
            )
            patcher.setattr(module, "_uds_client", lambda *a, **kw: Client())
            with pytest.raises(AssertionError):
                module.TestForwarderSplice().test_concurrent_connections(str(tmp_path))
        assert len(clients) == len(workers) == 8
        assert all(client.sock.fileno() == -1 for client in clients), (
            "concurrent IO failure leaked clients"
        )
        assert all(not worker.is_alive() for worker in workers)
    finally:
        for worker in workers:
            if worker.ident is not None:
                worker.join(3)
        for client in clients:
            client.sock.close()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_join_cleanup_failure_attempts_every_started_thread(error):
    workers = [Mock(ident=1), Mock(ident=None), Mock(ident=2)]
    for worker in workers:
        worker.is_alive.return_value = False
    workers[0].join.side_effect = error("injected client join failure")
    with pytest.raises(error, match="injected client join failure"):
        module._join_started(workers)
    workers[0].join.assert_called_once()
    workers[1].join.assert_not_called()
    workers[2].join.assert_called_once()

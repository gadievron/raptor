"""Raw worker client creation and caller faults retain native socket ownership."""

import inspect
import json
import socket
from types import SimpleNamespace

import pytest

from core.llm.dispatcher.tests import test_orphan_cancel as native
from core.testing.module_bindings import patch_module_attribute

pytestmark = [pytest.mark.slow, pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix worker socket fixture")]

CALLERS = [
    ("TestOrphanCancel", "_drive_disconnect_mid_stream"),
    ("TestOrphanCancel", "test_worker_close_after_full_response_is_normal_completion"),
    ("TestOrphanCancel", "test_worker_close_during_post_body_dwell_is_normal_completion"),
    ("TestOrphanCancel", "test_final_chunk_is_held_until_watcher_stop_returns"),
    ("TestOrphanCancel", "test_worker_disconnect_during_head_dwell_aborts_at_head"),
    ("TestAcquireFailureRetiresWatcher", "test_acquire_raise_stops_watcher_and_writes_no_orphan_row"),
    ("TestWatcherAbortIsNotShardEvidence", "test_watcher_cancel_does_not_drain_the_shard"),
]


@pytest.fixture
def fake_creds():
    return native.fake_creds.__wrapped__()


@pytest.fixture
def peer(tmp_path):
    path = tmp_path / "peer"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(3)
            yield listener, path
    finally:
        path.unlink(missing_ok=True)


def _instrument(patch, *, stage=None, error=None, after=False):
    clients, reached = [], []
    failure = error("owned socket setup failure") if error else None

    class OwnedSocket(socket.socket):
        def _call(self, operation, call, *args):
            if stage == operation:
                reached.append(stage)
                if after:
                    call(*args)
                raise failure
            return call(*args)

        def settimeout(self, value):
            return self._call("settimeout", super().settimeout, value)

        def connect(self, address):
            return self._call("connect", super().connect, address)

        def sendall(self, data, *args):
            return self._call("sendall", super().sendall, data, *args)

    def create(*args, **kwargs):
        result = OwnedSocket(*args, **kwargs)
        clients.append(result)
        return result

    def serialize(*args, **kwargs):
        reached.append(stage)
        if after:
            json.dumps(*args, **kwargs)
        raise failure

    patch_module_attribute(patch, native, "socket", "socket", create)
    if stage == "serialize":
        patch_module_attribute(patch, native, "json", "dumps", serialize)
    return clients, reached, failure


@pytest.mark.parametrize("stage", ["settimeout", "connect", "serialize", "sendall"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before", "after"])
def test_startup_failure_closes_request_socket(stage, error, after, peer, monkeypatch):
    _, path = peer
    borrowed_socket, borrowed_json = native.socket, native.json
    clients = []
    try:
        with monkeypatch.context() as patch:
            clients, reached, failure = _instrument(patch, stage=stage, error=error, after=after)
            with pytest.raises(error) as caught:
                native._raw_worker_request(SimpleNamespace(socket_path=path), "fixture-token")
            assert caught.value is failure and reached == [stage]
            assert len(clients) == 1 and clients[0].fileno() == -1
        assert native.socket is borrowed_socket and native.json is borrowed_json
    finally:
        for client in clients:
            socket.socket.close(client)


def test_actual_missing_peer_closes_request_socket(tmp_path, monkeypatch):
    clients = []
    try:
        with monkeypatch.context() as patch:
            clients, _, _ = _instrument(patch)
            with pytest.raises(FileNotFoundError) as caught:
                native._raw_worker_request(SimpleNamespace(socket_path=tmp_path / "absent"), "fixture-token")
            assert caught.value.__traceback__ is not None
            assert len(clients) == 1 and clients[0].fileno() == -1
    finally:
        for client in clients:
            socket.socket.close(client)


def test_success_transfers_open_socket_and_exact_request(peer, monkeypatch):
    listener, path = peer
    clients = []
    try:
        with monkeypatch.context() as patch:
            clients, reached, _ = _instrument(patch)
            client = native._raw_worker_request(SimpleNamespace(socket_path=path), "fixture-token")
            assert clients == [client] and not reached
        assert client.fileno() >= 0 and client.gettimeout() == 10.0
        body = json.dumps({"model": "m", "messages": []}).encode()
        expected = (b"POST /anthropic/v1/messages HTTP/1.1\r\n"
                    b"Host: dispatcher\r\n"
                    + f"{native._TOKEN_HEADER}: fixture-token\r\n".encode()
                    + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        with listener.accept()[0] as remote:
            remote.settimeout(3)
            received = b""
            while len(received) < len(expected):
                chunk = remote.recv(len(expected) - len(received))
                assert chunk
                received += chunk
        assert received == expected
        client.close()
        assert client.fileno() == -1
    finally:
        for client in clients:
            socket.socket.close(client)


@pytest.mark.upstream_forward
@pytest.mark.parametrize("classname,method", CALLERS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_caller_body_failure_closes_transferred_socket(classname, method, error, fake_creds, tmp_path, monkeypatch):
    clients, reached = [], []
    failure = error("owned caller read boundary failure")
    original_request, original_upstream = native._raw_worker_request, native._CaptiveUpstream
    try:
        with monkeypatch.context() as patch:
            def request(*args, **kwargs):
                result = original_request(*args, **kwargs)
                clients.append(result)
                return result

            def fail(*args, **kwargs):
                reached.append(True)
                raise failure

            def upstream(*args, **kwargs):
                result = original_upstream(*args, **kwargs)
                if method == "test_worker_disconnect_during_head_dwell_aborts_at_head":
                    patch.setattr(result.request_seen, "wait", fail)
                return result

            patch.setattr(native, "_raw_worker_request", request)
            patch.setattr(native, "_recv_until", fail)
            patch.setattr(native, "_CaptiveUpstream", upstream)
            available = dict(fake_creds=fake_creds, tmp_path=tmp_path, monkeypatch=patch)
            invoke = getattr(getattr(native, classname)(), method)
            with pytest.raises(error) as caught:
                invoke(**{key: available[key] for key in inspect.signature(invoke).parameters})
            assert caught.value is failure and reached == [True]
        assert len(clients) == 1 and clients[0].fileno() == -1
    finally:
        for client in clients:
            client.close()

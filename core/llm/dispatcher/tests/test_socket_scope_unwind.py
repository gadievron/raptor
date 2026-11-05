"""Socket test scopes release later owners after acquisition or close errors."""

from contextlib import contextmanager
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.llm.dispatcher.tests import test_orphan_cancel as orphan
from core.sandbox.tests import test_parser_jail as parser
from core.sandbox.tests import test_parser_jail_io_reliability as parser_io
from core.sandbox.tests import test_pass_fds_socketpair as passing


_ORPHAN = [
    ("TestWorkerSocketDead", name)
    for name in (
        "test_silent_peer_is_alive",
        "test_closed_peer_is_dead",
        "test_peer_with_pending_data_is_alive",
        "test_closed_own_fd_is_dead",
    )
] + [
    ("TestCancelGuardIsStructural", name)
    for name in (
        "test_h1_with_socket_shuts_the_raw_socket",
        "test_h2_is_flag_only_and_socket_untouched",
        "test_empty_version_is_flag_only",
    )
]


@contextmanager
def _pair_fault(module, failure, position, monkeypatch):
    owned, failed = [], set()

    class OwnedSocket(socket.socket):
        def close(self):
            super().close()
            if (
                len(owned) > position
                and self is owned[position]
                and id(self) not in failed
            ):
                failed.add(id(self))
                raise failure

    def pair(*args, **kwargs):
        raw = socket.socketpair(*args, **kwargs)
        result = tuple(OwnedSocket(fileno=item.detach()) for item in raw)
        owned.extend(result)
        return result

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                module,
                "socket",
                SimpleNamespace(**(vars(socket) | {"socketpair": pair})),
            )
            yield owned, patcher
    finally:
        for item in owned:
            socket.socket.close(item)


@pytest.mark.parametrize("owner,name", _ORPHAN)
@pytest.mark.parametrize("position", [0, 1])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_orphan_pair_close_failure_releases_all_sockets(
    owner, name, position, error, monkeypatch
):
    failure = error("owned socket close failure")
    with _pair_fault(orphan, failure, position, monkeypatch) as (owned, patcher):
        with pytest.raises(error, match="owned socket close failure"):
            getattr(getattr(orphan, owner)(), name)()
        assert len(owned) >= 2
        assert all(item.fileno() == -1 for item in owned), (
            "pair teardown abandoned a socket"
        )


@pytest.mark.parametrize("stage", ["construct", "stop", "join", "close", "none"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_watcher_scope_attempts_stop_join_and_both_closes(stage, error, monkeypatch):
    failure = error("owned watcher failure")
    parent, peer = socket.socketpair()
    joined = []
    watcher = None
    real_watcher = orphan._OrphanWatcher
    failed = []

    class Parent:
        def close(self):
            parent.close()
            if stage == "close" and not failed:
                failed.append(True)
                raise failure

        def fileno(self):
            return parent.fileno()

        def recv(self, *args):
            return parent.recv(*args)

    def construct(*args, **kwargs):
        nonlocal watcher
        if stage == "construct":
            raise failure
        watcher = real_watcher(*args, **kwargs)
        stop, join = watcher.stop, watcher.join

        def stop_once():
            stop()
            if stage == "stop":
                raise failure

        def join_once():
            join()
            joined.append(True)
            if stage == "join":
                raise failure

        watcher.stop, watcher.join = stop_once, join_once
        return watcher

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                orphan,
                "socket",
                SimpleNamespace(
                    **(vars(socket) | {"socketpair": lambda: (Parent(), peer)})
                ),
            )
            patcher.setattr(orphan, "_OrphanWatcher", construct)
            with pytest.raises(error, match="owned watcher failure"):
                with orphan.TestCancelGuardIsStructural()._watcher():
                    raise failure
        assert parent.fileno() == peer.fileno() == -1, (
            "watcher teardown abandoned a socket"
        )
        if stage != "construct":
            assert joined == [True], "watcher teardown skipped its join"
            assert not watcher._thread.is_alive()
    finally:
        if watcher is not None:
            real_watcher.stop(watcher)
            real_watcher.join(watcher)
        parent.close()
        peer.close()


@pytest.mark.parametrize("position", [0, 1])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_parser_ready_error_closes_both_caller_sockets(position, error, monkeypatch):
    failure = error("owned socket close failure")
    with _pair_fault(parser_io, failure, position, monkeypatch) as (owned, patcher):
        with pytest.raises(error, match="owned socket close failure"):
            parser_io.test_decoder_recursion_failure_is_protocol_error(patcher, "ready")
        assert all(item.fileno() == -1 for item in owned), (
            "ready error teardown abandoned a socket"
        )


@pytest.mark.parametrize("interrupt_close", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_fake_worker_construction_retains_both_caller_sockets(
    interrupt_close, error, monkeypatch
):
    failure = error("owned socket close failure")
    setup_error = error("owned worker construction failure")
    position = 0 if interrupt_close else 99
    with _pair_fault(parser, failure, position, monkeypatch) as (owned, patcher):
        patcher.setattr(parser, "_FakeWorker", Mock(side_effect=setup_error))
        with pytest.raises(error):
            parser.TestFakeWorkerLifecycle().test_kill_wakes_blocked_read_with_peer_still_open(
                patcher
            )
        assert all(item.fileno() == -1 for item in owned), (
            "failed worker setup abandoned a caller socket"
        )


@pytest.mark.skipif(os.name != "posix", reason="owned Unix pathname sockets")
@pytest.mark.parametrize(
    "accepted,stage",
    [
        (accepted, stage)
        for accepted in (False, True)
        for stage in ("second-socket", "bind", "connect", "close", "accept")
        if accepted or stage != "accept"
    ],
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_pathname_fixture_owns_each_acquired_socket(
    accepted, stage, error, monkeypatch
):
    owned, failed = [], set()
    failure = error("owned pathname socket failure")

    class OwnedSocket(socket.socket):
        def bind(self, *args):
            if stage == "bind":
                raise failure
            return super().bind(*args)

        def connect(self, *args):
            if stage == "connect":
                raise failure
            return super().connect(*args)

        def accept(self):
            if stage == "accept":
                raise failure
            raw, address = super().accept()
            item = OwnedSocket(fileno=raw.detach())
            owned.append(item)
            return item, address

        def close(self):
            super().close()
            index = 2 if accepted else 1
            if (
                stage == "close"
                and len(owned) > index
                and self is owned[index]
                and id(self) not in failed
            ):
                failed.add(id(self))
                raise failure

    def acquire(*args, **kwargs):
        if stage == "second-socket" and len(owned) == 1:
            raise failure
        item = OwnedSocket(*args, **kwargs)
        owned.append(item)
        return item

    try:
        with tempfile.TemporaryDirectory(
            prefix="raptor-owned-path-", dir="/tmp"
        ) as raw:
            with monkeypatch.context() as patcher:
                patcher.setattr(
                    passing,
                    "socket",
                    SimpleNamespace(**(vars(socket) | {"socket": acquire})),
                )
                name = (
                    "test_pathname_accepted_side_refused"
                    if accepted
                    else "test_pathname_client_refused"
                )
                with pytest.raises(error, match="owned pathname socket failure"):
                    getattr(passing.TestRefusedShapes(), name)(Path(raw))
            assert owned
            assert all(item.fileno() == -1 for item in owned), (
                "pathname fixture abandoned an acquired socket"
            )
    finally:
        for item in owned:
            socket.socket.close(item)


@pytest.mark.skipif(os.name != "posix", reason="owned descriptor-transfer child")
@pytest.mark.parametrize("stage", ["spawn", "receive"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_descriptor_transfer_failure_reaps_child_and_closes_pair(
    stage, error, monkeypatch
):
    parent, child = socket.socketpair()
    processes = []
    failure = error("owned descriptor transfer failure")
    real_popen = subprocess.Popen

    def popen(*args, **kwargs):
        if stage == "spawn":
            raise failure
        # No descriptor-transfer payload is executed in the failure check.
        process = real_popen(
            [sys.executable, "-I", "-c", "import time; time.sleep(60)"],
            pass_fds=kwargs["pass_fds"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        processes.append(process)
        return process

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                passing,
                "socket",
                SimpleNamespace(
                    **(
                        vars(socket)
                        | {
                            "socketpair": lambda: (parent, child),
                            "recv_fds": Mock(side_effect=failure),
                        }
                    )
                ),
            )
            patcher.setattr(
                passing,
                "subprocess",
                SimpleNamespace(**(vars(subprocess) | {"Popen": popen})),
            )
            with pytest.raises(error, match="owned descriptor transfer failure"):
                passing.TestRefusedShapes().test_foreign_created_pair_refused()
        assert parent.fileno() == child.fileno() == -1, (
            "transfer failure abandoned a socketpair end"
        )
        for process in processes:
            assert process.returncode is not None, (
                "transfer failure left its child unreaped"
            )
            with pytest.raises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
            assert process.stdout.closed and process.stderr.closed
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
        parent.close()
        child.close()

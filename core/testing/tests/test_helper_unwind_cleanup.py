"""Pipe and socket-worker helpers finish cleanup after cleanup itself raises."""

import errno
import os
import socket
import threading
from types import SimpleNamespace

import pytest

from core.testing import pipes
from core.testing import sockets


def _identity(fd):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return None
        raise
    return stat.st_dev, stat.st_ino


@pytest.mark.parametrize("mode", ["body", "allocation", "fork"])
@pytest.mark.parametrize("position", range(4))
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, RuntimeError])
def test_pipe_unwind_attempts_every_descriptor(mode, position, error, monkeypatch):
    pairs, identities, closed = [], {}, []
    setup_error = LookupError("owned pipe setup failed")
    close_error = error("owned pipe close failed")

    def pipe():
        if mode == "allocation" and len(pairs) == 2:
            raise setup_error
        pair = os.pipe()
        pairs.append(pair)
        identities.update((fd, _identity(fd)) for fd in pair)
        return pair

    def close(fd):
        closed.append(fd)
        os.close(fd)
        if len(closed) == position + 1:
            raise close_error

    def fork():
        raise setup_error

    filesystem = SimpleNamespace(
        **(vars(os) | {"pipe": pipe, "close": close, "fork": fork})
    )
    try:
        monkeypatch.setattr(pipes, "os", filesystem)
        with pytest.raises(BaseException) as caught:
            if mode == "fork":
                pipes.fork_with_pipes(2)
            else:
                with pipes.pipes_for_setup(3 if mode == "allocation" else 2):
                    raise setup_error
        assert len(pairs) == 2
        assert all(_identity(fd) != identity for fd, identity in identities.items()), (
            "pipe unwind abandoned a later descriptor"
        )
        assert closed == [fd for pair in reversed(pairs) for fd in pair]
        assert caught.value is (setup_error if error is OSError else close_error)
    finally:
        for fd, identity in identities.items():
            if _identity(fd) == identity:
                os.close(fd)


@pytest.mark.parametrize("forked", [False, True])
def test_pipe_success_transfers_open_descriptors(forked, monkeypatch):
    pairs = []
    monkeypatch.setattr(
        pipes, "os", SimpleNamespace(**(vars(os) | {"fork": lambda: 123456}))
    )
    try:
        if forked:
            pid, pairs = pipes.fork_with_pipes(2)
            assert pid == 123456
        else:
            with pipes.pipes_for_setup(2) as acquired:
                pairs = acquired
        assert len(pairs) == 2
        for reader, writer in pairs:
            os.write(writer, b"owned")
            assert os.read(reader, 5) == b"owned"
    finally:
        for pair in pairs:
            for fd in pair:
                os.close(fd)


@pytest.mark.parametrize("stage", ["shutdown", "join", "none", "transfer"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, RuntimeError])
def test_socket_worker_unwind_joins_after_shutdown_failure(stage, error, monkeypatch):
    parent, original = socket.socketpair()
    adopted, workers, joined = [], [], []
    ready, finished = threading.Event(), threading.Event()
    setup_error = LookupError("owned socket setup failed")
    cleanup_error = error("owned socket cleanup failed")
    real_thread = threading.Thread

    class OwnedSocket(socket.socket):
        def shutdown(self, how):
            super().shutdown(how)
            if stage == "shutdown":
                raise cleanup_error

    def adopt(*args, **kwargs):
        instance = OwnedSocket(*args, **kwargs)
        adopted.append(instance)
        return instance

    def thread(*args, **kwargs):
        instance = real_thread(*args, **kwargs)
        workers.append(instance)
        join = instance.join

        def join_once(*args, **kwargs):
            joined.append(instance)
            result = join(*args, **kwargs)
            if stage == "join":
                raise cleanup_error
            return result

        instance.join = join_once
        return instance

    def invoke():
        with sockets.socket_worker_setup(original.fileno()) as (owned, start):

            def work():
                ready.set()
                try:
                    owned.recv(1)
                except OSError:
                    pass
                finally:
                    finished.set()

            start(work)
            assert ready.wait(3), "owned socket worker did not initialize"
            if stage != "transfer":
                raise setup_error

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                sockets, "socket", SimpleNamespace(**(vars(socket) | {"socket": adopt}))
            )
            patcher.setattr(
                sockets,
                "threading",
                SimpleNamespace(**(vars(threading) | {"Thread": thread})),
            )
            if stage == "transfer":
                invoke()
            else:
                with pytest.raises(BaseException) as caught:
                    invoke()
        assert len(adopted) == len(workers) == 1
        assert original.fileno() >= 0, "helper closed the caller's original socket"
        if stage == "transfer":
            assert adopted[0].fileno() >= 0
            assert workers[0].is_alive()
            assert joined == []
        else:
            assert joined == workers, "shutdown failure skipped joining the worker"
            assert not workers[0].is_alive()
            assert finished.is_set()
            assert adopted[0].fileno() == -1
            expected = (
                setup_error
                if stage == "none" or stage == "shutdown" and error is OSError
                else cleanup_error
            )
            assert caught.value is expected
    finally:
        # Bypass injected cleanup methods while containing baseline failures.
        for instance in adopted:
            try:
                socket.socket.shutdown(instance, socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            original.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=5)
        for instance in adopted:
            instance.close()
        parent.close()
        original.close()

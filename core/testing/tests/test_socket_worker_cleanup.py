"""Duplicated-socket test workers own startup and honest thread settlement."""

from contextlib import suppress
import errno
import importlib
import os
import socket
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

_KINDS = ("parser", "usage", "trickle")


def _module(kind):
    name = (
        "core.sandbox.tests.test_parser_jail"
        if kind == "parser"
        else "core.llm.dispatcher.tests.test_usage_scan_jail"
    )
    return importlib.import_module(name)


def _worker(module, kind, fd):
    if kind == "trickle":
        return module._TricklingWorker([], pass_fds=(fd,), gap_s=0.01)
    return module._FakeWorker(
        [], pass_fds=(fd,), ready=None, responder=lambda *args: False
    )


def _owned(fd, identity):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return False
        raise
    return (stat.st_dev, stat.st_ino) == identity


@pytest.mark.skipif(os.name != "posix", reason="owned socket-pair workers")
@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize(
    "fault", ["dup", "socket", "event", "construction", "start", "after-start"]
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_socket_worker_setup_releases_duplicate_and_thread(
    kind, fault, error, monkeypatch
):
    module = _module(kind)
    support = None
    with suppress(ModuleNotFoundError):
        support = importlib.import_module("core.testing.sockets")
    parent, child = socket.socketpair()
    duplicates, threads, joined, adopted = [], [], [], []
    real_dup, real_socket, real_thread = os.dup, socket.socket, threading.Thread
    real_join = threading.Thread.join

    def fail(*args, **kwargs):
        raise error("injected socket-worker setup failure")

    def dup(fd):
        if fault == "dup":
            return fail()
        result = real_dup(fd)
        stat = os.fstat(result)
        duplicates.append((result, (stat.st_dev, stat.st_ino)))
        return result

    def adopt_socket(*args, **kwargs):
        if fault == "socket":
            return fail()
        instance = real_socket(*args, **kwargs)
        # Retain the adopted object: destructor-driven cleanup must not mask
        # whether the fixture explicitly releases a failed startup.
        adopted.append(instance)
        return instance

    def thread(*args, **kwargs):
        if fault == "construction":
            return fail()
        owner = kwargs["target"].__self__

        def run():
            try:
                owner._sock.recv(1)
            except OSError:
                pass
            finally:
                owner._sock.close()
                owner._dead.set()

        instance = real_thread(target=run, daemon=True)
        threads.append(instance)
        start = instance.start

        def join(*args, **kwargs):
            joined.append(instance)
            return real_join(instance, *args, **kwargs)

        instance.join = join
        if fault == "start":
            instance.start = fail
        elif fault == "after-start":

            def after_start():
                start()
                fail()

            instance.start = after_start
        return instance

    os_proxy = SimpleNamespace(**(vars(os) | {"dup": dup}))
    socket_proxy = SimpleNamespace(**(vars(socket) | {"socket": adopt_socket}))
    threading_proxy = SimpleNamespace(
        **(
            vars(threading)
            | {"Thread": thread, "Event": fail if fault == "event" else threading.Event}
        )
    )
    try:
        with monkeypatch.context() as patcher:
            for target in (module, support):
                if target is not None:
                    if hasattr(target, "os"):
                        patcher.setattr(target, "os", os_proxy)
                    patcher.setattr(target, "socket", socket_proxy)
                    patcher.setattr(target, "threading", threading_proxy)
            with pytest.raises(error, match="injected socket-worker setup failure"):
                _worker(module, kind, child.fileno())
        assert len(duplicates) == (0 if fault == "dup" else 1)
        assert not any(_owned(fd, identity) for fd, identity in duplicates), (
            "worker setup stranded its duplicate"
        )
        assert all(not thread.is_alive() for thread in threads), (
            "worker setup left a thread running"
        )
        assert all(
            thread in joined for thread in threads if thread.ident is not None
        ), "worker setup skipped joining its started thread"
        assert child.fileno() >= 0, "worker closed the caller's original handle"
    finally:
        parent.close()
        child.close()
        for instance in threads:
            if instance.ident is not None:
                real_join(instance, timeout=5)
        for instance in adopted:
            instance.close()
        for fd, identity in duplicates:
            if _owned(fd, identity):
                os.close(fd)


@pytest.mark.skipif(os.name != "posix", reason="owned socket-pair workers")
@pytest.mark.parametrize("kind", _KINDS)
def test_successful_worker_transfers_duplicate_ownership(kind):
    module = _module(kind)
    parent, child = socket.socketpair()
    worker = None
    try:
        worker = _worker(module, kind, child.fileno())
        assert child.fileno() >= 0
        assert worker._sock.fileno() >= 0
        assert worker._sock.fileno() != child.fileno()
        assert worker._thread.is_alive()
    finally:
        parent.close()
        child.close()
        if worker is not None:
            worker.kill()
            worker.wait(timeout=2)
            assert not worker._thread.is_alive()


@pytest.mark.skipif(os.name != "posix", reason="owned blocked socket workers")
@pytest.mark.parametrize("kind", ["parser", "usage"])
def test_kill_wakes_blocked_worker_with_peer_open(kind, monkeypatch):
    module = _module(kind)
    entered, wake = threading.Event(), threading.Event()
    real_socket = socket.socket

    class Socket:
        def __init__(self, *args, **kwargs):
            self.socket = real_socket(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.socket, name)

        def recv(self, size):
            entered.set()
            assert wake.wait(5), "controlled receive was not released"
            raise OSError("controlled receive ended")

        def shutdown(self, how):
            self.socket.shutdown(how)
            wake.set()

    support = None
    with suppress(ModuleNotFoundError):
        support = importlib.import_module("core.testing.sockets")
    worker = None
    parent, child = socket.socketpair()
    try:
        with monkeypatch.context() as patcher:
            proxy = SimpleNamespace(**(vars(socket) | {"socket": Socket}))
            patcher.setattr(module, "socket", proxy)
            if support is not None:
                patcher.setattr(support, "socket", proxy)
            worker = _worker(module, kind, child.fileno())
            assert entered.wait(2)
            worker.kill()
            assert worker.wait(timeout=0.2) == 0
            assert not worker._thread.is_alive(), (
                "kill did not wake and settle the receiver"
            )
            assert worker.poll() == 0
            assert worker._sock.fileno() == -1
    finally:
        wake.set()
        parent.close()
        child.close()
        if worker is not None:
            worker._thread.join(2)
            worker._sock.close()


@pytest.mark.skipif(os.name != "posix", reason="owned responder threads")
@pytest.mark.parametrize("kind", ["parser", "usage"])
def test_wait_reports_live_responder_timeout(kind):
    module = _module(kind)
    entered, release = threading.Event(), threading.Event()
    parent, child = socket.socketpair()
    worker = None

    def responder(*args):
        entered.set()
        assert release.wait(5), "controlled responder was not released"
        return False

    try:
        worker = module._FakeWorker(
            [], pass_fds=(child.fileno(),), ready=None, responder=responder
        )
        parent.sendall(module.FRAME_HEADER.pack(0, 1))
        assert entered.wait(2)
        with pytest.raises(subprocess.TimeoutExpired):
            worker.wait(timeout=0.02)
        assert worker.poll() is None
    finally:
        release.set()
        parent.close()
        child.close()
        if worker is not None:
            worker.kill()
            worker.wait(timeout=2)
            assert not worker._thread.is_alive()


@pytest.mark.skipif(os.name != "posix", reason="owned paced worker thread")
def test_trickling_worker_poll_waits_for_actual_exit(monkeypatch):
    module = _module("trickle")
    entered, release = threading.Event(), threading.Event()
    parent, child = socket.socketpair()
    worker = None

    def sleep(seconds):
        entered.set()
        assert release.wait(5), "controlled trickler was not released"

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                module, "time", SimpleNamespace(**(vars(time) | {"sleep": sleep}))
            )
            worker = _worker(module, "trickle", child.fileno())
            assert entered.wait(2)
            worker.kill()
            assert worker.poll() is None, (
                "poll reported exit while the worker was still running"
            )
            with pytest.raises(subprocess.TimeoutExpired):
                worker.wait(timeout=0.02)
            release.set()
            assert worker.wait(timeout=2) == 0
            assert worker.poll() == 0
    finally:
        release.set()
        parent.close()
        child.close()
        if worker is not None:
            worker._thread.join(2)
            worker._sock.close()

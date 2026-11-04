"""Fake RPC hosts own descriptors and workers across partial setup."""

from contextlib import suppress
import errno
import importlib
import os
import sys
import threading
from types import SimpleNamespace

import pytest


def _owned(fd, identity):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return False
        raise
    return (stat.st_dev, stat.st_ino) == identity


@pytest.mark.skipif(sys.platform != "linux", reason="owned Linux pipe-host fixtures")
@pytest.mark.parametrize("kind", ["response", "ceiling"])
@pytest.mark.parametrize(
    "fault", ["second-pipe", "construction", "lock", "host", "start", "after-start"]
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_fake_host_setup_releases_all_resources(kind, fault, error, monkeypatch):
    from core.sandbox.tests import test_daemon_capture_caps as caps
    from core.sandbox.tests import test_host_response_reliability as response

    module = response if kind == "response" else caps
    support = None
    with suppress(ModuleNotFoundError):
        support = importlib.import_module("core.sandbox.tests.pipe_host")
    pairs, descriptors, threads, joined = [], [], [], []
    real_pipe = os.pipe
    real_thread, real_lock = threading.Thread, threading.Lock
    real_join = threading.Thread.join

    def fail(*args, **kwargs):
        raise error("injected pipe-host setup failure")

    def pipe():
        if fault == "second-pipe" and pairs:
            return fail()
        pair = real_pipe()
        pairs.append(pair)
        for fd in pair:
            stat = os.fstat(fd)
            descriptors.append((fd, (stat.st_dev, stat.st_ino)))
        return pair

    def controlled_worker():
        # Replace the original server loop in the failure matrix. EOF on our
        # request pipe is sufficient to stop this inert worker; it never runs
        # a sandbox command or builds a large response.
        try:
            while os.read(pairs[0][0], 4096):
                pass
        except OSError:
            pass
        finally:
            for fd in (pairs[0][0], pairs[1][1]):
                with suppress(OSError):
                    os.close(fd)

    def thread(*args, **kwargs):
        if fault == "construction":
            return fail()
        instance = real_thread(target=controlled_worker, daemon=True)
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

    proxy = SimpleNamespace(Thread=thread, Lock=fail if fault == "lock" else real_lock)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(os, "pipe", pipe)
            patcher.setattr(module, "threading", proxy, raising=False)
            if support is not None:
                patcher.setattr(support, "threading", proxy)
            if fault == "host":
                patcher.setattr(module.host_mod, "SandboxHost", fail)
            with pytest.raises(error, match="injected pipe-host setup failure"):
                if kind == "response":
                    module.fake_host(
                        lambda request: {"ok": True, "rid": request["rid"]}
                    )
                else:
                    module.TestParentReplyCeiling().test_parent_reads_frame_beyond_legacy_64mib()
        assert descriptors
        assert not any(_owned(fd, identity) for fd, identity in descriptors), (
            "failed host setup left pipe descriptors open"
        )
        assert all(not instance.is_alive() for instance in threads), (
            "failed host setup left a worker running"
        )
        assert all(
            instance in joined for instance in threads if instance.ident is not None
        ), "failed host setup did not join its started worker"
    finally:
        # Close only this fixture's original descriptors, and let the worker
        # release its own endpoints before the independent final sweep.
        if len(pairs) == 2:
            for fd in (pairs[0][1], pairs[1][0]):
                identity = next(
                    identity for number, identity in descriptors if number == fd
                )
                if _owned(fd, identity):
                    os.close(fd)
        for instance in threads:
            if instance.ident is not None:
                real_join(instance, timeout=5)
        for fd, identity in descriptors:
            if _owned(fd, identity):
                os.close(fd)


@pytest.mark.skipif(sys.platform != "linux", reason="owned high-descriptor fixture")
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_high_descriptor_fixture_restores_limits_after_close_failure(
    error, monkeypatch
):
    from core.sandbox.tests import test_host_response_reliability as module

    changes, hosts = [], []
    original = module.fake_host

    def host(*args):
        instance, thread, errors = original(*args)
        hosts.append(instance)
        close = instance.close

        def fail_close():
            close()
            raise error("injected host close failure")

        instance.close = fail_close
        return instance, thread, errors

    proxy = SimpleNamespace(
        RLIMIT_NOFILE=module.resource.RLIMIT_NOFILE,
        RLIM_INFINITY=module.resource.RLIM_INFINITY,
        getrlimit=lambda _: (1024, 4096),
        setrlimit=lambda _, limits: changes.append(limits),
    )
    with monkeypatch.context() as patcher:
        patcher.setattr(module, "fake_host", host)
        patcher.setattr(module, "resource", proxy)
        with pytest.raises(error, match="injected host close failure"):
            module.test_high_numbered_reply_descriptor_is_supported()
    assert changes == [(2049, 4096), (1024, 4096)], (
        "host close failure skipped restoring the resource limit"
    )
    assert hosts and all(not instance._thread.is_alive() for instance in hosts)


@pytest.mark.skipif(sys.platform != "linux", reason="owned EOF fixture pipes")
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_eof_fixture_setup_releases_pipes(error, monkeypatch):
    from core.sandbox.tests import test_host_response_reliability as module

    descriptors = []
    real_pipe = os.pipe

    def pipe():
        pair = real_pipe()
        for fd in pair:
            stat = os.fstat(fd)
            descriptors.append((fd, (stat.st_dev, stat.st_ino)))
        return pair

    class Host:
        def __setattr__(self, name, value):
            raise error("injected EOF host setup failure")

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(os, "pipe", pipe)
            patcher.setattr(module.host_mod, "SandboxHost", Host)
            with pytest.raises(error, match="injected EOF host setup failure"):
                module.test_reply_eof_wakes_poll_without_waiting_for_deadline()
        assert descriptors
        assert not any(_owned(fd, identity) for fd, identity in descriptors), (
            "EOF host setup leaked its pipe"
        )
    finally:
        for fd, identity in descriptors:
            if _owned(fd, identity):
                os.close(fd)


@pytest.mark.skipif(sys.platform != "linux", reason="owned pipe-host protocol")
@pytest.mark.parametrize("prefix", [b"", bytes([0, 0]), bytes([0, 0, 0, 10]) + b"{}"])
def test_pipe_host_stops_at_first_request_eof(prefix, monkeypatch):
    from core.sandbox.tests import pipe_host

    eof_reads = []
    real_read = os.read

    def read(fd, size):
        data = real_read(fd, size)
        if not data:
            eof_reads.append(fd)
            # Independently bound a regressed EOF spin in the worker.
            if len(eof_reads) > 1:
                raise OSError("controlled repeated EOF")
        return data

    with monkeypatch.context() as patcher:
        patcher.setattr(pipe_host, "os", SimpleNamespace(**(vars(os) | {"read": read})))
        host, thread, errors = pipe_host.fake_host(lambda request: {"ok": True})
        try:
            if prefix:
                os.write(host._write_fd, prefix)
            os.close(host._write_fd)
            host._write_fd = -1  # the test released this endpoint explicitly
            thread.join(timeout=2)
            assert not thread.is_alive()
            assert len(eof_reads) == 1
            assert len(errors) == 1 and isinstance(errors[0], EOFError)
        finally:
            host.close()


@pytest.mark.skipif(sys.platform != "linux", reason="owned pipe-host protocol")
def test_pipe_host_completes_fragmented_response_writes(monkeypatch):
    from core.sandbox.tests import pipe_host

    writes = []

    def write(fd, data):
        written = os.write(fd, data[:3])
        writes.append(written)
        return written

    with monkeypatch.context() as patcher:
        patcher.setattr(
            pipe_host, "os", SimpleNamespace(**(vars(os) | {"write": write}))
        )
        host, thread, errors = pipe_host.fake_host(
            lambda request: {"ok": True, "rid": request["rid"], "payload": "small"},
        )
        try:
            assert host._rpc({"cmd": "ping"}, timeout=2) == {
                "ok": True,
                "payload": "small",
            }
        finally:
            host.close()
        assert not thread.is_alive() and not errors
        assert len(writes) > 1 and all(0 < written <= 3 for written in writes)

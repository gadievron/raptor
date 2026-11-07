"""File-wrapper setup owns descriptors until successful handoff."""

from contextlib import contextmanager, suppress
import errno
import importlib
import os
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


@contextmanager
def _record_fds():
    entries = []

    def record(fd):
        stat = os.fstat(fd)
        entries.append((fd, (stat.st_dev, stat.st_ino)))
        return fd

    try:
        yield record, entries
    finally:
        for fd, identity in entries:
            if _owned(fd, identity):
                os.close(fd)


@pytest.mark.parametrize("fault", ["constructor", "label", "open"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_descriptor_argument_failure_closes_duplicate(
    fault, error, tmp_path, monkeypatch
):
    from core.binary.tests import test_elf_worker as module
    from core.binary import _elf_worker_child as child

    with _record_fds() as (record, entries):
        real_dup = os.dup

        def dup(fd):
            return record(real_dup(fd))

        def fail(*args, **kwargs):
            raise error("injected descriptor handoff failure")

        with monkeypatch.context() as patcher:
            patcher.setattr(os, "dup", dup)
            if fault == "constructor":
                patcher.setattr(child, "_DescriptorInput", fail)
            elif fault == "label":
                patcher.setattr(child._DescriptorInput, "__fspath__", fail)
            else:
                patcher.setattr(module, "open", fail, raising=False)
            with pytest.raises(error, match="injected descriptor handoff failure"):
                module.test_descriptor_input_reads_pinned_inode_without_reopening_alias(
                    tmp_path
                )
        assert entries and not any(_owned(fd, identity) for fd, identity in entries), (
            "wrapper setup left its duplicate open"
        )


def test_descriptor_argument_does_not_close_a_reused_slot(tmp_path, monkeypatch):
    from core.binary.tests import test_elf_worker as module

    borrowed = []
    real_open = open

    class Stream:
        def __init__(self, fd, *args, **kwargs):
            self.stream = real_open(fd, *args, **kwargs)

        def __enter__(self):
            return self.stream

        def __exit__(self, *args):
            fd = self.stream.fileno()
            self.stream.__exit__(*args)
            new_fd = os.open(tmp_path / "other-owner", os.O_CREAT | os.O_WRONLY, 0o600)
            borrowed.append(new_fd)
            if new_fd != fd:
                pytest.skip("descriptor was not naturally reused")

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "open", Stream, raising=False)
            module.test_descriptor_input_reads_pinned_inode_without_reopening_alias(
                tmp_path
            )
        os.write(borrowed[0], b"still owned")
        assert (tmp_path / "other-owner").read_bytes() == b"still owned"
    finally:
        for fd in borrowed:
            os.close(fd)


_MODULES = {
    "gate": "core.sandbox.tests.test_seatbelt_audit_warmup_io",
    "cleanup": "core.sandbox.tests.test_seatbelt_audit_warmup_cleanup",
}


@contextmanager
def _warmup_resources(kind, fault, error, tmp_path, monkeypatch):
    module = importlib.import_module(_MODULES[kind])
    support = None
    with suppress(ModuleNotFoundError):
        support = importlib.import_module("core.testing.streams")
    fixture = None
    streams = []
    real_pipe, real_fdopen = os.pipe, os.fdopen

    with _record_fds() as (record, entries):

        def pipe():
            pair = real_pipe()
            for fd in pair:
                record(fd)
            return pair

        class Stream:
            def __init__(self, stream, mode):
                self.stream, self.mode = stream, mode

            def __getattr__(self, name):
                return getattr(self.stream, name)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

            def close(self):
                self.stream.close()
                if fault == "close" and self.mode == "r":
                    raise error("injected stream fixture failure")

        def fdopen(fd, mode, *args, **kwargs):
            if (fault == "reader" and mode == "r") or (
                fault == "writer" and mode == "wb"
            ):
                raise error("injected stream fixture failure")
            wrapped = Stream(real_fdopen(fd, mode, *args, **kwargs), mode)
            # Strong references keep destructor cleanup from masking a leak.
            streams.append(wrapped)
            return wrapped

        def fail(*args, **kwargs):
            raise error("injected stream fixture failure")

        try:
            with monkeypatch.context() as patcher:
                proxy = SimpleNamespace(**(vars(os) | {"pipe": pipe, "fdopen": fdopen}))
                patcher.setattr(module, "os", proxy, raising=False)
                if support is not None:
                    patcher.setattr(support, "os", proxy)
                if fault == "mock":
                    patcher.setattr(module, "Mock", fail)
                if fault == "write":
                    proxy.write = fail

                def setattr_fixture(target, name, value, *, raising=True):
                    if fault == "patch" and name == "_find_sandbox_binary":
                        fail()
                    return patcher.setattr(target, name, value, raising=raising)

                fixture_patcher = SimpleNamespace(
                    setattr=setattr_fixture, setitem=patcher.setitem,
                )
                if kind in ("gate", "cleanup"):
                    function = module.gate if kind == "gate" else module.warmup_setup
                    fixture = function.__wrapped__(tmp_path, fixture_patcher)
                yield SimpleNamespace(
                    module=module, fixture=fixture, streams=streams, entries=entries
                )
            assert not any(_owned(fd, identity) for fd, identity in entries), (
                "stream fixture left a pipe endpoint open"
            )
        finally:
            if fixture is not None:
                with suppress(OSError, KeyboardInterrupt):
                    fixture.close()
            for wrapped in streams:
                wrapped.stream.close()


@pytest.mark.parametrize("kind", ["gate", "cleanup"])
@pytest.mark.parametrize("fault", ["reader", "mock", "patch", "close"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_warmup_fixture_setup_and_close_own_both_pipe_ends(
    kind, fault, error, tmp_path, monkeypatch
):
    with _warmup_resources(kind, fault, error, tmp_path, monkeypatch) as state:
        with pytest.raises(error, match="injected stream fixture failure"):
            next(state.fixture)
            state.fixture.close()


@pytest.mark.parametrize("kind", ["gate", "cleanup"])
def test_warmup_fixture_abort_closes_streams(kind, tmp_path, monkeypatch):
    with _warmup_resources(kind, "none", OSError, tmp_path, monkeypatch) as state:
        next(state.fixture)
        state.fixture.close()
        assert state.streams and all(s.closed for s in state.streams)


@pytest.mark.parametrize("fault", ["reader", "write"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_unterminated_line_setup_failure_closes_pipe(
    fault, error, tmp_path, monkeypatch
):
    with _warmup_resources("gate", fault, error, tmp_path, monkeypatch) as state:
        with pytest.raises(error, match="injected stream fixture failure"):
            state.module.test_final_unterminated_line_is_preserved(tmp_path)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_writer_adoption_failure_closes_both_ends(tmp_path, monkeypatch, error):
    with _warmup_resources("gate", "writer", error, tmp_path, monkeypatch) as state:
        with pytest.raises(error):
            next(state.fixture)
        assert not any(_owned(fd, identity) for fd, identity in state.entries)

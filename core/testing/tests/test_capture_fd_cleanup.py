"""Capture rollback and independent descriptor teardown own every handle."""

from contextlib import contextmanager
import errno
import fcntl
import os
import resource
from types import SimpleNamespace

import pytest

from core.testing.pipes import pipes_for_setup


def _owned(fd, identity):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return False
        raise
    return (stat.st_dev, stat.st_ino) == identity


@contextmanager
def _native_high_limit(minimum):
    prior = resource.getrlimit(resource.RLIMIT_NOFILE)
    setter = resource.setrlimit
    soft, hard = prior
    if hard != resource.RLIM_INFINITY and hard <= minimum:
        pytest.skip("host hard limit prevents staging the high descriptor")
    wanted = minimum + 64 if hard == resource.RLIM_INFINITY else min(minimum + 64, hard)
    try:
        if soft != resource.RLIM_INFINITY and soft < wanted:
            setter(resource.RLIMIT_NOFILE, (wanted, hard))
        yield
    finally:
        setter(resource.RLIMIT_NOFILE, prior)


@contextmanager
def _descriptors():
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


@pytest.mark.parametrize("prior_call", [False, True])
@pytest.mark.parametrize("position", [1, 2])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_capture_dup_failure_rolls_back_only_current_call(
    prior_call, position, error, monkeypatch
):
    from core.sandbox import _spawn
    from core.sandbox.tests import test_capture_post_exit_drain as module

    with _descriptors() as (record, entries):

        def create():
            with pipes_for_setup(2) as pairs:
                for pair in pairs:
                    for fd in pair:
                        record(fd)
                return (*pairs[0], *pairs[1])

        calls = []
        failing_call = position + (2 if prior_call else 0)

        def dup(fd):
            calls.append(fd)
            if len(calls) == failing_call:
                raise error("injected capture duplicate failure")
            return record(os.dup(fd))

        fixture = None
        try:
            with monkeypatch.context() as patcher:
                patcher.setattr(_spawn, "_open_capture_pipes", create)
                patcher.setattr(
                    module, "os", SimpleNamespace(**(vars(os) | {"dup": dup}))
                )
                fixture = module.retained_write_ends.__wrapped__(patcher)
                holders = next(fixture)
                if prior_call:
                    for fd in _spawn._open_capture_pipes():
                        os.close(fd)  # successful call transferred these to us
                prior = list(holders)
                with pytest.raises(error, match="injected capture duplicate failure"):
                    _spawn._open_capture_pipes()
                assert holders == prior, "failed capture retained a partial duplicate"
                assert all(
                    _owned(fd, identity) for fd, identity in entries if fd in prior
                )
                assert not any(
                    _owned(fd, identity) for fd, identity in entries if fd not in prior
                ), "failed capture leaked current pipe endpoints"
                with pytest.raises(StopIteration):
                    next(fixture)
            assert not any(_owned(fd, identity) for fd, identity in entries)
        finally:
            if fixture is not None:
                fixture.close()


@pytest.mark.parametrize("finish", ["close", "interrupt", "normal"])
def test_capture_fixture_closes_retained_fds_on_every_exit(finish, monkeypatch):
    from core.sandbox import _spawn
    from core.sandbox.tests import test_capture_post_exit_drain as module

    with _descriptors() as (record, entries):

        def create():
            with pipes_for_setup(2) as pairs:
                for pair in pairs:
                    for fd in pair:
                        record(fd)
                return (*pairs[0], *pairs[1])

        def dup(fd):
            return record(os.dup(fd))

        fixture = None
        try:
            with monkeypatch.context() as patcher:
                patcher.setattr(_spawn, "_open_capture_pipes", create)
                patcher.setattr(
                    module, "os", SimpleNamespace(**(vars(os) | {"dup": dup}))
                )
                fixture = module.retained_write_ends.__wrapped__(patcher)
                holders = next(fixture)
                original = _spawn._open_capture_pipes()
                assert len(holders) == 2
                for fd in original:
                    os.close(fd)
                if finish == "close":
                    fixture.close()
                elif finish == "interrupt":
                    with pytest.raises(KeyboardInterrupt):
                        fixture.throw(KeyboardInterrupt())
                else:
                    with pytest.raises(StopIteration):
                        next(fixture)
            assert not any(_owned(fd, identity) for fd, identity in entries), (
                "fixture exit left retained capture endpoints open"
            )
        finally:
            if fixture is not None:
                fixture.close()


_BRIDGE = [
    ("test_high_numbered_descriptor_is_readable", role)
    for role in ("high", "read", "write", "dup")
]
_BRIDGE += [
    ("test_closed_writer_wakes_reader", "write"),
    ("test_writable_and_timeout", "read"),
    ("test_invalid_descriptor_reports_ebadf", "read"),
]


@pytest.mark.parametrize("name,fault", _BRIDGE)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_bridge_cleanup_continues_after_close_failure(name, fault, error, monkeypatch):
    from core.sandbox.tests import test_proxy_bridge_poll as module

    roles, changes = {}, []
    with _native_high_limit(2048), _descriptors() as (record, entries):

        def pipe():
            pair = os.pipe()
            for role, fd in zip(("read", "write"), pair):
                roles[fd] = role
                record(fd)
            return pair

        def duplicate(fd, op, minimum):
            if fault == "dup":
                raise error("injected bridge cleanup failure")
            result = record(fcntl.fcntl(fd, op, minimum))
            roles[result] = "high"
            return result

        def close(fd):
            os.close(fd)
            if roles.get(fd) == fault:
                raise error("injected bridge cleanup failure")

        limits = SimpleNamespace(
            RLIMIT_NOFILE=resource.RLIMIT_NOFILE,
            RLIM_INFINITY=resource.RLIM_INFINITY,
            getrlimit=lambda _: (1024, 4096),
            setrlimit=lambda _, value: changes.append(value),
        )
        with monkeypatch.context() as patcher:
            patcher.setattr(
                module,
                "os",
                SimpleNamespace(**(vars(os) | {"pipe": pipe, "close": close})),
            )
            patcher.setattr(module, "resource", limits)
            patcher.setattr(
                module, "fcntl", SimpleNamespace(F_DUPFD=fcntl.F_DUPFD, fcntl=duplicate)
            )
            with pytest.raises(error, match="injected bridge cleanup failure"):
                getattr(module, name)()
        assert not any(_owned(fd, identity) for fd, identity in entries), (
            "one close failure skipped another pipe endpoint"
        )
        if name == "test_high_numbered_descriptor_is_readable":
            assert changes[-1] == (1024, 4096), (
                "close failure skipped restoring the descriptor limit"
            )


@pytest.mark.parametrize("fault", ["keeper", "cli"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_config_descriptor_is_reclaimed_when_setup_or_cli_fails(
    fault, error, tmp_path, monkeypatch
):
    from core.sandbox.tests import test_evidence as module
    from core.sandbox import tracer

    real_anonymous = module.ev.anonymous_fd
    with _descriptors() as (record, entries):

        def anonymous(*args, **kwargs):
            return record(real_anonymous(*args, **kwargs))

        def dup(fd):
            if fault == "keeper":
                raise error("injected config descriptor failure")
            return record(os.dup(fd))

        def fail(*args):
            raise error("injected config descriptor failure")

        with monkeypatch.context() as patcher:
            patcher.setattr(module.ev, "anonymous_fd", anonymous)
            patcher.setattr(module, "os", SimpleNamespace(**(vars(os) | {"dup": dup})))
            if fault == "cli":
                patcher.setattr(tracer, "_cli_main", fail)
            with pytest.raises(error, match="injected config descriptor failure"):
                module.TestTracerFdConfigConsumption().test_cli_reads_fd_path_config_and_closes_fd(
                    tmp_path, patcher
                )
        assert not any(_owned(fd, identity) for fd, identity in entries), (
            "config failure left its pinned descriptor open"
        )


def test_config_cleanup_preserves_a_reused_descriptor(tmp_path, monkeypatch):
    from core.sandbox.tests import test_evidence as module
    from core.sandbox import tracer

    originals, borrowed = [], []
    real_anonymous = module.ev.anonymous_fd

    def anonymous(*args, **kwargs):
        fd = real_anonymous(*args, **kwargs)
        originals.append(fd)
        return fd

    def cli(*args):
        os.close(originals[0])
        fd = os.open(tmp_path / "other-owner", os.O_CREAT | os.O_WRONLY, 0o600)
        borrowed.append(fd)
        if fd != originals[0]:
            pytest.skip("descriptor was not naturally reused")
        tracer.trace(
            1, str(tmp_path), audit_filter={"verbose": True, "observe_mode": False}
        )
        return 0

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module.ev, "anonymous_fd", anonymous)
            patcher.setattr(tracer, "_cli_main", cli)
            module.TestTracerFdConfigConsumption().test_cli_reads_fd_path_config_and_closes_fd(
                tmp_path, patcher
            )
        os.write(borrowed[0], b"still owned")
        assert (tmp_path / "other-owner").read_bytes() == b"still owned"
    finally:
        for fd in borrowed:
            os.close(fd)


@pytest.mark.parametrize("fault", ["reader", "writer", "duplicate"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_symbolic_frame_cleanup_closes_both_streams(fault, error, monkeypatch):
    from core.symbolic.tests import test_isolate as module

    original = module._pipe_pair
    real_fcntl = fcntl.fcntl
    pairs, duplicates, changes = [], [], []

    class Connection:
        def __init__(self, connection, role):
            self.connection, self.role = connection, role

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def close(self):
            self.connection.close()
            if self.role == fault:
                raise error("injected symbolic cleanup failure")

    def pair():
        reader, writer = original()
        pairs.append((reader, writer))
        return Connection(reader, "reader"), Connection(writer, "writer")

    def duplicate(fd, op, *args):
        result = real_fcntl(fd, op, *args)
        if op == fcntl.F_DUPFD:
            duplicates.append(result)
        return result

    def close(fd):
        os.close(fd)
        if fault == "duplicate" and fd in duplicates:
            raise error("injected symbolic cleanup failure")

    with _native_high_limit(1100):
        try:
            with monkeypatch.context() as patcher:
                patcher.setattr(module, "_pipe_pair", pair)
                patcher.setattr(
                    module, "os", SimpleNamespace(**(vars(os) | {"close": close}))
                )
                patcher.setattr(fcntl, "fcntl", duplicate)
                patcher.setattr(
                    resource, "setrlimit", lambda _, value: changes.append(value)
                )
                with pytest.raises(error, match="injected symbolic cleanup failure"):
                    module.test_high_fd_frame_read_bounded_past_fd_setsize()
            assert pairs and all(
                reader.closed and writer.closed for reader, writer in pairs
            ), "one stream close failure skipped its peer"
            assert changes, "symbolic cleanup skipped restoring the descriptor limit"
        finally:
            for reader, writer in pairs:
                reader.close()
                writer.close()

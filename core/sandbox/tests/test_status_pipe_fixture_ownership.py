"""The existing status test owns setup failures without retrying consumed FDs."""
from contextlib import contextmanager
import errno
import os
from types import FunctionType, ModuleType

import pytest

from core.sandbox import _spawn
from core.sandbox.tests import test_setup_status_read_errors as native
from core.testing.pipes import pipes_for_setup


def _same(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


def _exercise(tmp_path, phase=None, error=None, after=False, recycle=False):
    identities, pairs, sentinels = {}, [], {}
    failure = error("owned status fixture fault") if error else None
    fired = False
    original = native.test_real_pipe_confirmation_followed_by_exec_failure
    borrowed_pipe, borrowed_write, borrowed_close = os.pipe, os.write, os.close
    borrowed_drain = _spawn._drain_status_pipe

    def pipe():
        pair = borrowed_pipe()
        pairs.append(pair)
        for fd in pair:
            stat = os.fstat(fd)
            identities[fd] = (stat.st_dev, stat.st_ino)
        return pair

    def write(fd, data):
        nonlocal fired
        if phase == "write":
            fired = True
            if after:
                borrowed_write(fd, data)
            raise failure
        return borrowed_write(fd, data)

    def close(fd):
        nonlocal fired
        borrowed_close(fd)
        if phase == "writer-close" and not fired and fd == pairs[0][1]:
            fired = True
            raise failure

    def drain(fd, owned):
        nonlocal fired
        result = borrowed_drain(fd, owned)
        assert result == ("X", "exec failed") and fd not in owned
        if phase == "drain":
            fired = True
            if recycle:
                replacement = os.open(tmp_path / "later-owner", os.O_CREAT | os.O_WRONLY, 0o600)
                if replacement != fd:
                    os.dup2(replacement, fd)
                    borrowed_close(replacement)
                stat = os.fstat(fd)
                sentinels[fd] = (stat.st_dev, stat.st_ino)
            raise failure
        return result

    private_os = ModuleType("os")
    vars(private_os).update(vars(os))
    private_os.pipe, private_os.write, private_os.close = pipe, write, close
    guard = pipes_for_setup.__wrapped__
    private_guard = contextmanager(FunctionType(guard.__code__, {**guard.__globals__, "os": private_os}))
    private_spawn = ModuleType("_spawn")
    vars(private_spawn).update(vars(_spawn))
    private_spawn._drain_status_pipe = drain
    body = FunctionType(original.__code__, {**original.__globals__, "os": private_os,
                                          "_spawn": private_spawn, "pipes_for_setup": private_guard})
    try:
        if error:
            with pytest.raises(error) as caught:
                body()
            assert caught.value is failure
            assert fired
        else:
            body()
        assert len(pairs) == 1 and len(identities) == 2
        assert all(not _same(fd, identity) for fd, identity in identities.items())
        assert len(sentinels) == int(recycle)
        for fd, identity in sentinels.items():
            assert _same(fd, identity)
            borrowed_write(fd, b"still owned")
        if recycle:
            assert (tmp_path / "later-owner").read_bytes() == b"still owned"
        assert os.pipe is borrowed_pipe and os.write is borrowed_write and os.close is borrowed_close
        assert _spawn._drain_status_pipe is borrowed_drain
        assert native.test_real_pipe_confirmation_followed_by_exec_failure is original
    finally:
        for fd, identity in {**identities, **sentinels}.items():
            if _same(fd, identity):
                borrowed_close(fd)


@pytest.mark.parametrize("phase,after,recycle", [("write", False, False), ("write", True, False),
                                                ("writer-close", False, False), ("drain", False, False),
                                                ("drain", False, True)])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_status_fixture_fault_preserves_ownership(tmp_path, phase, after, recycle, error):
    _exercise(tmp_path, phase, error, after, recycle)


def test_actual_status_fixture_positive_control(tmp_path):
    _exercise(tmp_path)

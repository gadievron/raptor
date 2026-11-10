"""Emulated control fixture directory descriptors have setup ownership.

These are real native directory FDs over ordinary temporary files, not
kernel cgroup enforcement or a native cgroup profile.
"""
import errno
import os
from types import FunctionType, ModuleType

import pytest

from core.security.tests import test_cgroup_scope as native


def _same_descriptor(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


def _exercise(tmp_path, phase, position, error, after=False):
    opened = []
    failure = error("owned fixture allocation fault") if error else None
    fired = False
    original = native.scope.__wrapped__
    native_scope = native.cgroup_scope.Scope

    def open_directory(*args, **kwargs):
        nonlocal fired
        if phase == "open" and len(opened) == position:
            fired = True
            raise failure
        fd = os.open(*args, **kwargs)
        stamp = os.fstat(fd)
        opened.append((fd, (stamp.st_dev, stamp.st_ino)))
        return fd

    class Constructor(native_scope):
        def __init__(self, *args, **kwargs):
            nonlocal fired
            fired = True
            if after:
                super().__init__(*args, **kwargs)
            raise failure

    private_os = ModuleType("os")
    vars(private_os).update(vars(os))
    private_os.open = open_directory
    private_scope = ModuleType("cgroup_scope")
    vars(private_scope).update(vars(native.cgroup_scope))
    if phase == "constructor":
        private_scope.Scope = Constructor
    body = FunctionType(original.__code__, {**original.__globals__, "os": private_os, "cgroup_scope": private_scope})
    generator = body(tmp_path)
    try:
        if phase in ("open", "constructor"):
            with pytest.raises(error) as caught:
                next(generator)
            assert caught.value is failure
            assert fired
        else:
            result = next(generator)
            assert isinstance(result, native_scope)
            assert len(opened) == 2
            assert all(_same_descriptor(fd, identity) for fd, identity in opened)
            result.attach(123)
            assert (result.path / "cgroup.procs").read_text() == "123"
            if error:
                with pytest.raises(error) as caught:
                    generator.throw(failure)
                assert caught.value is failure
            else:
                with pytest.raises(StopIteration):
                    next(generator)
        assert len(opened) == (position if phase == "open" else 2)
        assert all(not _same_descriptor(fd, identity) for fd, identity in opened)
        assert native.cgroup_scope.Scope is native_scope
        assert native.scope.__wrapped__ is original
    finally:
        generator.close()
        for fd, identity in opened:
            if _same_descriptor(fd, identity):
                os.close(fd)


@pytest.mark.parametrize("position", [0, 1])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_directory_allocation_failure_retires_prior_fd(tmp_path, position, error):
    _exercise(tmp_path, "open", position, error)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_constructor_refusal_retires_both_directory_fds(tmp_path, after, error):
    _exercise(tmp_path, "constructor", None, error, after)


@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt, SystemExit])
def test_native_emulated_fixture_lifetime(tmp_path, error):
    _exercise(tmp_path, "body", None, error)

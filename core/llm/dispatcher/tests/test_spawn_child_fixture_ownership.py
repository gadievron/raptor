"""Actual spawn cleanup test reaps its owned native child on wait failure."""
import errno
import os
import subprocess

import pytest

from core.llm.dispatcher import spawn
from core.llm.dispatcher.tests import test_spawn_fd_cleanup as native
from core.testing.module_bindings import patch_module_attribute
from core.testing.processes import reap_on_exit


def _same_descriptor(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


def _exercise(error=None, after=False):
    children, tokens = [], []
    failure = error("owned native child wait fault") if error else None
    fired = False
    borrowed_popen = subprocess.Popen
    borrowed_binding = spawn.subprocess
    original = native.test_successful_spawn_still_closes_token_fd

    class Child(borrowed_popen):
        def wait(self, *args, **kwargs):
            nonlocal fired
            if error is not None and not fired:
                fired = True
                if after:
                    super().wait(*args, **kwargs)
                raise failure
            return super().wait(*args, **kwargs)

    def popen(*args, **kwargs):
        assert len(kwargs["pass_fds"]) == 1
        fd = kwargs["pass_fds"][0]
        current = os.fstat(fd)
        tokens.append((fd, (current.st_dev, current.st_ino)))
        child = Child(*args, **kwargs)
        children.append(child)
        return child

    with pytest.MonkeyPatch.context() as scope:
        patch_module_attribute(scope, spawn, "subprocess", "Popen", popen)
        try:
            if error:
                with pytest.raises(error) as caught:
                    original()
                assert caught.value is failure
                assert fired
            else:
                original()
            assert len(children) == len(tokens) == 1
            child = children[0]
            assert child.returncode is not None
            with pytest.raises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
            assert all(not _same_descriptor(fd, identity) for fd, identity in tokens)
            assert subprocess.Popen is borrowed_popen
            assert native.test_successful_spawn_still_closes_token_fd is original
        finally:
            for child in children:
                with reap_on_exit(child):
                    pass
                assert child.returncode is not None
    assert spawn.subprocess is borrowed_binding


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_native_child_reaped_when_actual_wait_fails(error, after):
    _exercise(error, after)


def test_native_spawn_positive_control():
    _exercise()

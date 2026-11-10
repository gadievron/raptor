"""Actual token-pipe fixture owns native setup and consumed descriptors."""
from contextlib import contextmanager
import errno
import os
from types import FunctionType, ModuleType

import pytest

from core.llm.dispatcher.tests import test_spawn_fd_cleanup as native


def _same_descriptor(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


@pytest.mark.parametrize("name", ["test_popen_failure_closes_token_fd", "test_successful_spawn_still_closes_token_fd"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_actual_pipe_factory_refusal_retires_both_native_ends(name, error, after):
    pairs, identities = [], {}
    failure = error("owned dispatcher mock construction refused")
    original_helper = native._dispatcher_with_real_pipe
    original_caller = getattr(native, name)
    original_factory = native.MagicMock
    def pipe():
        pair = os.pipe()
        pairs.append(pair)
        for fd in pair:
            current = os.fstat(fd)
            identities[fd] = (current.st_dev, current.st_ino)
        return pair
    def factory():
        if after:
            original_factory()
        raise failure
    private = ModuleType("os")
    vars(private).update(vars(os))
    private.pipe = pipe
    support = native.pipes_for_setup.__wrapped__
    private_pipes = contextmanager(FunctionType(support.__code__, {**support.__globals__, "os": private}))
    generator = original_helper.__wrapped__
    helper = contextmanager(FunctionType(generator.__code__, {**generator.__globals__, "pipes_for_setup": private_pipes, "MagicMock": factory}))
    body = FunctionType(original_caller.__code__, {**original_caller.__globals__, "_dispatcher_with_real_pipe": helper})
    try:
        with pytest.raises(error) as caught:
            body()
        assert caught.value is failure
        assert len(pairs) == 1
        assert all(not _same_descriptor(fd, identities[fd]) for fd in pairs[0])
        assert native.MagicMock is original_factory
        assert native._dispatcher_with_real_pipe is original_helper
        assert getattr(native, name) is original_caller
    finally:
        for pair in pairs:
            for fd in pair:
                if _same_descriptor(fd, identities[fd]):
                    os.close(fd)


def test_consumed_fixture_descriptor_replacement_is_preserved(tmp_path):
    replacements = []
    try:
        with native._dispatcher_with_real_pipe() as (_dispatcher, token_fd):
            current = os.fstat(token_fd)
            identity = (current.st_dev, current.st_ino)
            os.close(token_fd)
            fd = os.open(tmp_path / "replacement", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            current = os.fstat(fd)
            replacement = (current.st_dev, current.st_ino)
            replacements.append((fd, replacement))
            assert fd == token_fd, "native control did not reuse the consumed descriptor"
            assert replacement != identity
            os.write(fd, b"independent replacement")
        assert _same_descriptor(fd, replacement)
        os.lseek(fd, 0, os.SEEK_SET)
        assert os.read(fd, 128) == b"independent replacement"
    finally:
        for fd, identity in replacements:
            if _same_descriptor(fd, identity):
                os.close(fd)

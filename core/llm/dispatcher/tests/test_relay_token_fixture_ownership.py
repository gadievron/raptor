"""Actual relay token test closes both native pipe ends on setup failure."""
import errno
import os
from types import FunctionType, ModuleType

import pytest

from core.llm.dispatcher.tests import test_relay_limits as native


def _same_descriptor(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


@pytest.mark.parametrize("fault", ["read", "decode"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_actual_token_setup_write_failure_retires_both_ends(fault, error, after):
    pairs, identities = [], {}
    failure = error("owned token setup write fault")
    original = native.test_failed_token_read_closes_descriptor
    borrowed_os = native.os
    native_write = os.write
    def pipe():
        pair = os.pipe()
        pairs.append(pair)
        for fd in pair:
            current = os.fstat(fd)
            identities[fd] = (current.st_dev, current.st_ino)
        return pair
    def write(*args):
        if after:
            native_write(*args)
        raise failure
    private = ModuleType("os")
    vars(private).update(vars(os))
    private.pipe, private.write = pipe, write
    body = FunctionType(original.__code__, {**original.__globals__, "os": private})
    with pytest.MonkeyPatch.context() as patch:
        try:
            with pytest.raises(error) as caught:
                body(patch, fault)
            assert caught.value is failure
            assert len(pairs) == 1
            assert all(not _same_descriptor(fd, identities[fd]) for fd in pairs[0])
            assert os.write is native_write
            assert native.os is borrowed_os
            assert native.test_failed_token_read_closes_descriptor is original
        finally:
            for pair in pairs:
                for fd in pair:
                    if _same_descriptor(fd, identities[fd]):
                        os.close(fd)

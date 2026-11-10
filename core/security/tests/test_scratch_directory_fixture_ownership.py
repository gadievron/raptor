"""Actual scratch-record test setup retires its native directory descriptor."""
import errno
import os
from types import FunctionType, ModuleType

import pytest

from core.security.tests import test_scratch_write_lifecycle as native


CASES = [
    ("test_failed_adoption_retires_descriptor_and_temporary", {}),
    ("test_primary_failure_keeps_previous_record_and_retires_owned_state", {"phase": "write", "error_type": OSError}),
    ("test_success_syncs_file_then_published_directory", {}),
    ("test_directory_sync_failure_does_not_remove_published_record", {}),
]


def _same_descriptor(fd, identity):
    try:
        current = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (current.st_dev, current.st_ino) == identity


@pytest.mark.parametrize("name,extra", CASES)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_actual_setup_failure_retires_directory_fd(tmp_path, name, extra, error, after):
    opened, publications = [], []
    failure = error("owned instrumentation publication refused")
    original = getattr(native, name)
    borrowed_os = native.lifecycle.os
    native_open = os.open
    def open_directory(*args, **kwargs):
        fd = native_open(*args, **kwargs)
        if args[1] & os.O_DIRECTORY:
            stat = os.fstat(fd)
            opened.append((fd, (stat.st_dev, stat.st_ino)))
        return fd
    def install(*args, **kwargs):
        if after:
            native.patch_module_attribute(*args, **kwargs)
            publications.append(native.lifecycle.os)
            assert native.lifecycle.os is not borrowed_os
        raise failure
    private = ModuleType("os")
    vars(private).update(vars(os))
    private.open = open_directory
    body = FunctionType(original.__code__, {**original.__globals__, "os": private, "patch_module_attribute": install})
    with pytest.MonkeyPatch.context() as patch:
        try:
            with pytest.raises(error) as caught:
                body(tmp_path, patch, **extra)
            assert caught.value is failure
            assert len(opened) == 1
            assert len(publications) == int(after)
            assert all(not _same_descriptor(fd, identity) for fd, identity in opened)
            assert os.open is native_open
            assert getattr(native, name) is original
        finally:
            for fd, identity in opened:
                if _same_descriptor(fd, identity):
                    os.close(fd)
    assert native.lifecycle.os is borrowed_os

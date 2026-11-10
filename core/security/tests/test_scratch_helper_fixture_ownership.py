"""Native directory ownership in the actual adjacent-helper failure test."""
import errno
import os
from types import FunctionType, ModuleType

import pytest

from core.security.tests import test_scratch_writer_setup as native


def _same_descriptor(fd, identity):
    try:
        actual = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return False
    return (actual.st_dev, actual.st_ino) == identity


@pytest.mark.parametrize("boundary", ["direct", "module"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_actual_helper_setup_refusal_retires_directory(tmp_path, boundary, after, error):
    opened, publications = [], []
    failure = error("owned helper publication refused")
    original = native.test_record_writer_helper_failure_allocates_no_file
    borrowed_scratch, borrowed_os = native.scratch_lifecycle.scratch, native.scratch_lifecycle.os
    native_open = os.open
    def open_directory(*args, **kwargs):
        fd = native_open(*args, **kwargs)
        stamp = os.fstat(fd)
        opened.append((fd, (stamp.st_dev, stamp.st_ino)))
        return fd
    private = ModuleType("os")
    vars(private).update(vars(os))
    private.open = open_directory
    with pytest.MonkeyPatch.context() as patch:
        class Patch:
            def setattr(self, *args, **kwargs):
                if boundary == "direct":
                    if after:
                        patch.setattr(*args, **kwargs)
                        publications.append(native.scratch_lifecycle.scratch)
                        assert native.scratch_lifecycle.scratch is not borrowed_scratch
                    raise failure
                patch.setattr(*args, **kwargs)
            def setitem(self, *args, **kwargs):
                patch.setitem(*args, **kwargs)
        def install(*args, **kwargs):
            if after:
                native.patch_module_attribute(*args, **kwargs)
                publications.append(native.scratch_lifecycle.os)
                assert native.scratch_lifecycle.os is not borrowed_os
            raise failure
        body = FunctionType(original.__code__, {**original.__globals__, "os": private, "patch_module_attribute": install})
        try:
            with pytest.raises(error) as caught:
                body(tmp_path, Patch())
            assert caught.value is failure
            assert len(opened) == 1 and len(publications) == int(after)
            assert all(not _same_descriptor(fd, identity) for fd, identity in opened)
            assert os.open is native_open
            assert native.test_record_writer_helper_failure_allocates_no_file is original
        finally:
            for fd, identity in opened:
                if _same_descriptor(fd, identity):
                    os.close(fd)
    assert native.scratch_lifecycle.scratch is borrowed_scratch
    assert native.scratch_lifecycle.os is borrowed_os

"""Result read cancellation survives a consuming descriptor-close failure."""
import errno
import os
import stat
from types import SimpleNamespace

import pytest

from core.audit import prepared_result_retention as module
from core.audit.sweep import SweepResult
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("failure_owner", ["file", "directory", "root"])
def test_retained_result_read_preserves_primary_interrupt_and_retires_descriptor(tmp_path, failure_owner):
    result = SweepResult(tool="smt", file_path="unit.c", function_name="Read",
                         outcome="inconclusive", rule_id="smt:check-overflow",
                         details={"existing_result": True})
    reference = module.retain_smt_result(tmp_path, result)
    before = (tmp_path / reference).read_bytes()
    primary = KeyboardInterrupt("owned result read interrupted")
    secondary = OSError(errno.EIO, "owned result consuming close failed")
    reads, regular_closes, directory_closes = [], [], []
    original_read, original_close = os.read, os.close

    def read(fd, amount):
        assert stat.S_ISREG(os.fstat(fd).st_mode)
        reads.append(fd)
        raise primary

    def close(fd):
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
        original_close(fd)
        if regular:
            regular_closes.append(fd)
            if failure_owner == "file":
                raise secondary
        elif reads:
            directory_closes.append(fd)
            if len(directory_closes) == (1 if failure_owner == "directory" else 2) and failure_owner != "file":
                raise secondary

    private_os = SimpleNamespace(**{**vars(os), "read": read, "close": close})
    view = module_function_view(module, bindings={"os": private_os})
    returned, caught = None, None
    try:
        returned = view.retained_smt_result_matches(tmp_path, reference, result)
    except BaseException as error:
        caught = error
    assert len(reads) == len(regular_closes) == 1
    assert len(directory_closes) == 2
    for retired in [*regular_closes, *directory_closes]:
        with pytest.raises(OSError) as closed:
            os.fstat(retired)
        assert closed.value.errno == errno.EBADF
    assert (tmp_path / reference).read_bytes() == before
    assert os.read is original_read and os.close is original_close
    assert returned is None
    assert caught is primary


def test_directory_walk_retires_successor_after_consuming_parent_close_error(tmp_path):
    primary = OSError(errno.EIO, "owned parent directory consuming close failed")
    original_open, original_close = os.open, os.close
    opened, closes, live = [], [], set()

    def open_fd(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        live.add(fd)
        return fd

    def close(fd):
        assert fd in opened
        closes.append(fd)
        original_close(fd)
        live.remove(fd)
        if len(closes) == 1:
            raise primary

    private_os = SimpleNamespace(**{**vars(os), "open": open_fd, "close": close})
    view = module_function_view(module, bindings={"os": private_os})
    try:
        with pytest.raises(OSError) as caught:
            view._open_output_directory(tmp_path)
        assert caught.value is primary
        assert len(opened) == len(closes) == 2 and len(set(closes)) == 2
        for fd in opened:
            with pytest.raises(OSError) as closed:
                os.fstat(fd)
            assert closed.value.errno == errno.EBADF
        assert os.open is original_open and os.close is original_close
    finally:
        # A regression must not leak the intentionally faulted test's descriptors.
        for fd in live:
            original_close(fd)

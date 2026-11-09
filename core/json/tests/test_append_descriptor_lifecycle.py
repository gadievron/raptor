"""Append teardown preserves the primary operation and consumes its descriptor."""

import errno
import json
import os
from itertools import product

import pytest

from core.json import jsonl
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def trail_writer(tmp_path, monkeypatch):
    path = tmp_path / "trail.jsonl"
    retained, closed = [], []
    real_open, real_close, real_write, real_fstat = os.open, os.close, os.write, os.fstat

    def install(stage, primary, cleanup):
        def opened(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            info = real_fstat(fd)
            retained.append((fd, (info.st_dev, info.st_ino)))
            return fd

        def fstat(fd):
            if stage == "fstat":
                raise primary
            return real_fstat(fd)

        def write(fd, data):
            if stage == "write":
                raise primary
            if stage == "zero":
                return 0
            return real_write(fd, data)

        def close(fd):
            real_close(fd)
            closed.append(fd)
            raise cleanup

        patch_module_attribute(monkeypatch, jsonl, "os", "open", opened)
        patch_module_attribute(monkeypatch, jsonl, "os", "fstat", fstat)
        patch_module_attribute(monkeypatch, jsonl, "os", "write", write)
        patch_module_attribute(monkeypatch, jsonl, "os", "close", close)
        return path, retained, closed

    yield install
    for fd, identity in retained:
        try:
            info = real_fstat(fd)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == identity:
            real_close(fd)


_CASES = [
    pytest.param(stage, primary, cleanup, id=f"{stage}-{primary.__name__}-{cleanup.__name__}")
    for stage, primary, cleanup in product(
        ["fstat", "write"], [OSError, RuntimeError, KeyboardInterrupt, SystemExit], [OSError, RuntimeError],
    )
]


@pytest.mark.parametrize("stage,primary_type,cleanup_type", _CASES)
def test_primary_error_survives_descriptor_cleanup(trail_writer, stage, primary_type, cleanup_type):
    primary = primary_type("append failed")
    path, retained, closed = trail_writer(stage, primary, cleanup_type("close failed"))
    with pytest.raises(primary_type) as caught:
        jsonl.append_jsonl(path, {"owned": True})
    assert caught.value is primary
    assert len(retained) == 1 and closed == [retained[0][0]]
    with pytest.raises(OSError) as gone:
        os.fstat(retained[0][0])
    assert gone.value.errno == errno.EBADF
    assert path.read_bytes() == b""


@pytest.mark.parametrize("cleanup_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_successful_append_still_reports_new_close_error(trail_writer, cleanup_type):
    cleanup = cleanup_type("close failed")
    path, retained, closed = trail_writer("success", None, cleanup)
    with pytest.raises(cleanup_type) as caught:
        jsonl.append_jsonl(path, {"owned": True})
    assert caught.value is cleanup
    assert json.loads(path.read_text()) == {"owned": True}
    assert len(retained) == 1 and closed == [retained[0][0]]


def test_zero_progress_error_is_preserved_during_close_failure(trail_writer):
    path, retained, closed = trail_writer("zero", None, OSError("close failed"))
    with pytest.raises(OSError, match="short write"):
        jsonl.append_jsonl(path, {"owned": True})
    assert len(retained) == 1 and closed == [retained[0][0]]

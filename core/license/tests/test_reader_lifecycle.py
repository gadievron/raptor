"""Licence stream setup retires owned descriptors on interruption."""
import errno
import os

import pytest

from core.license import detector
from core.source import gated
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_failed_stream_setup_closes_descriptor(tmp_path, monkeypatch, error_type):
    path = tmp_path / "LICENSE"
    path.write_bytes(b"MIT License\n")
    retained = []
    original_open = os.open
    primary = error_type("owned stream setup interruption")

    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        info = os.fstat(fd)
        retained.append((fd, (info.st_dev, info.st_ino)))
        return fd

    def fail(*args, **kwargs):
        raise primary

    try:
        with scoped_function_imports(detector, ["_read_license_full"], {"os": os}) as owned:
            monkeypatch.setattr(owned.os, "open", opened)
            monkeypatch.setattr(owned.os, "fdopen", fail)
            patch_module_attribute(monkeypatch, gated, "os", "open", opened)
            patch_module_attribute(monkeypatch, gated, "os", "fdopen", fail)
            with pytest.raises(error_type) as caught:
                detector._read_license_full(path, 4)
            assert caught.value is primary
            assert len(retained) == 1
            with pytest.raises(OSError) as closed:
                os.fstat(retained[0][0])
            assert closed.value.errno == errno.EBADF
    finally:
        for fd, identity in retained:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)


@pytest.mark.parametrize("cap", [0, 1, 4, 100])
def test_regular_file_keeps_prefix_and_decode_contract(tmp_path, cap):
    path = tmp_path / "LICENSE"
    raw = b"MIT\xff License\n"
    path.write_bytes(raw)
    assert detector._read_license_full(path, cap) == raw[:cap].decode("utf-8", errors="replace")


def test_missing_file_stays_best_effort(tmp_path):
    assert detector._read_license_full(tmp_path / "missing", 100) == ""


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_read_error_keeps_precedence_over_close_failure(tmp_path, error_type):
    path = tmp_path / "LICENSE"
    path.write_bytes(b"MIT License\n")
    primary = error_type("owned licence read failure")
    handles = []

    class Stream:
        def __init__(self, stream):
            self.stream = stream
            self.closed = False
        def __enter__(self):
            return self
        def read(self, count):
            assert count == 4
            raise primary
        def __exit__(self, *args):
            self.stream.close()
            self.closed = True
            raise OSError("secondary close failure")

    def opened(*args, **kwargs):
        stream = Stream(gated.open_regular_gated(*args, **kwargs))
        handles.append(stream)
        return stream

    with scoped_function_imports(detector, ["_read_license_full"], {"core.source.gated": gated}) as owned:
        getattr(owned, "core.source.gated").open_regular_gated = opened
        if error_type is OSError:
            assert detector._read_license_full(path, 4) == ""
        else:
            with pytest.raises(error_type) as caught:
                detector._read_license_full(path, 4)
            assert caught.value is primary
    assert len(handles) == 1 and handles[0].closed
    assert handles[0].stream.closed

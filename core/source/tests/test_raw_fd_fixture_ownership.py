"""The native raw-FD fixture owns setup without reclaiming transferred handles."""

import os

import pytest

from core.source.tests import test_owned_fd_stream as native
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_initial_metadata_fault_closes_untransferred_fd(tmp_path, monkeypatch, after, error):
    opened, closed = [], []
    failure = error("owned initial metadata failure")
    borrowed = native.os

    def opening(*a, **k):
        fd = os.open(*a, **k)
        opened.append(fd)
        return fd

    def stat(fd):
        if after:
            os.fstat(fd)
        raise failure

    def closing(fd):
        assert fd in opened and fd not in closed
        os.close(fd)
        closed.append(fd)

    with monkeypatch.context() as patch:
        patch_module_attribute(patch, native, "os", "open", opening)
        patch_module_attribute(patch, native, "os", "fstat", stat)
        patch_module_attribute(patch, native, "os", "close", closing)
        generator = native.owned_fd.__wrapped__(tmp_path)
        try:
            with pytest.raises(error) as caught:
                next(generator)
            assert caught.value is failure
            assert len(opened) == 1 and closed == opened
        finally:
            generator.close()
            for fd in opened:
                if fd not in closed:
                    os.close(fd)
    assert native.os is borrowed


def test_normal_native_fixture_yield_and_retirement(tmp_path):
    generator = native.owned_fd.__wrapped__(tmp_path)
    fd, path = next(generator)
    identity = os.fstat(fd)
    try:
        assert path.read_bytes() == b"owned bytes"
        assert os.read(fd, 32) == b"owned bytes"
        generator.close()
        with pytest.raises(OSError):
            os.fstat(fd)
    finally:
        generator.close()
        try:
            current = os.fstat(fd)
        except OSError:
            pass
        else:
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                os.close(fd)


def test_native_post_yield_guard_preserves_replaced_descriptor(tmp_path):
    generator = native.owned_fd.__wrapped__(tmp_path)
    fd, _ = next(generator)
    original = os.fstat(fd)
    sentinel = tmp_path / "borrowed"
    sentinel.write_bytes(b"borrowed bytes")
    identity = original
    try:
        with sentinel.open("rb") as borrowed:
            # fd still belongs to this test. Replace it atomically, rather
            # than closing it and risking overwriting an unrelated reused FD.
            os.dup2(borrowed.fileno(), fd)
            identity = os.fstat(fd)
            assert (identity.st_dev, identity.st_ino) != (original.st_dev, original.st_ino)
            generator.close()
            assert os.fstat(fd).st_ino == identity.st_ino
            assert os.read(fd, 32) == b"borrowed bytes"
    finally:
        generator.close()
        try:
            current = os.fstat(fd)
        except OSError:
            pass
        else:
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                os.close(fd)

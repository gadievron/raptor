"""The key's read-failure contract survives nonblocking-open hardening."""

import errno
import os

import pytest

from core import atomic_fs
from core.security import mac_key
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize("close_fails", [False, True])
def test_key_metadata_io_failure_keeps_read_and_close_contract(tmp_path, monkeypatch, close_fails):
    path = tmp_path / "key"
    path.write_bytes(b"k" * 32)
    path.chmod(0o600)
    opened, closed, warnings = [], [], []
    close_error = OSError(errno.EIO, "fresh close failure")

    def opening(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def metadata_failure(fd):
        raise OSError(errno.EIO, "metadata read failed")

    def closing(fd):
        os.close(fd)
        closed.append(fd)
        if close_fails:
            raise close_error

    # Inject the same native failure through both possible consumers. This
    # distinguishes a read failure from an opener that misclassifies it as a
    # policy refusal, without changing the borrowed process-wide os module.
    for consumer in (mac_key, atomic_fs):
        patch_module_attribute(monkeypatch, consumer, "os", "open", opening)
        patch_module_attribute(monkeypatch, consumer, "os", "fstat", metadata_failure)
        patch_module_attribute(monkeypatch, consumer, "os", "close", closing)

    def read():
        return mac_key.read_existing_key(path, key_len=32, warn=lambda *args: warnings.append(args))

    if close_fails:
        with pytest.raises(OSError) as error:
            read()
        assert error.value is close_error
    else:
        assert read() is None
    assert warnings == []
    assert len(opened) == 1
    assert closed == opened
    with pytest.raises(OSError) as retired:
        os.fstat(opened[0])
    assert retired.value.errno == errno.EBADF

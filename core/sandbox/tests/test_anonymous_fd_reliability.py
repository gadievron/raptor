"""Anonymous config descriptors remain complete and owned on failure."""

import contextlib
import errno
import os
import sys
from unittest.mock import Mock

import pytest

from core.sandbox import evidence


@pytest.fixture
def tempfile_branch(tmp_path, monkeypatch):
    real_mkstemp, real_close = evidence.tempfile.mkstemp, os.close
    allocated, released = [], set()

    def mkstemp(**kwargs):
        fd, path = real_mkstemp(dir=tmp_path, **kwargs)
        allocated.append(fd)
        return fd, path

    def close(fd):
        if fd in allocated:
            released.add(fd)
        real_close(fd)

    monkeypatch.delattr(evidence.os, "memfd_create", raising=False)
    monkeypatch.setattr(evidence.tempfile, "mkstemp", mkstemp)
    monkeypatch.setattr(evidence.os, "close", close)
    try:
        yield allocated
    finally:
        for fd in allocated:
            if fd not in released:
                with contextlib.suppress(OSError):
                    real_close(fd)


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, MemoryError])
def test_unlink_failure_closes_fd_and_removes_tempfile(
    tmp_path, monkeypatch, tempfile_branch, failure_type,
):
    real_unlink = os.unlink
    failure = failure_type("unlink interrupted")
    calls = []

    def unlink(path):
        calls.append(path)
        if len(calls) == 1:
            raise failure
        real_unlink(path)

    monkeypatch.setattr(evidence.os, "unlink", unlink)
    with pytest.raises(failure_type) as raised:
        evidence.anonymous_fd(b"config")
    assert raised.value is failure
    assert len(tempfile_branch) == 1
    with pytest.raises(OSError) as exc:
        os.fstat(tempfile_branch[0])
    assert exc.value.errno == errno.EBADF
    assert list(tmp_path.iterdir()) == []


def test_partial_writes_use_one_backing_buffer_and_rewind(
    tmp_path, monkeypatch, tempfile_branch,
):
    payload = bytes(range(256)) * 4
    real_write = os.write
    buffers = []

    def partial(fd, data):
        buffers.append(data)
        return real_write(fd, data[:7])

    monkeypatch.setattr(evidence.os, "write", partial)
    fd = evidence.anonymous_fd(payload)
    try:
        assert len(buffers) > 1
        assert all(isinstance(buf, memoryview) and buf.obj is payload for buf in buffers)
        assert os.read(fd, len(payload) + 1) == payload
        assert not os.get_inheritable(fd)
        assert list(tmp_path.iterdir()) == []
    finally:
        os.close(fd)


@pytest.mark.parametrize("failure", ["zero", "error"])
def test_write_failure_releases_anonymous_fd(
    tmp_path, monkeypatch, tempfile_branch, failure,
):
    real_write = os.write
    calls = []

    def write(fd, data):
        calls.append(fd)
        if len(calls) == 1:
            return real_write(fd, data[:2])
        if failure == "zero":
            return 0
        raise OSError(errno.ENOSPC, "no space")

    monkeypatch.setattr(evidence.os, "write", write)
    with pytest.raises(OSError) as exc:
        evidence.anonymous_fd(b"config")
    assert exc.value.errno == (errno.EIO if failure == "zero" else errno.ENOSPC)
    assert len(calls) == 2
    with pytest.raises(OSError):
        os.fstat(tempfile_branch[0])
    assert list(tmp_path.iterdir()) == []


def test_rewind_failure_releases_descriptor(monkeypatch, tempfile_branch):
    monkeypatch.setattr(evidence.os, "lseek", Mock(side_effect=OSError("seek failed")))
    with pytest.raises(OSError, match="seek failed"):
        evidence.anonymous_fd(b"config")
    with pytest.raises(OSError) as exc:
        os.fstat(tempfile_branch[0])
    assert exc.value.errno == errno.EBADF


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux memfd fallback")
def test_runtime_enosys_uses_unlinked_tempfile(tmp_path, monkeypatch, tempfile_branch):
    monkeypatch.setattr(
        evidence.os, "memfd_create",
        Mock(side_effect=OSError(errno.ENOSYS, "unsupported syscall")), raising=False,
    )
    fd = evidence.anonymous_fd(b"config")
    try:
        assert len(tempfile_branch) == 1
        assert os.read(fd, 6) == b"config"
        assert not os.get_inheritable(fd)
        assert list(tmp_path.iterdir()) == []
    finally:
        os.close(fd)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux memfd errors")
@pytest.mark.parametrize("code", [errno.EMFILE, errno.EINVAL, errno.EPERM])
def test_other_memfd_errors_are_not_hidden(monkeypatch, code):
    failure = OSError(code, "memfd failed")
    monkeypatch.setattr(evidence.os, "memfd_create", Mock(side_effect=failure), raising=False)
    temporary = Mock(side_effect=AssertionError("must not fall back"))
    monkeypatch.setattr(evidence.tempfile, "mkstemp", temporary)
    with pytest.raises(OSError) as raised:
        evidence.anonymous_fd(b"config")
    assert raised.value is failure
    temporary.assert_not_called()

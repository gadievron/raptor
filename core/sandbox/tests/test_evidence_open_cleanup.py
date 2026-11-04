"""Failed evidence setup releases every descriptor it acquired."""

import errno
import fcntl
import os
import stat

import pytest

from core.sandbox import evidence


@pytest.mark.parametrize("existing,stage", [
    (False, "fstat"), (True, "fstat"),
    (True, "getfl"), (True, "setfl"),
    (False, "construct"), (True, "construct"),
])
def test_open_failure_closes_descriptors(tmp_path, monkeypatch, existing, stage):
    if existing:
        handle = evidence.EvidenceFile.open(tmp_path, "events.jsonl")
        handle.close()

    real_open, real_close, real_fstat = os.open, os.close, os.fstat
    real_fcntl = fcntl.fcntl
    acquired = []
    closed = []
    failure = OSError(errno.EIO, "injected setup failure")

    def track_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        acquired.append(fd)
        return fd

    def track_close(fd):
        closed.append(fd)
        return real_close(fd)

    def fail_fstat(fd):
        result = real_fstat(fd)
        if stage == "fstat" and stat.S_ISREG(result.st_mode):
            raise failure
        return result

    def fail_fcntl(fd, operation, *args):
        if ((stage == "getfl" and operation == fcntl.F_GETFL)
                or (stage == "setfl" and operation == fcntl.F_SETFL)):
            raise failure
        return real_fcntl(fd, operation, *args)

    def fail_construct(self, *args):
        raise failure

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", track_open)
        patch.setattr(os, "close", track_close)
        patch.setattr(os, "fstat", fail_fstat)
        patch.setattr(fcntl, "fcntl", fail_fcntl)
        if stage == "construct":
            patch.setattr(evidence.EvidenceFile, "__init__", fail_construct)
        with pytest.raises(OSError) as raised:
            evidence.EvidenceFile.open(tmp_path, "events.jsonl")

    assert raised.value is failure
    assert len(acquired) == 2
    assert sorted(closed) == sorted(acquired)
    for fd in acquired:
        with pytest.raises(OSError) as invalid:
            real_fstat(fd)
        assert invalid.value.errno == errno.EBADF

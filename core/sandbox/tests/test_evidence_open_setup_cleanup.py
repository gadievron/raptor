"""Every acquired evidence descriptor is guarded through setup."""
import os

import pytest

from core.sandbox import evidence


class Cancelled(BaseException):
    pass


@pytest.fixture
def descriptors(monkeypatch):
    acquired = set()
    closed = []
    real_open, real_close = os.open, os.close

    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        acquired.add(fd)
        return fd

    def close_fd(fd):
        if fd in acquired:
            acquired.remove(fd)
            closed.append(fd)
        else:
            pytest.fail('descriptor closed without ownership')
        real_close(fd)

    # Limit patched calls to the operation, avoiding unrelated pytest cleanup.
    with monkeypatch.context() as scoped:
        scoped.setattr(evidence.os, 'open', open_fd)
        scoped.setattr(evidence.os, 'close', close_fd)
        yield acquired, closed
    for fd in acquired:
        real_close(fd)


@pytest.mark.parametrize('error_type', [ValueError, MemoryError, Cancelled])
def test_path_setup_failure_releases_directory(tmp_path, monkeypatch, descriptors, error_type):
    acquired, closed = descriptors
    error = error_type('path setup failed')

    def fail(*args):
        raise error

    monkeypatch.setattr(evidence, 'evidence_write_path', fail)
    with pytest.raises(error_type) as caught:
        evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    assert caught.value is error
    assert not acquired
    assert len(closed) == 1
    assert not (tmp_path / '.audit' / 'events.jsonl').exists()


@pytest.mark.parametrize('existing', [False, True])
@pytest.mark.parametrize('error_type', [RuntimeError, Cancelled])
def test_constructor_failure_releases_file_and_directory(
        tmp_path, descriptors, existing, error_type):
    acquired, closed = descriptors
    if existing:
        directory = tmp_path / '.audit'
        directory.mkdir(mode=0o700)
        path = directory / 'events.jsonl'
        path.write_bytes(b'previous\n')
        path.chmod(0o600)
    error = error_type('construction failed')

    class FailedEvidence(evidence.EvidenceFile):
        def __init__(self, *args):
            raise error

    with pytest.raises(error_type) as caught:
        FailedEvidence.open(tmp_path, 'events.jsonl')
    assert caught.value is error
    assert not acquired
    assert len(closed) == 2
    if existing:
        assert path.read_bytes() == b'previous\n'

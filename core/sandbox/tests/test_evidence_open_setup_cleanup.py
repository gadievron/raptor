"""Every acquired evidence descriptor is guarded through setup."""
import os

import pytest

from core.sandbox import evidence
from core.testing.module_bindings import patch_module_attribute


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

    # Keep descriptor spies local to evidence, including fixture teardown.
    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, evidence, 'os', 'open', open_fd)
        patch_module_attribute(scoped, evidence, 'os', 'close', close_fd)
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


@pytest.mark.parametrize('failure_type', [RuntimeError, KeyboardInterrupt])
def test_directory_close_failure_retires_unreturned_file(
        tmp_path, monkeypatch, descriptors, failure_type):
    acquired, closed = descriptors
    close = evidence.os.close
    failure = failure_type('directory close interrupted')
    attempts = []

    def interrupted_close(fd):
        attempts.append(fd)
        close(fd)
        if len(attempts) == 1:
            raise failure

    patch_module_attribute(monkeypatch, evidence, 'os', 'close', interrupted_close)
    with pytest.raises(failure_type) as caught:
        evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    assert caught.value is failure
    assert not acquired
    assert len(closed) == 2
    assert len(attempts) == len(set(attempts)) == 2


@pytest.mark.parametrize('stage', ['path', 'constructor'])
@pytest.mark.parametrize('secondary_type', [RuntimeError, KeyboardInterrupt])
def test_setup_failure_survives_cleanup_interruptions(
        tmp_path, monkeypatch, descriptors, stage, secondary_type):
    acquired, closed = descriptors
    close = evidence.os.close
    primary = Cancelled('setup interrupted')
    secondary = secondary_type('cleanup interrupted')

    def fail(*args):
        raise primary

    class FailedEvidence(evidence.EvidenceFile):
        __init__ = fail

    def interrupted_close(fd):
        close(fd)
        raise secondary

    if stage == 'path':
        monkeypatch.setattr(evidence, 'evidence_write_path', fail)
    patch_module_attribute(monkeypatch, evidence, 'os', 'close', interrupted_close)
    with pytest.raises(Cancelled) as caught:
        FailedEvidence.open(tmp_path, 'events.jsonl')
    assert caught.value is primary
    assert not acquired
    assert len(closed) == (1 if stage == 'path' else 2)


def test_directory_oserror_preserves_returned_file(tmp_path, monkeypatch, descriptors):
    acquired, closed = descriptors
    close = evidence.os.close

    def interrupted_close(fd):
        close(fd)
        if len(closed) == 1:
            raise OSError('directory close failed')

    patch_module_attribute(monkeypatch, evidence, 'os', 'close', interrupted_close)
    result = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    try:
        assert acquired == {result.fd}
        assert result.write_record({'owned': True})
    finally:
        result.close(verify=False)
    assert not acquired

"""Tar cleanup preserves primary failures and borrowed iterator ownership."""

import io
import tarfile

import pytest

from core.tar import extract as extraction
from core.testing.module_bindings import patch_module_attribute


def _tar_bytes():
    with io.BytesIO() as output:
        with tarfile.open(fileobj=output, mode='w') as archive:
            for index in range(2):
                entry = tarfile.TarInfo(f'file-{index}')
                entry.size = 4
                with io.BytesIO(b'data') as data:
                    archive.addfile(entry, data)
        return output.getvalue()


def _faulted_archive(monkeypatch, phase, primary):
    original = tarfile.open
    archives, members = [], []

    class Member:
        def __init__(self, stream):
            self.stream = stream

        def read(self):
            if phase == 'duplicate':
                pytest.fail('duplicate data must not be read')
            if primary is not None:
                raise primary
            return self.stream.read()

        def close(self):
            self.stream.close()
            raise OSError('member close failure')

    class Archive:
        def __init__(self, archive):
            self.archive = archive

        def __iter__(self):
            return iter(self.archive)

        def extractfile(self, member):
            stream = self.archive.extractfile(member)
            assert stream is not None
            members.append(stream)
            if phase == 'member' or (phase == 'duplicate' and len(members) == 2):
                return Member(stream)
            return stream

        def close(self):
            self.archive.close()
            raise OSError('archive close failure')

    def open_archive(*args, **kwargs):
        archive = original(*args, **kwargs)
        archives.append(archive)
        return Archive(archive)

    patch_module_attribute(monkeypatch, extraction, 'tarfile', 'open', open_archive)
    return archives, members


@pytest.mark.parametrize('phase', ['selector', 'member'])
@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_cancellation_keeps_precedence(monkeypatch, phase, failure):
    raw = _tar_bytes()
    primary = failure('cancelled')
    archives, members = _faulted_archive(monkeypatch, phase, primary)

    def select(member):
        if phase == 'selector':
            raise primary
        return member.name

    try:
        with pytest.raises(failure) as caught:
            extraction.extract_files_from_tar(raw, selector=select, mode='r:')
        assert caught.value is primary
    finally:
        assert len(archives) == 1 and archives[0].closed
        assert all(member.closed for member in members)


def test_typed_read_refusal_keeps_original_cause(monkeypatch):
    raw = _tar_bytes()
    primary = EOFError('member read failed')
    archives, members = _faulted_archive(monkeypatch, 'member', primary)
    with pytest.raises(extraction.TarReadError) as caught:
        extraction.extract_files_from_tar(raw, selector=lambda member: member.name, mode='r:')
    assert caught.value.__cause__ is primary
    assert archives[0].closed and members[0].closed


def test_duplicate_key_refusal_precedes_cleanup_failure(monkeypatch):
    raw = _tar_bytes()
    archives, members = _faulted_archive(monkeypatch, 'duplicate', None)
    with pytest.raises(ValueError, match='duplicate tar key'):
        extraction.extract_files_from_tar(
            raw, selector=lambda member: 'same', mode='r:', unique_keys=True,
        )
    assert archives[0].closed and len(members) == 2
    assert all(member.closed for member in members)


@pytest.mark.parametrize('phase, message', [
    ('archive', 'archive close failure'), ('member', 'member close failure'),
])
def test_cleanup_failure_without_primary_still_propagates(monkeypatch, phase, message):
    raw = _tar_bytes()
    archives, members = _faulted_archive(monkeypatch, phase, None)
    with pytest.raises(OSError, match=message):
        extraction.extract_files_from_tar(raw, selector=lambda member: member.name, mode='r:')
    assert archives[0].closed and all(member.closed for member in members)


def test_early_exit_leaves_borrowed_chunks_resumable():
    closed = []
    raw = _tar_bytes()
    tail = b'\0' * 512

    def chunks():
        try:
            yield raw
            yield tail
        finally:
            closed.append(True)

    source = chunks()
    try:
        assert extraction.extract_files_from_tar(
            source, selector=lambda member: member.name, mode='r|', expected_count=1,
        ) == {'file-0': b'data'}
        assert not closed
        assert next(source) == tail
    finally:
        source.close()
    assert closed == [True]

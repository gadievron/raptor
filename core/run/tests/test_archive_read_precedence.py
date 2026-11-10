"""Archive acquisition reads preserve cancellation and identity bytes."""

import hashlib
from pathlib import Path
import zipfile

import pytest

import core.archive.detect as detection
import core.hash as hashes
from core.run import provenance


def _case(tmp_path, monkeypatch, stage, primary=None, close_fails=True):
    source = tmp_path / 'owned.zip'
    with zipfile.ZipFile(source, 'w') as archive:
        archive.writestr('fixture.txt', b'owned fixture')
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    streams, reads = [], []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()
            if close_fails:
                raise OSError('secondary archive close failure')

        def read(self, size):
            reads.append(size)
            if primary is not None:
                raise primary
            return self.stream.read(size)

    class OwnedPath(type(Path())):
        def open(self, *args, **kwargs):
            assert self == source
            stream = super().open(*args, **kwargs)
            streams.append(stream)
            return Reader(stream)

    if stage in ('detect', 'all'):
        monkeypatch.setattr(detection, 'Path', OwnedPath)
    if stage in ('hash', 'all'):
        # Exercise the original private loop and its shared replacement at
        # the same native file seam without patching pathlib globally.
        monkeypatch.setattr(provenance, 'Path', OwnedPath)
        monkeypatch.setattr(hashes, 'Path', OwnedPath)
    return source, expected, streams, reads


@pytest.mark.parametrize('stage', ['detect', 'hash'])
@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_archive_read_cancellation_survives_close_error(tmp_path, monkeypatch, stage, failure):
    primary = failure('cancelled archive read')
    source, _, streams, _ = _case(tmp_path, monkeypatch, stage, primary)
    try:
        with pytest.raises(failure) as caught:
            provenance.archive_snapshot(source)
        assert caught.value is primary
    finally:
        assert len(streams) == 1 and streams[0].closed


@pytest.mark.parametrize('stage', ['detect', 'hash'])
@pytest.mark.parametrize('read_fails', [False, True])
def test_archive_io_failure_retains_no_snapshot(tmp_path, monkeypatch, stage, read_fails):
    primary = OSError('archive read unavailable') if read_fails else None
    source, _, streams, _ = _case(tmp_path, monkeypatch, stage, primary)
    assert provenance.archive_snapshot(source) is None
    assert len(streams) == 1 and streams[0].closed


def test_native_archive_identity_and_chunk_boundaries_are_preserved(tmp_path, monkeypatch):
    source, expected, streams, reads = _case(tmp_path, monkeypatch, 'all', close_fails=False)
    snapshot = {'archive_sha256': expected, 'archive_name': source.name, 'format': 'zip'}
    assert provenance.archive_snapshot(source) == snapshot
    assert provenance.archive_target_identity(source) == {'source': 'archive', **snapshot}
    assert len(streams) == 4 and all(stream.closed for stream in streams)
    assert reads == [512, 1 << 20, 1 << 20] * 2

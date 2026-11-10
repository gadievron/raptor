"""Archive teardown must not turn cancellation into an extraction miss."""

import io
import tarfile

import pytest

from core.concepts import library_detect as ld
from core.testing.module_bindings import patch_module_attribute


def _archive_case(tmp_path, monkeypatch, phase, primary):
    source = tmp_path / 'source.tar'
    with tarfile.open(source, 'w') as archive:
        entry = tarfile.TarInfo('library/file.c')
        entry.size = 3
        with io.BytesIO(b'new') as data:
            archive.addfile(entry, data)
    cache = tmp_path / 'cache'
    previous = cache / 'library'
    previous.mkdir(parents=True)
    (previous / 'old.txt').write_text('keep')
    streams, archives = [], []
    original_open = ld.open_regular_gated
    original_tar = tarfile.open

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()
            raise OSError('secondary file close failure')

        def read(self, *args):
            raise primary

    class Archive:
        def __init__(self, archive):
            self.archive = archive

        def __getattr__(self, name):
            return getattr(self.archive, name)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.archive.close()
            raise OSError('secondary archive close failure')

        def __iter__(self):
            iterator = iter(self.archive)
            yield next(iterator)
            if primary is not None:
                raise primary
            yield from iterator

    def open_reader(*args, **kwargs):
        stream = original_open(*args, **kwargs)
        streams.append(stream)
        return Reader(stream) if phase == 'stream' else stream

    def open_archive(*args, **kwargs):
        archive = original_tar(*args, **kwargs)
        archives.append(archive)
        return Archive(archive)

    monkeypatch.setattr(ld, 'open_regular_gated', open_reader)
    if phase == 'archive':
        patch_module_attribute(monkeypatch, ld, 'tarfile', 'open', open_archive)
    return source, cache, streams, archives


@pytest.mark.parametrize('phase', ['stream', 'archive'])
@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_archive_read_cancellation_keeps_precedence(tmp_path, monkeypatch, phase, failure):
    primary = failure('cancelled')
    source, cache, streams, archives = _archive_case(tmp_path, monkeypatch, phase, primary)
    try:
        with pytest.raises(failure) as caught:
            ld._extract_tarball(source, cache)
        assert caught.value is primary
    finally:
        assert len(streams) == 1 and streams[0].closed
        assert all(archive.closed for archive in archives)
        assert (cache / 'library/old.txt').read_text() == 'keep'
        assert not list(cache.glob('.library-extract-*'))


def test_archive_close_failure_alone_remains_a_refusal(tmp_path, monkeypatch):
    source, cache, streams, archives = _archive_case(tmp_path, monkeypatch, 'archive', None)
    assert ld._extract_tarball(source, cache) is None
    assert streams and all(stream.closed for stream in streams)
    assert len(archives) == 1 and archives[0].closed

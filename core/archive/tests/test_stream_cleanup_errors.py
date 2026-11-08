"""Extraction limit/cancellation receipts survive failed stream teardown."""
import gzip

import pytest

from core.archive import extract as extraction
from core.archive.errors import DecompressionLimitExceeded
from core.testing.stream_faults import FaultingStream


@pytest.mark.parametrize('primary_type', [DecompressionLimitExceeded, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_single_file_extraction_keeps_limit_or_cancellation(tmp_path, monkeypatch, primary_type, cleanup_type):
    source = tmp_path / 'source.gz'
    source.write_bytes(gzip.compress(b'payload'))
    original = source.read_bytes()
    primary = (primary_type('primary extraction failure', cap='total_bytes')
               if primary_type is DecompressionLimitExceeded else primary_type('primary extraction failure'))
    opened = []
    real_open = open
    def chunks(*args, **kwargs):
        yield b'payload' * 100  # Enough to finish the real tar sniff.
        raise primary
    def writer(*args, **kwargs):
        stream = FaultingStream(real_open(*args, **kwargs), cleanup=cleanup_type('close failed'))
        opened.append(stream)
        return stream
    monkeypatch.setattr(extraction, 'iter_decompressed', chunks)
    monkeypatch.setattr(extraction, 'open', writer, raising=False)
    with pytest.raises(primary_type) as caught:
        extraction.extract_to_dir(source, tmp_path / 'output')
    assert caught.value is primary
    if primary_type is DecompressionLimitExceeded:
        assert caught.value.cap == 'total_bytes'
    assert source.read_bytes() == original
    assert len(opened) == 1
    assert opened[0].closed
    assert len(opened[0].exits) == 1


@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_tar_input_failure_keeps_its_error_contract(tmp_path, monkeypatch, primary_type, cleanup_type):
    import io
    import tarfile
    from core.archive.errors import ArchiveError

    source = tmp_path / 'source.tar'
    with tarfile.open(source, 'w') as archive:
        info = tarfile.TarInfo('data.bin')
        info.size = 7
        archive.addfile(info, io.BytesIO(b'payload'))
    before = source.read_bytes()
    primary = primary_type('primary tar read failure')
    opened = []
    class OwnedPath(type(tmp_path)):
        def open(self, mode='r', *args, **kwargs):
            stream = super().open(mode, *args, **kwargs)
            if self == source and mode == 'rb':
                stream = FaultingStream(stream, primary=primary, cleanup=cleanup_type('close failed'))
                opened.append(stream)
            return stream
    monkeypatch.setattr(extraction, 'Path', OwnedPath)
    expected = (ArchiveError, OSError) if primary_type is OSError else primary_type
    with pytest.raises(expected) as caught:
        extraction.extract_to_dir(source, tmp_path / 'output')
    assert 'primary tar read failure' in str(caught.value)
    if primary_type is not OSError:
        assert caught.value is primary
    assert source.read_bytes() == before
    assert len(opened) == 1
    assert opened[0].closed and len(opened[0].exits) == 1

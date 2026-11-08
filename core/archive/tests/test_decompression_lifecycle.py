"""Decompression owns decoder lifetimes and enforces the remaining byte budget."""
import bz2
from contextlib import ExitStack
import gzip
import io
import lzma
import tarfile

import pytest

from core.archive import compression, extract as extraction
from core.archive.errors import ArchiveError, DecompressionLimitExceeded
from core.testing.stream_faults import FaultingStream

FORMATS = ['gz', 'bz2', 'xz']
ENCODERS = {'gz': gzip.compress, 'bz2': bz2.compress, 'xz': lzma.compress}


def archive_bytes(payload, tar):
    if not tar:
        return payload
    with io.BytesIO() as data:
        with tarfile.open(fileobj=data, mode='w') as archive:
            info = tarfile.TarInfo('data.bin')
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        return data.getvalue()


@pytest.fixture
def decoders(monkeypatch):
    opened = []
    with ExitStack() as owned:
        def install(fmt, *, primary=None, cleanup=None):
            original = compression._OPENERS[fmt]
            def open_decoder(*args, **kwargs):
                stream = original(*args, **kwargs)
                owned.callback(lambda: None if stream.closed else stream.close())
                class Decoder(FaultingStream):
                    def __init__(self):
                        super().__init__(stream, primary=primary, cleanup=cleanup)
                        self.reads = []
                    def read(self, size):
                        assert 0 < size <= compression._CHUNK_BYTES
                        block = super().read(size)
                        self.reads.append((size, len(block)))
                        return block
                result = Decoder()
                opened.append(result)
                return result
            monkeypatch.setitem(compression._OPENERS, fmt, open_decoder)
            return opened
        yield install


def write_source(tmp_path, fmt, payload=b'payload', *, tar=False):
    source = tmp_path / ('source.' + fmt)
    source.write_bytes(ENCODERS[fmt](archive_bytes(payload, tar)))
    return source


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('budget,payload_size', [
    (0, 0), (0, 1), (1, 1), (1, 2),
    (compression._CHUNK_BYTES - 1, compression._CHUNK_BYTES),
    (compression._CHUNK_BYTES, compression._CHUNK_BYTES),
    (compression._CHUNK_BYTES, compression._CHUNK_BYTES + 1),
    (compression._CHUNK_BYTES + 1, compression._CHUNK_BYTES + 1),
], ids=['empty', 'zero-refusal', 'one-exact', 'one-refusal', 'below-chunk', 'chunk-exact', 'chunk-refusal', 'above-chunk'])
def test_decoder_reads_only_the_remaining_allowance_plus_a_probe(tmp_path, decoders, fmt, budget, payload_size):
    payload = b'x' * payload_size
    source = write_source(tmp_path, fmt, payload)
    opened = decoders(fmt)
    if payload_size > budget:
        with pytest.raises(DecompressionLimitExceeded) as caught:
            compression.decompress_single(source, fmt, max_bytes=budget)
        assert caught.value.cap == 'total_bytes'
    else:
        assert compression.decompress_single(source, fmt, max_bytes=budget) == payload
    assert len(opened) == 1 and opened[0].closed
    total = 0
    for requested, returned in opened[0].reads:
        assert requested == min(compression._CHUNK_BYTES, budget - total + 1)
        total += returned
    assert total <= budget + 1
    assert len(opened[0].exits) == 1


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('budget', [
    pytest.param(-1, id='negative'), pytest.param(True, id='true'),
    pytest.param(False, id='false'), pytest.param(1.5, id='fractional'),
    pytest.param(float('nan'), id='nan'), pytest.param(float('inf'), id='infinite'),
    pytest.param(None, id='none'), pytest.param('100', id='string'),
])
def test_invalid_budget_refuses_before_opening_input(tmp_path, monkeypatch, fmt, budget):
    opened = []
    def refuse_open(*args, **kwargs):
        opened.append(True)
        raise AssertionError('invalid budget reached decoder')
    monkeypatch.setitem(compression._OPENERS, fmt, refuse_open)
    with pytest.raises(ValueError, match='non-negative integer'):
        compression.decompress_single(tmp_path / 'missing', fmt, max_bytes=budget)
    assert opened == []


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('cleanup_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_budget_kind_survives_decoder_close_failure(tmp_path, decoders, fmt, cleanup_type):
    source = write_source(tmp_path, fmt, b'payload')
    opened = decoders(fmt, cleanup=cleanup_type('secondary decoder close'))
    with pytest.raises(DecompressionLimitExceeded) as caught:
        compression.decompress_single(source, fmt, max_bytes=1)
    assert caught.value.cap == 'total_bytes'
    assert any(cleanup_type.__name__ in note for note in caught.value.__notes__)
    assert opened[0].closed and len(opened[0].exits) == 1


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt])
def test_decoder_read_failure_keeps_its_cause_and_closes_input(tmp_path, decoders, fmt, primary_type, cleanup_type):
    source = write_source(tmp_path, fmt)
    primary = primary_type('primary decoder read')
    opened = decoders(fmt, primary=primary, cleanup=cleanup_type('secondary decoder close'))
    with pytest.raises(ArchiveError if primary_type is OSError else primary_type) as caught:
        compression.decompress_single(source, fmt)
    if primary_type is OSError:
        assert caught.value.__cause__ is primary
        assert 'primary decoder read' in str(caught.value)
    else:
        assert caught.value is primary
    assert opened[0].closed and len(opened[0].exits) == 1


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('tar', [False, True], ids=['single-file', 'tar'])
def test_extraction_closes_a_retained_input_generator_on_success(tmp_path, monkeypatch, decoders, fmt, tar):
    payload = b'payload'
    source = write_source(tmp_path, fmt, payload, tar=tar)
    opened = decoders(fmt)
    original = extraction.iter_decompressed
    retained = []
    def capture(*args, **kwargs):
        iterator = original(*args, **kwargs)
        retained.append(iterator)
        return iterator
    monkeypatch.setattr(extraction, 'iter_decompressed', capture)
    output = tmp_path / 'output'
    result = extraction.extract_to_dir(source, output)
    assert result['files'] == 1 and result['dropped'] == 0
    assert (output / ('data.bin' if tar else 'source')).read_bytes() == payload
    assert len(retained) == 1 and retained[0].gi_frame is None
    assert opened[0].closed and len(opened[0].exits) == 1


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('tar', [False, True], ids=['single-file', 'tar'])
@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_fails', [False, True], ids=['normal-close', 'failed-close'])
def test_consumer_failure_closes_retained_decoder_without_replacing_primary(tmp_path, monkeypatch, decoders, fmt, tar, primary_type, cleanup_fails):
    source = write_source(tmp_path, fmt, b'payload' * 100, tar=tar)
    before = source.read_bytes()
    opened = decoders(fmt, cleanup=OSError('secondary close') if cleanup_fails else None)
    primary = primary_type('primary extraction failure')
    reached = []
    retained = []
    original = extraction.iter_decompressed
    def capture(*args, **kwargs):
        result = original(*args, **kwargs)
        retained.append(result)
        return result
    def fail(chunks, *args, **kwargs):
        head = next(iter(chunks))
        assert bool(extraction.looks_like_tar(head)) is tar
        reached.append(True)
        raise primary
    monkeypatch.setattr(extraction, 'iter_decompressed', capture)
    monkeypatch.setattr(extraction, 'extract_files_from_tar' if tar else '_write_single_file', fail)
    with pytest.raises(primary_type) as caught:
        extraction.extract_to_dir(source, tmp_path / 'output')
    assert caught.value is primary
    assert reached == [True]
    assert len(retained) == 1 and retained[0].gi_frame is None
    assert opened[0].closed and len(opened[0].exits) == 1
    assert source.read_bytes() == before


@pytest.mark.parametrize('fmt', FORMATS)
@pytest.mark.parametrize('cleanup_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_early_tar_completion_still_requires_successful_decoder_close(tmp_path, decoders, fmt, cleanup_type):
    source = write_source(tmp_path, fmt, tar=True)
    cleanup = cleanup_type('primary decoder close')
    opened = decoders(fmt, cleanup=cleanup)
    expected = ArchiveError if isinstance(cleanup, Exception) else cleanup_type
    with pytest.raises(expected) as caught:
        extraction.extract_to_dir(source, tmp_path / 'output')
    if isinstance(cleanup, Exception):
        assert caught.value.__cause__ is cleanup
    else:
        assert caught.value is cleanup
    assert opened[0].closed and len(opened[0].exits) == 1


@pytest.mark.parametrize('fmt', FORMATS)
def test_explicit_generator_exit_keeps_the_protocol_and_releases_decoder(tmp_path, decoders, fmt):
    source = write_source(tmp_path, fmt, b'payload')
    opened = decoders(fmt)
    iterator = compression.iter_decompressed(source, fmt)
    assert next(iterator) == b'payload'
    primary = GeneratorExit('explicit close')
    with pytest.raises(GeneratorExit) as caught:
        iterator.throw(primary)
    assert caught.value is primary
    assert iterator.gi_frame is None and opened[0].closed
    assert len(opened[0].exits) == 1

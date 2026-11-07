"""Kernel sniffing keeps character boundaries, caps and cache behavior."""

import io
import random

import pytest

from core.audit import context
from core.source import windows


@pytest.fixture(autouse=True)
def owned_kernel_cache(monkeypatch):
    monkeypatch.setattr(context, '_kernel_file_cache', context.BoundedMemo(2048))


@pytest.mark.parametrize('raw', [
    pytest.param(b'// ordinary\n' * 1000, id='plain'),
    pytest.param(('😀' * 1024 + 'MODULE_LICENSE').encode(), id='marker-after-4096-bytes'),
    pytest.param(('😀' * (4096-len('MODULE_LICENSE')) + 'MODULE_LICENSE').encode(), id='marker-at-character-cut'),
    pytest.param(('😀' * 4096 + 'MODULE_LICENSE').encode(), id='marker-outside-character-cut'),
    pytest.param(b'\xff\xf0\x9f' * 3000 + b'MODULE_LICENSE', id='malformed-prefix'),
])
def test_kernel_sniff_matches_full_decode_character_prefix(tmp_path, raw):
    path = tmp_path / 'source.c'
    path.write_bytes(raw)
    expected = any(marker in raw.decode('utf-8', 'replace')[:4096] for marker in context._KERNEL_SOURCE_MARKERS)
    assert context._file_has_kernel_markers({'file': path.name, 'target_path': str(tmp_path)}) is expected


def test_random_utf8_prefixes_match_full_replacement_decode(tmp_path, monkeypatch):
    rng = random.Random(908)
    path = tmp_path / 'source.c'
    for _ in range(100):
        raw = rng.randbytes(rng.randrange(200))
        path.write_bytes(raw)
        chars = rng.randrange(40)
        monkeypatch.setattr(windows, '_CHUNK_BYTES', rng.randrange(1, 20))
        assert context._read_target_text_prefix(path, chars) == raw.decode('utf-8', 'replace')[:chars]


def test_oversized_tail_preserves_warning_and_kernel_fallback(tmp_path, monkeypatch, caplog):
    path = tmp_path / 'source.c'
    path.write_bytes(b'ordinary source with an oversized tail')
    monkeypatch.setattr(context, '_MAX_SOURCE_FILE_BYTES', 16)
    assert context._file_has_kernel_markers({'file': path.name, 'target_path': str(tmp_path)}) is True
    assert 'cap, skipping:' in caplog.text
    assert context._read_target_text_prefix(path, 4) is None


def test_tail_read_failure_preserves_kernel_fallback(tmp_path, monkeypatch):
    path = tmp_path / 'source.c'
    path.write_bytes(b'ordinary source')

    class FailingStream(io.BytesIO):
        def read(self, size):
            if self.tell():
                raise OSError('owned late error')
            return super().read(size)

    stream = FailingStream(b'ordinary source with a failing tail')
    monkeypatch.setattr(windows, '_CHUNK_BYTES', 8)
    monkeypatch.setattr(windows, 'open_regular', lambda *args: stream)
    assert context._file_has_kernel_markers({'file': path.name, 'target_path': str(tmp_path)}) is True
    assert stream.closed


def test_existing_kernel_cache_still_performs_one_read_per_key(tmp_path, monkeypatch):
    path = tmp_path / 'source.c'
    path.write_bytes(b'MODULE_LICENSE')
    actual = context._read_target_text_prefix
    reads = []

    def read(*args):
        reads.append(args)
        return actual(*args)

    monkeypatch.setattr(context, '_read_target_text_prefix', read)
    ctx = {'file': path.name, 'target_path': str(tmp_path)}
    assert context._file_has_kernel_markers(ctx) is True
    assert context._file_has_kernel_markers(ctx) is True
    assert len(reads) == 1

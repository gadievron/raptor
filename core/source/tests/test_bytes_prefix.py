"""Byte prefixes retain whole-file cap and late-error guarantees."""

import io
import random

import pytest

from core.source import windows


@pytest.mark.parametrize('chunk_bytes', [1, 3, 65536])
@pytest.mark.parametrize('prefix_bytes', [0, 1, 7, 40])
def test_prefix_matches_whole_read_without_changing_cap_result(tmp_path, monkeypatch, chunk_bytes, prefix_bytes):
    raw = b'a\r\nb\xff\xf0\x9f\x98\x80\x00tail'
    path = tmp_path / 'source.c'
    path.write_bytes(raw)
    monkeypatch.setattr(windows, '_CHUNK_BYTES', chunk_bytes)
    assert windows.read_bytes_prefix_capped(path, prefix_bytes, max_bytes=len(raw)) == (raw[:prefix_bytes], False)
    assert windows.read_bytes_prefix_capped(path, prefix_bytes, max_bytes=len(raw)-1) == (b'', True)


def test_random_prefixes_and_budgets(tmp_path, monkeypatch):
    rng = random.Random(808)
    path = tmp_path / 'source.c'
    for _ in range(100):
        raw = rng.randbytes(rng.randrange(100))
        path.write_bytes(raw)
        prefix, cap = rng.randrange(110), rng.randrange(110)
        monkeypatch.setattr(windows, '_CHUNK_BYTES', rng.randrange(1, 20))
        assert windows.read_bytes_prefix_capped(path, prefix, max_bytes=cap) == (
            (b'', True) if len(raw) > cap else (raw[:prefix], False)
        )


def test_late_read_failure_discards_a_retained_prefix(monkeypatch):
    class FailingStream(io.BytesIO):
        def read(self, size):
            if self.tell():
                raise OSError('owned tail failure')
            return super().read(size)

    stream = FailingStream(b'head then tail')
    monkeypatch.setattr(windows, 'open_regular', lambda *args: stream)
    monkeypatch.setattr(windows, '_CHUNK_BYTES', 4)
    assert windows.read_bytes_prefix_capped(None, 2, max_bytes=100) is None
    assert stream.closed


def test_probe_reads_through_prefix_but_never_beyond_cap_plus_one(monkeypatch):
    sizes = []

    class ObservedStream(io.BytesIO):
        def read(self, size):
            result = super().read(size)
            sizes.append(len(result))
            return result

    stream = ObservedStream(b'x' * 100)
    monkeypatch.setattr(windows, 'open_regular', lambda *args: stream)
    monkeypatch.setattr(windows, '_CHUNK_BYTES', 4)
    assert windows.read_bytes_prefix_capped(None, 1, max_bytes=10) == (b'', True)
    assert sum(sizes) == 11
    assert stream.closed


def test_missing_and_symlinked_paths_are_refused(tmp_path):
    assert windows.read_bytes_prefix_capped(tmp_path / 'missing', 4, max_bytes=100) is None
    path = tmp_path / 'source.c'
    path.write_bytes(b'head')
    link = tmp_path / 'link.c'
    link.symlink_to(path)
    assert windows.read_bytes_prefix_capped(link, 4, max_bytes=100) is None


@pytest.mark.parametrize('raw', [b'', b'x'], ids=['empty', 'nonempty'])
def test_zero_budget(tmp_path, raw):
    path = tmp_path / 'source.c'
    path.write_bytes(raw)
    assert windows.read_bytes_prefix_capped(path, 4, max_bytes=0) == (b'', bool(raw))


@pytest.mark.parametrize('prefix,cap', [(-1, 10), (1, -1)])
def test_negative_limits_are_rejected(tmp_path, prefix, cap):
    with pytest.raises(ValueError):
        windows.read_bytes_prefix_capped(tmp_path / 'unused', prefix, max_bytes=cap)

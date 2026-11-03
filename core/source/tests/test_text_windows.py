"""Character-capped windows match the legacy reader's visible prefix."""

import io
from itertools import product
import random

import pytest

from core.source import read_text_capped, split_lines
from core.source import windows


@pytest.mark.parametrize('chunk_chars', [1, 2, 3, 17, 65536])
@pytest.mark.parametrize('raw', [
    b'', b'a', b'\n', b'\n\n', b'a\nbcdef', b'a\r\nb\r\nc',
    b'a\rb\n', b'a\r\r\nb\n', b'\r\n\r\n\r',
    'é🙂\nend\u2028\u2029\x00'.encode(), b'\xf0\x9f\n\xff\xe2\x82',
])
def test_differential_prefix_and_windows(tmp_path, monkeypatch, chunk_chars, raw):
    path = tmp_path / 'a.c'
    path.write_bytes(raw)
    monkeypatch.setattr(windows, '_CHUNK_CHARS', chunk_chars)
    for cap in (0, 1, 2, 3, 5, 10, 100):
        content, truncated = read_text_capped(path, cap, newline='')
        lines = split_lines(content)
        for start, end in product((0, 1, 2, 100), repeat=2):
            assert windows.read_text_line_window_capped(
                path, start, end, max_chars=cap,
            ) == (lines[start:end], truncated), (raw, cap, start, end)


def test_random_binary_input_and_character_boundaries(tmp_path, monkeypatch):
    rng = random.Random(551)
    path = tmp_path / 'a.c'
    for _ in range(300):
        raw = bytes(rng.choice((10, 13, 97, 194, 226, 128, 255))
                    for _ in range(rng.randrange(200)))
        path.write_bytes(raw)
        cap, start, end = rng.randrange(150), rng.randrange(30), rng.randrange(30)
        monkeypatch.setattr(windows, '_CHUNK_CHARS', rng.randrange(1, 30))
        content, truncated = read_text_capped(path, cap, newline='')
        assert windows.read_text_line_window_capped(
            path, start, end, max_chars=cap,
        ) == (split_lines(content)[start:end], truncated)


def test_cap_is_characters_not_utf8_bytes(tmp_path):
    path = tmp_path / 'a.c'
    path.write_text('🙂x\n')
    assert windows.read_text_line_window_capped(path, 0, 1, max_chars=1) == (['🙂'], True)


def test_error_after_selected_window_discards_it(monkeypatch):
    class Broken(io.StringIO):
        def read(self, size):
            if self.tell():
                raise OSError('later read failure')
            return super().read(size)

    monkeypatch.setattr(windows, '_CHUNK_CHARS', 2)
    monkeypatch.setattr(windows, 'open_regular', lambda *_args, **_kw: Broken('a\nb\nc\n'))
    assert windows.read_text_line_window_capped(None, 0, 1, max_chars=20) is None


def test_probe_stops_at_cap_plus_one(monkeypatch):
    reads = []

    class Counted(io.StringIO):
        def read(self, size):
            text = super().read(size)
            reads.append(len(text))
            return text

    monkeypatch.setattr(windows, '_CHUNK_CHARS', 3)
    monkeypatch.setattr(windows, 'open_regular', lambda *_args, **_kw: Counted('a\nb\nc\nd\ne\n'))
    assert windows.read_text_line_window_capped(None, 0, 1, max_chars=5) == (['a'], True)
    assert sum(reads) == 6


def test_missing_and_final_symlink_refused(tmp_path):
    path = tmp_path / 'a.c'
    assert windows.read_text_line_window_capped(path, 0, 1) is None
    real = tmp_path / 'real.c'
    real.write_text('a\n')
    path.symlink_to(real)
    assert windows.read_text_line_window_capped(path, 0, 1) is None

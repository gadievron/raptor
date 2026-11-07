"""Narrowed newline searches retain exact offsets and reader semantics."""

import pytest

from core.source import windows
from core.source.contained import read_text_capped
from core.source.lines import split_lines


def legacy_offset(chunk, count, offset):
    newline = b'\n' if isinstance(chunk, bytes) else '\n'
    for _ in range(count):
        offset = chunk.index(newline, offset) + 1
    return offset


def outcome(function, *args):
    try:
        return function(*args)
    except ValueError as exc:
        return type(exc), str(exc)


@pytest.mark.parametrize('kind', ['bytes', 'text'])
@pytest.mark.parametrize('count', [0, 1, 127, 128, 129, 255, 256, 257, 32768, 65536, 65537])
@pytest.mark.parametrize('offset', [-1, 0, 17, 65535, 65536, 65537])
def test_nth_newline_offsets_and_errors_match_legacy(kind, count, offset):
    chunk = '\n' * 65536
    if kind == 'bytes':
        chunk = chunk.encode()
    helper = windows._after_newlines if kind == 'bytes' else windows._after_text_newlines
    assert outcome(helper, chunk, count, offset) == outcome(legacy_offset, chunk, count, offset)


@pytest.mark.parametrize('kind', ['bytes', 'text'])
@pytest.mark.parametrize('count', [128, 129, 512, 7000, 7001])
def test_uneven_newline_positions_and_nonzero_offsets(kind, count):
    chunk = ('a\n' * 4000) + ('界' * 20000) + ('\nxyz\r\n' * 2000)
    if kind == 'bytes':
        chunk = chunk.encode()
    helper = windows._after_newlines if kind == 'bytes' else windows._after_text_newlines
    assert outcome(helper, chunk, count, 79) == outcome(legacy_offset, chunk, count, 79)


@pytest.mark.parametrize('kind', ['bytes', 'text'])
def test_string_adapters_keep_index_calls_and_do_not_use_count(kind):
    base = bytes if kind == 'bytes' else str
    calls = []

    class Adapter(base):
        def count(self, *args):
            raise AssertionError('adapter count was invoked')

        def index(self, *args):
            calls.append(args)
            return super().index(*args)

    chunk = Adapter(b'\n' * 400 if kind == 'bytes' else '\n' * 400)
    helper = windows._after_newlines if kind == 'bytes' else windows._after_text_newlines
    assert helper(chunk, 300, 7) == 307
    assert len(calls) == 300
    assert all(len(args) == 2 for args in calls)


@pytest.mark.parametrize('kind', ['bytes', 'text'])
def test_indexable_count_keeps_its_original_conversion(kind):
    calls = []

    class Count:
        def __index__(self):
            calls.append(1)
            return 300

    chunk = b'\n' * 400 if kind == 'bytes' else '\n' * 400
    helper = windows._after_newlines if kind == 'bytes' else windows._after_text_newlines
    assert helper(chunk, Count()) == 300
    assert calls == [1]


@pytest.mark.parametrize('bounds', [(32000, 32005), (63999, 64001), (90000, 90005)])
def test_dense_line_readers_preserve_raw_and_text_window_models(tmp_path, bounds):
    raw = b'\n' * 64000 + '界\r\ninvalid:\ufffd\n'.encode() * 4000
    path = tmp_path / 'source.c'
    path.write_bytes(raw)
    start, end = bounds
    expected = split_lines(raw.decode('utf-8', errors='replace'))[start:end]
    assert windows.read_line_window_capped(path, start, end, max_bytes=len(raw)) == (expected, False)
    text, truncated = read_text_capped(path, max_chars=len(raw), newline='')
    assert windows.read_text_line_window_capped(path, start, end, max_chars=len(raw)) == (
        split_lines(text)[start:end], truncated,
    )


@pytest.mark.parametrize('kind', ['bytes', 'text'])
@pytest.mark.parametrize('sparse', [False, True], ids=['dense', 'sparse'])
def test_narrowing_is_reserved_for_dense_native_searches(monkeypatch, kind, sparse):
    actual = windows._after_many_newlines
    calls = []

    def observed(*args):
        calls.append(1)
        return actual(*args)

    monkeypatch.setattr(windows, '_after_many_newlines', observed)
    chunk = ('x' * 511 + '\n') * 128 if sparse else '\n' * 8192
    if kind == 'bytes':
        chunk = chunk.encode()
    helper = windows._after_newlines if kind == 'bytes' else windows._after_text_newlines
    assert helper(chunk, 128) == (65536 if sparse else 128)
    assert len(calls) == (0 if sparse else 1)

"""Capture keeps a bounded byte prefix even when one chunk crosses the cap."""
import subprocess

import pytest

from core.sandbox import _spawn as spawn
from core.sandbox.context import _apply_capture_ceiling


@pytest.mark.parametrize('cap', [0, 1, 4, 10])
@pytest.mark.parametrize('chunks', [[b'abcdefghij'], [b'ab', b'cdef', b'ghij'], [b'', b'a', b'b']])
def test_chunk_collection_matches_bounded_prefix(cap, chunks):
    kept, truncated = 0, False
    collected = []
    for chunk in chunks:
        kept, discarded = spawn._append_capture_chunk(collected, kept, chunk, cap)
        truncated |= discarded
        assert kept <= cap
        assert kept == sum(map(len, collected))
    data = b''.join(chunks)
    assert b''.join(collected) == data[:cap]
    assert truncated is (len(data) > cap)


def test_single_crossing_chunk_reports_truncation_immediately():
    chunks = []
    kept, discarded = spawn._append_capture_chunk(chunks, 0, b'x' * 65536, 7)
    assert kept == 7
    assert chunks == [b'x' * 7]
    assert discarded is True


@pytest.mark.parametrize('text,cap,expected', [
    ('\u00e9\u00e9', 3, '\u00e9'),
    ('\U0001f995\U0001f995', 4, '\U0001f995'),
    ('\U0001f995', 1, ''),
    ('a\u00e9b', 3, 'a\u00e9'),
    ('\u00e9', 0, ''),
])
def test_text_ceiling_counts_utf8_bytes_without_split_characters(text, cap, expected):
    result = subprocess.CompletedProcess(['x'], 0, stdout=text, stderr=text)
    _apply_capture_ceiling(result, cap)
    for label in ('stdout', 'stderr'):
        value = getattr(result, label)
        marker = f'\n[sandbox: {label} capture truncated at {cap} bytes]\n'
        assert value == expected + marker
        assert len(expected.encode('utf-8')) <= cap


def test_unicode_at_exact_byte_cap_is_unchanged():
    result = subprocess.CompletedProcess(['x'], 0, stdout='\u00e9\U0001f995', stderr=None)
    _apply_capture_ceiling(result, 6)
    assert result.stdout == '\u00e9\U0001f995'
    assert result.stderr is None

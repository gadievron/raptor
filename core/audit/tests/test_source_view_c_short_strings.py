"""Short-literal probes must never manufacture a closing boundary."""

import tracemalloc

import pytest

from core.audit import source_view as sv


@pytest.fixture(params=['normal', 'probe'], autouse=True)
def string_probe_mode(request, monkeypatch):
    if request.param == 'probe':
        monkeypatch.setattr(sv, '_C_RANGE_MIN_SOURCE', 0)
        monkeypatch.setattr(sv, '_C_RANGE_MIN_CHARS_PER_MARKER', 1)


@pytest.mark.parametrize('length', [0, 1, 2, 126, 127, 128, 129, 256])
@pytest.mark.parametrize('keep_strings', [False, True])
def test_real_closing_quote_at_window_boundaries(length, keep_strings):
    body = 'a' * length
    source = 'before(); "' + body + '"; live();'
    expected = source if keep_strings else 'before(); "' + ' ' * length + '"; live();'
    result = sv.sanitized_view_with_status(source, 'a.c', keep_strings=keep_strings)
    assert result.text == expected
    assert not result.ambiguous


@pytest.mark.parametrize('body', [
    r'a\"b', r'a\\b', 'a\\\nb',
    'a' * 126 + '\\\nrest', 'a' * 127 + '\\\nrest',
    'é🙂\x00\u2028',
])
@pytest.mark.parametrize('keep_strings', [False, True])
def test_escapes_and_continuations_at_probe_boundaries(body, keep_strings):
    source = 'before(); "' + body + '"; live();'
    blanked = ''.join('\n' if char == '\n' else ' ' for char in body)
    expected = source if keep_strings else 'before(); "' + blanked + '"; live();'
    result = sv.sanitized_view_with_status(source, 'a.cpp', keep_strings=keep_strings)
    assert result.text == expected
    assert not result.ambiguous


@pytest.mark.parametrize('body', ['short', 'a' * 127, 'a' * 128, 'tail\\'])
def test_unterminated_eof_retains_existing_view(body):
    source = 'before(); "' + body
    # Existing single-line EOF handling leaves the final character visible.
    expected = 'before(); "' + ' ' * (len(body) - 1) + body[-1]
    result = sv.sanitized_view_with_status(source, 'a.c')
    assert result.text == expected
    assert not result.ambiguous


def test_unescaped_lf_ends_the_single_line_literal():
    result = sv.sanitized_view_with_status('before(); "text\nlive();', 'a.c')
    assert result.text == 'before(); "    \nlive();'
    assert not result.ambiguous


def test_long_escaped_literals_keep_probe_workspace_bounded():
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    body = '\\n' * 50000
    source = 'before(); "' + body + '"; live();'
    tracemalloc.start()
    try:
        result = sv.sanitized_view_with_status(source, 'a.c')
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.text == 'before(); "' + ' ' * len(body) + '"; live();'
    assert not result.ambiguous
    assert peak < len(source) * 4

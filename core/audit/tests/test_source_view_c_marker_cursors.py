"""Cached marker positions expire across consumed lexical regions."""

import time

import pytest

from core.audit import source_view as sv


@pytest.fixture(autouse=True)
def force_marker_cursors(monkeypatch):
    monkeypatch.setattr(sv, '_C_RANGE_MIN_SOURCE', 0)
    monkeypatch.setattr(sv, '_C_RANGE_MIN_CHARS_PER_MARKER', 1)


@pytest.mark.parametrize('keep_strings', [False, True])
@pytest.mark.parametrize('source', [
    '''leading(); /* hidden_comment " ' / */ live_one(); "literal"; 'x'; live_two();''',
    r'''leading(); "literal /* ' \" /"; live_one(); 'x'; live_two();''',
    '''leading(); R"tag(literal /* "quote" ' /)tag"; live_one(); live_two();''',
    '''leading(); // hidden_comment " ' ''' + "\\\n" + 'still_hidden\nlive_one(); live_two();\n',
])
def test_cached_positions_inside_comments_and_literals(source, keep_strings):
    result = sv.sanitized_view_with_status(source, 'a.cpp', keep_strings=keep_strings)
    assert 'live_one();' in result.text
    assert 'live_two();' in result.text
    assert 'hidden_comment' not in result.text
    assert 'still_hidden' not in result.text
    if 'literal' in source:
        assert ('literal' in result.text) == keep_strings
    assert len(result.text) == len(source)
    assert result.text.count('\n') == source.count('\n')
    assert not result.ambiguous


def test_exhausted_quote_searches_do_not_restart():
    source = '"literal"; \'x\';\n' + ('ordinary_value / ' + 'x' * 64 + ';\n') * 50000
    started = time.process_time()
    result = sv.sanitized_view_with_status(source, 'a.c', keep_strings=True)
    elapsed = time.process_time() - started
    assert result.text == source
    assert not result.ambiguous
    assert elapsed < 1.0, f'exhausted marker search rescanned suffixes: {elapsed:.3f}s'

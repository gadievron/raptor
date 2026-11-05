"""Inert-text skipping preserves marker positions and diagnostics."""

import tracemalloc

import pytest

from core.audit.source_view import sanitized_view_with_status


@pytest.mark.parametrize(('extension', 'opener'), [('rb', '=begin'), ('pl', '=pod')])
@pytest.mark.parametrize('keep_strings', [False, True])
def test_doc_opener_after_long_ordinary_prefix(extension, opener, keep_strings):
    source = 'ordinary_call();\n' * 100 + opener + '\nhidden_call();\n'
    result = sanitized_view_with_status(source, 'a.' + extension,
                                        keep_strings=keep_strings)
    assert 'ordinary_call();' in result.text
    assert 'hidden_call' not in result.text
    assert result.reasons == ('unterminated-doc-block',)
    assert len(result.text) == len(source)
    assert result.text.count('\n') == source.count('\n')


@pytest.mark.parametrize('extension', ['py', 'rb', 'pl', 'sh', 'toml', 'yaml'])
def test_marker_free_source_has_bounded_temporary_allocation(extension):
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    source = 'ordinary_call(argument);\n' * 50000
    tracemalloc.start()
    try:
        result = sanitized_view_with_status(source, 'a.' + extension)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.text == source
    assert not result.ambiguous
    assert peak < 64 * 1024

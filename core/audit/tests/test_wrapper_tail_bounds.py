"""Wrapper gates reject at their existing two-match boundaries."""

import tracemalloc

import pytest

from core.audit.prefilter import _multiple_wrapper_statements, _wrapper_tail_gates


@pytest.mark.parametrize(('body', 'expected'), [
    pytest.param(' ; \t; delegate(); ; ', False, id='one-nonempty-part'),
    pytest.param(' ; delegate(); ; other(); ', True, id='two-nonempty-parts'),
])
def test_statement_count_ignores_empty_parts(body, expected):
    assert _multiple_wrapper_statements(body, ';') is expected


def test_custom_split_parts_keep_original_strip_calls():
    calls = []

    class Part(str):
        def strip(self):
            calls.append('strip')
            return 'statement'

    class Body(str):
        def split(self, separator):
            assert separator == ';'
            return [Part('first'), Part('second')]

    assert _multiple_wrapper_statements(Body('unused'), ';') is True
    assert calls == ['strip'] * 4


def test_return_rejection_does_not_collect_every_match():
    if tracemalloc.is_tracing():
        pytest.skip('Requires an independently owned allocation tracer')
    body = 'return delegate();\n' * 50000
    try:
        tracemalloc.start()
        result = _wrapper_tail_gates('c', body, 'delegate')
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == (False, '')
    assert peak < 128 * 1024, f'Wrapper rejection allocated {peak} bytes'

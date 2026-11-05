"""Provenance windows and accessor allocation preserve observable results."""

import tracemalloc

import pytest

from core.audit import protocol_state as ps, struct_accessor_index as sa


def test_local_window_keeps_last_assignment_and_key_order():
    source = ('header' * 3000 + '\n'
              'v = decode_old(x);\nv = decode_new(x);\nu = get_peer(x);\n'
              'v = outside(x);\n')
    assert list(ps._local_call_sources(source, (2, 4)).items()) == [
        ('v', 'decode_new'), ('u', 'get_peer'),
    ]


def test_local_window_trims_only_one_trailing_cr(monkeypatch):
    seen = []
    pattern = ps._LOCAL_CALL_ASSIGN_RE

    class Capture:
        def finditer(self, text):
            seen.append(text)
            return pattern.finditer(text)

    monkeypatch.setattr(ps, '_LOCAL_CALL_ASSIGN_RE', Capture())
    source = 'header' * 3000 + '\nv = decode(x);\r\r\n'
    assert ps._local_call_sources(source, (2, 2)) == {'v': 'decode'}
    assert seen == ['v = decode(x);\r']


def test_negative_span_keeps_python_slice_semantics():
    source = 'header' * 3000 + '\na = first();\nb = second();\nc = third();\n'
    assert ps._local_call_sources(source, (-2, -1)) == {'a': 'first', 'b': 'second'}


def test_impossible_local_lines_skip_assignment_regex(monkeypatch):
    class UnexpectedScan:
        def finditer(self, text):
            pytest.fail('Line lacks a required assignment-call marker')

    monkeypatch.setattr(ps, '_LOCAL_CALL_ASSIGN_RE', UnexpectedScan())
    assert ps._local_call_sources('void f(void) {\nx = y;\nf();\n}\n', None) == {}


def test_connector_free_source_skips_accessor_regex(monkeypatch):
    class UnexpectedScan:
        def finditer(self, text):
            pytest.fail('Source lacks a required field connector')

    monkeypatch.setattr(sa, '_FIELD_ACCESS_RE', UnexpectedScan())
    assert sa._extract_fields('alpha = beta; return value;') == set()


def test_accessor_index_retains_plain_dict_and_record_order():
    index = sa.build_index_from_source([
        {'name': 'first', 'file': 'x.c', 'source': 'p->epoch_value;'},
        {'name': 'second', 'file': 'x.c', 'source': 'p->epoch_value;'},
    ])
    assert type(index) is dict
    assert [r.function for r in index['epoch_value']] == ['first', 'second']
    with pytest.raises(KeyError):
        index['absent']


def test_custom_source_keeps_original_local_split():
    calls = []

    class Source(str):
        def split(self, *args, **kwargs):
            calls.append((args, kwargs))
            return super().split(*args, **kwargs)

    source = Source('header' * 3000 + '\nv = decode(x);\n')
    assert ps._local_call_sources(source, (2, 2)) == {'v': 'decode'}
    assert calls == [(('\n',), {})]


def test_early_local_window_does_not_split_entire_source():
    if tracemalloc.is_tracing():
        pytest.skip('Requires an independently owned allocation tracer')
    source = 'x = y;\n' * 100000
    try:
        tracemalloc.start()
        result = ps._local_call_sources(source, (10, 20))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == {}
    assert peak < 128 * 1024, f'Local provenance allocated {peak} bytes'

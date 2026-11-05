"""Field-line admission preserves both legacy line models and sites."""

import tracemalloc

import pytest

from core.audit import field_census as fc, protocol_state as ps
from core.source.lines import _NON_NL_BREAKERS


_SOURCE = 'int f(void) {\n    x = y;\n    p->field = value;\n}\n'


def test_native_lf_source_reuses_one_line_view(monkeypatch):
    def unexpected_split(source):
        pytest.fail('Compatible line models were split twice')

    monkeypatch.setattr(fc, 'split_lines', unexpected_split)
    raw = {}
    fc._scan_file_regex(_SOURCE, 'x.c', raw, lambda name: True)
    assert raw['field'].writes[0].line == 3
    assert raw['field'].writes[0].function == 'f'


@pytest.mark.parametrize('breaker', _NON_NL_BREAKERS,
                         ids=['cr', 'vt', 'ff', 'fs', 'gs', 'rs', 'nel', 'ls', 'ps'])
def test_differing_line_models_keep_canonical_split(monkeypatch, breaker):
    calls = []
    original = fc.split_lines

    def canonical(source):
        calls.append(source)
        return original(source)

    monkeypatch.setattr(fc, 'split_lines', canonical)
    source = 'int f(void) {\n    // ' + breaker + 'break\n    p->field = value;\n}\n'
    raw = {}
    fc._scan_file_regex(source, 'x.c', raw, lambda name: True)
    assert calls == [source]
    assert raw['field'].writes[0].line == 3


def test_subclass_keeps_both_split_calls():
    calls = []

    class Source(str):
        def splitlines(self, *args, **kwargs):
            calls.append('splitlines')
            return super().splitlines(*args, **kwargs)

        def split(self, *args, **kwargs):
            calls.append('split')
            return super().split(*args, **kwargs)

    raw = {}
    fc._scan_file_regex(Source(_SOURCE), 'x.c', raw, lambda name: True)
    assert calls == ['splitlines', 'split']
    assert raw['field'].writes[0].line == 3


def test_protocol_connector_free_lines_skip_chain_scans(monkeypatch):
    class UnexpectedScan:
        def finditer(self, text):
            pytest.fail('Connector-free line reached a field-chain scan')

    monkeypatch.setattr(ps, '_FIELD_CHAIN_RE', UnexpectedScan())
    monkeypatch.setattr(ps, '_FIELD_CHAIN_AFTER_CLOSER_RE', UnexpectedScan())
    assert ps.build_state_field_index({'x.c': 'void f(void) {\n x = y;\n}\n'}) == {
        'fields': {}, 'tier': 'regex', 'skipped': False,
    }


def test_protocol_keeps_dot_and_arrow_sites():
    index = ps.build_state_field_index({
        'x.c': 'void f(void) {\n arr[0].head.tail = 1;\n ++p->other;\n}\n',
    })
    assert index['fields']['tail']['writes'][0]['line'] == 2
    assert index['fields']['other']['writes'][0]['line'] == 3


def test_sparse_census_does_not_retain_duplicate_line_lists():
    if tracemalloc.is_tracing():
        pytest.skip('Requires an independently owned allocation tracer')
    source = '    x = y;\n' * 50000
    try:
        tracemalloc.start()
        raw = {}
        fc._scan_file_regex(source, 'x.c', raw, lambda name: True)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert raw == {}
    assert peak < 4 * 1024 * 1024, f'Sparse census allocated {peak} bytes'

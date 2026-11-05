"""Prepass cache reuse and lazy loop metadata retain existing behavior."""

from types import SimpleNamespace

import pytest

from core.audit import resource_bounds as rb


def _fixed_prepass(monkeypatch):
    monkeypatch.setattr(rb, 'time', SimpleNamespace(monotonic=lambda: 0.0))
    monkeypatch.setattr(rb, '_insert_vocabulary', lambda *args: {'list_add': ('seed', 'test')})
    monkeypatch.setattr(rb, '_alloc_vocabulary', lambda *args: {})
    monkeypatch.setattr(rb, '_adjudicate_site', lambda *args, **kwargs:
                        rb.BoundEvidence(outcome='refuted', reason='supplied fixture verdict'))


@pytest.mark.parametrize('body', ['list_add(p);', 'ordinary(p);'],
                         ids=['insert-takes-precedence', 'no-allocation-match'])
def test_loop_metadata_is_not_built_without_an_allocation_match(monkeypatch, body):
    def unexpected(lines, start):
        pytest.fail('Loop metadata was built without an allocation match')

    monkeypatch.setattr(rb, '_loop_lines', unexpected)
    sites = rb._enumerate_sites([body], 1, {'list_add': ('seed', 'test')},
                                {'malloc': ('seed', 'test')}, file_path='x.c')
    assert len(sites) == (1 if body.startswith('list_add') else 0)


def test_empty_loop_metadata_is_computed_only_once(monkeypatch):
    calls = []

    def no_loops(lines, start):
        calls.append(start)
        return set()

    monkeypatch.setattr(rb, '_loop_lines', no_loops)
    assert rb._enumerate_sites(['malloc(n);', 'malloc(n);'], 10, {},
                                {'malloc': ('seed', 'test')}, file_path='x.c') == []
    assert calls == [10]


@pytest.mark.parametrize('native', [True, False], ids=['native-source', 'subclass-source'])
def test_prepass_split_work_and_subclass_fallback(monkeypatch, native):
    _fixed_prepass(monkeypatch)

    class Source(str):
        pass

    text = '\n'.join(f'void f_{i}(void) {{\n list_add(p);\n}}\n' for i in range(3))
    source = text if native else Source(text)
    calls = []
    original = rb.split_lines

    def split(value):
        if value is source:
            calls.append(value)
        return original(value)

    monkeypatch.setattr(rb, 'split_lines', split)
    result = rb.run_resource_bounds_prepass({'x.c': source})
    assert result['telemetry']['candidates'] == 3
    assert result['telemetry']['refuted'] == 3
    assert len(calls) == (1 if native else 5)


def test_precomputed_span_input_is_read_only():
    lines = ['void f(void) {', ' list_add(p);', '}']
    before = list(lines)
    assert rb._c_function_spans_from_lines(lines) == [('f', 1, 3)]
    assert lines == before


def test_parenthesis_free_prepass_skips_insert_patterns(monkeypatch):
    _fixed_prepass(monkeypatch)

    class UnexpectedSearch:
        def search(self, text):
            pytest.fail('Insert pattern searched text without a call opener')

    monkeypatch.setattr(rb, '_call_re', lambda names: UnexpectedSearch())
    result = rb.run_resource_bounds_prepass({'x.c': 'int count = 4;\n'})
    assert result['telemetry']['candidates'] == 0

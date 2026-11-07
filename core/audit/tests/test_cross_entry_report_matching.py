"""Grouped report matching keeps definition order, ambiguity gates and aliases."""

from dataclasses import replace

import pytest

from core.audit.cross_entry import runner
from core.audit.cross_entry.integration import prepare_cross_entry
from core.audit.cross_entry.model import AccessIndex, Function, Limits
from core.json import load_json


@pytest.fixture
def data():
    index = AccessIndex()
    for fid, file in [('z', 'component/z.c'), ('duplicate1', 'component/duplicate.c'),
                      ('a', 'component/a.c'), ('duplicate2', 'component/duplicate.c'),
                      ('unrelated', 'other.c')]:
        index.functions[fid] = Function(fid, file, 'run', 1, 1, 0, 1, 'hash', 'void run(void){}')
    reports = {
        'component/a.c:run': 'a.c:run',
        'component/missing.c:run': 'missing.c:run',
        'component/duplicate.c:run': 'duplicate.c:run',
        'component/z.c:run': 'z.c:run',
    }
    return index, reports


def test_groups_keep_function_order_and_report_local_labels(data):
    index, reports = data
    requested, matches = runner._match_reports(index, reports)
    assert list(requested) == ['z', 'duplicate1', 'a', 'duplicate2']
    assert list(requested.values()) == ['z.c:run', 'duplicate.c:run', 'a.c:run', 'duplicate.c:run']
    assert matches == {
        'component/z.c:run': ['z'],
        'component/duplicate.c:run': ['duplicate1', 'duplicate2'],
        'component/a.c:run': ['a'],
    }
    assert matches.get('component/missing.c:run', ()) == ()


def test_function_mapping_is_traversed_once(data):
    index, reports = data

    class Counted(dict):
        scans = 0

        def values(self):
            self.scans += 1
            return super().values()

    index.functions = Counted(index.functions)
    runner._match_reports(index, reports)
    assert index.functions.scans == 1


def test_returned_containers_and_inputs_are_independent(data):
    index, reports = data
    before_index, before_reports = index.to_dict(), reports.copy()
    requested, matches = runner._match_reports(index, reports)
    requested.clear()
    matches['component/a.c:run'].append('invented')
    again, groups = runner._match_reports(index, reports)
    assert again['a'] == 'a.c:run'
    assert groups['component/a.c:run'] == ['a']
    assert index.to_dict() == before_index
    assert reports == before_reports


@pytest.mark.parametrize('reports', [{}, {'missing.c:run': 'missing'}], ids=['no-reports', 'missing-only'])
def test_empty_or_unmatched_reports_keep_empty_results(data, reports):
    index, _ = data
    assert runner._match_reports(index, reports) == ({}, {})


def require_grammar():
    from core.audit.callsite_consistency import parse_source_cached
    if parse_source_cached('probe.c', 'int f(void){return 0;}')[0] is None:
        pytest.skip('requires tree-sitter C grammar')


def repository(tmp_path):
    from core.audit.tests.test_cross_entry import sources
    component = tmp_path / 'component'
    component.mkdir()
    for path, source in sources().items():
        (component / path).write_text(source)
    return component


def test_ambiguity_and_missing_diagnostics_keep_canonical_report_order(tmp_path):
    require_grammar()
    component = repository(tmp_path)
    (component / 'ambiguous.c').write_text(
        '#include "state.h"\n#if MODE\n'
        'int ambiguous(struct state *s){return s->len;}\n#else\n'
        'int ambiguous(struct state *s){return s->ready;}\n#endif\n'
    )
    out = tmp_path / 'out'
    contexts = prepare_cross_entry(component, [
        {'file': 'ambiguous.c', 'name': 'ambiguous'},
        {'file': 'reader.c', 'name': 'absent'},
        {'file': 'reader.c', 'name': 'get'},
    ], mode='context', out_dir=out, context_root=tmp_path, include_dirs=(component,))
    assert set(contexts) == {'reader.c:get'}
    index = load_json(out / 'cross-entry-index.json')
    reports = [item['report'] for item in index['coverage']['unresolved']
               if item.get('reason') == 'ambiguous_or_missing_report_definition']
    assert reports == ['component/ambiguous.c:ambiguous', 'component/reader.c:absent']


def test_warm_lookup_is_reused_and_expanded_index_gets_its_own_lookup(tmp_path, monkeypatch):
    require_grammar()
    component = repository(tmp_path)
    calls = []
    original = runner._match_reports

    def match(index, reports):
        result = original(index, reports)
        calls.append((index, result[0].copy()))
        return result

    monkeypatch.setattr(runner, '_match_reports', match)
    kwargs = dict(mode='context', out_dir=tmp_path / 'out', context_root=tmp_path,
                  include_dirs=(component,), limits=replace(Limits(), max_files=2))
    gaps = [{'file': 'reader.c', 'name': 'get'}]
    prepare_cross_entry(component, gaps, **kwargs)
    assert len(calls) == 1
    prepare_cross_entry(component, gaps, **kwargs)
    assert len(calls) == 3
    assert calls[1][0] is not calls[2][0]
    assert all(list(requested.values()) == ['reader.c:get'] for _, requested in calls)

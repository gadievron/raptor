"""Preparation reuses bounded parsing work and read-only catalogue summaries."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from core.audit.cross_entry import runner
from core.audit.cross_entry.model import Access, AccessIndex, Call, Limits, Relation
from core.json import load_json


def term_index(count=300):
    index = AccessIndex()
    index.accesses = [Access(str(i), 'f', 'a.c', 1, 0, 1, 'a.c:0:struct state',
                             'p', 'payload.size', 'read', 'p->payload.size') for i in range(count)]
    index.calls = [Call('f', 'process', [], 1) for _ in range(count)]
    return index


@pytest.fixture
def regex_calls(monkeypatch):
    real = runner.re
    calls = {'search': 0, 'findall': 0, 'fullmatch': 0}

    def tracked(name):
        def invoke(*args, **kwargs):
            calls[name] += 1
            return getattr(real, name)(*args, **kwargs)
        return invoke

    monkeypatch.setattr(runner, 're', SimpleNamespace(**{name: tracked(name) for name in calls}))
    return calls


def test_repeated_native_values_are_parsed_once(regex_calls):
    index = term_index()
    assert runner._terms(index, ['f'], 3) == {'type:state', 'field:payload', 'field:size', 'symbol:process'}
    assert regex_calls == {'search': 1, 'findall': 1, 'fullmatch': 1}


def test_small_inputs_keep_direct_parsing(regex_calls):
    runner._terms(term_index(3), ['f'], 3)
    assert regex_calls == {'search': 3, 'findall': 3, 'fullmatch': 3}


class AdaptedName(str):
    __hash__ = None


@pytest.mark.parametrize('attribute,kind', [('type_id', 'search'), ('member_path', 'findall'), ('name', 'fullmatch')])
def test_adapted_strings_keep_direct_regex_handling(regex_calls, attribute, kind):
    index = term_index()
    rows = index.calls if attribute == 'name' else index.accesses
    for value in rows:
        setattr(value, attribute, AdaptedName(getattr(value, attribute)))
    assert runner._terms(index, ['f'], 3) == {'type:state', 'field:payload', 'field:size', 'symbol:process'}
    assert regex_calls[kind] == 300


def test_diverse_values_are_not_truncated_when_reuse_stops(monkeypatch, regex_calls):
    monkeypatch.setattr(runner, '_TERM_REUSE_LIMIT', 2)
    index = term_index(20)
    for number, (access, call) in enumerate(zip(index.accesses, index.calls)):
        access.type_id = f'a.c:0:struct state{number}'
        access.member_path = f'member{number}'
        call.name = f'process{number}'
    expected = {prefix + str(i) for prefix in ('type:state', 'field:member', 'symbol:process') for i in range(20)}
    assert runner._terms(index, ['f'], 0) == expected
    assert regex_calls == {'search': 20, 'findall': 20, 'fullmatch': 20}


def test_reuse_is_not_carried_across_invocations():
    index = term_index()
    runner._terms(index, ['f'], 0)
    for access in index.accesses:
        access.type_id = 'a.c:0:union changed'
        access.member_path = 'new_value'
    for call in index.calls:
        call.name = 'updated'
    assert runner._terms(index, ['f'], 0) == {'type:changed', 'field:new_value', 'symbol:updated'}


@pytest.mark.parametrize('depth', [0, 1, 2])
def test_reachability_depth_and_relation_kinds_stay_unchanged(depth):
    index = term_index()
    index.relations = [Relation('f', 'g', 'call', 'e'), Relation('g', 'h', 'call', 'e'),
                       Relation('f', 'other', 'resource_assignment', 'e')]
    for fid in ('g', 'h', 'other'):
        index.accesses.append(Access(fid, fid, 'a.c', 1, 0, 1, f'struct {fid}', 'p', fid, 'read', fid))
    expected = {'type:state', 'field:payload', 'field:size', 'symbol:process'}
    for fid in ('g', 'h')[:depth]:
        expected |= {'type:' + fid, 'field:' + fid}
    assert runner._terms(index, ['f'], depth) == expected


@pytest.fixture
def locations(tmp_path):
    root, out = tmp_path / 'src', tmp_path / 'out'
    root.mkdir()
    out.mkdir()
    return root, out


@pytest.fixture
def summary_reads(monkeypatch):
    reads, rendered = [], []
    original = runner.Catalogue
    json_text = runner.json_text

    class CountedCatalogue(original):
        def summary(self):
            value = super().summary()
            reads.append(value)
            return value

    def capture(value):
        if isinstance(value, dict) and 'repository' in value:
            rendered.append((value['repository'], len(reads)))
        return json_text(value)

    monkeypatch.setattr(runner, 'Catalogue', CountedCatalogue)
    monkeypatch.setattr(runner, 'json_text', capture)
    return reads, rendered


def test_context_batch_reuses_summary_and_next_invocation_refreshes(locations, summary_reads):
    from core.audit.callsite_consistency import parse_source_cached
    if parse_source_cached('probe.c', 'int f(void){return 0;}')[0] is None:
        pytest.skip('requires tree-sitter C grammar')
    root, out = locations
    (root / 'a.c').write_text('struct state {int value;};\n' + ''.join(
        f'int get{i}(struct state *p){{return p->value;}}\n' for i in range(3)))
    gaps = [{'file': 'a.c', 'name': f'get{i}'} for i in range(3)]
    limits = replace(Limits(), graph_seconds=100, scan_seconds=100)
    reads, rendered = summary_reads
    first = runner.prepare(root, gaps, mode='context', out_dir=out, limits=limits, include_dirs=(root,))
    assert len(first) == len(rendered) == 3
    snapshot = rendered[0][0]
    assert all(value is snapshot for value, _ in rendered)
    assert len({count for _, count in rendered}) == 1
    assert len(reads) == rendered[-1][1]
    assert snapshot['files'] == {'indexed': 1}
    assert load_json(out / 'cross-entry-progress.json')['indexing'] == snapshot
    (root / 'unrelated.c').write_text('int unrelated(void){return 0;}')
    rendered.clear()
    second = runner.prepare(root, gaps, mode='context', out_dir=out, limits=limits, include_dirs=(root,))
    assert len(second) == len(rendered) == 3
    assert rendered[0][0] is not snapshot
    assert rendered[0][0]['files'] == {'indexed': 2}
    assert all(value is rendered[0][0] for value, _ in rendered)


def test_empty_index_progress_queries_summary_once(locations, summary_reads):
    root, out = locations
    reads, rendered = summary_reads
    assert runner.prepare(root, [], mode='index', out_dir=out, include_dirs=(root,)) == {}
    assert len(reads) == 2  # advance() and progress(), one query group each.
    assert rendered == []
    progress = json.loads((out / 'cross-entry-progress.json').read_text())
    assert progress['indexing']['index_complete']
    assert not progress['work_remaining']

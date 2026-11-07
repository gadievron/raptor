"""Bounded prompt metadata preserves source order, omission counts and evidence."""

import json
from dataclasses import replace

import pytest

from core.audit.cross_entry import study
from core.audit.cross_entry.model import Access, AccessIndex, Call, Function, Limits, StudySlice


@pytest.fixture
def data():
    index = AccessIndex()
    ids = ['a.c:1:full', 'a.c:2:omitted', 'a.c:3:unrelated']
    for number, fid in enumerate(ids):
        source = 'void f(struct state *p){consume(p->value);}'
        if number == 1:
            source += '/* padding */' * 400
        index.functions[fid] = Function(fid, 'a.c', 'f', number + 1, number + 1, 0, len(source), 'hash', source)
    index.declarations = {
        'state': {'file': 'a.c', 'line': 1, 'source': 'struct state {int value;};'},
        'omitted': {'file': 'a.c', 'line': 1, 'source': 'struct omitted {int x;};'},
        'global:counter': {'file': 'a.c', 'line': 1, 'source': 'int counter;'},
        'unrelated': {'file': 'a.c', 'line': 1, 'source': 'struct unrelated {int x;};'},
    }
    for number in range(21):
        index.accesses.append(Access(f'access{number}', ids[0], 'a.c', 1, number, number + 1,
                                     'state', 'local:p', 'value', 'read', 'p->value'))
    index.accesses.insert(0, Access('unrelated', ids[2], 'a.c', 3, 0, 1,
                                   'unrelated', 'local:q', 'x', 'read', 'q->x'))
    index.accesses.append(Access('omitted-access', ids[1], 'a.c', 2, 0, 1,
                                 'omitted', 'global:counter', 'x', 'read', 'counter'))
    index.calls = [Call(ids[0], f'call{number}', [f'argument{number}'], 1) for number in range(31)]
    index.calls.insert(0, Call(ids[2], 'unrelated', [], 3))
    unit = StudySlice('unit', ids[0], [ids[0]], [], [], [], [], [], 0, '', 'fingerprint')
    limits = replace(Limits(), input_tokens=100000, output_tokens=0)
    return index, unit, limits


@pytest.fixture
def captured(monkeypatch):
    result = {'metadata': [], 'source': [], 'kinds': []}
    original = study.wrap_untrusted

    def wrap(content, *, kind, origin):
        result['kinds'].append(kind)
        if kind == 'cross-entry-metadata':
            result['metadata'].append(json.loads(content))
        elif kind == 'cross-entry-source':
            result['source'].append(content)
        return original(content, kind=kind, origin=origin)

    monkeypatch.setattr(study, 'wrap_untrusted', wrap)
    return result


def test_caps_order_omissions_and_evidence(data, captured):
    index, unit, limits = data
    _, allowed, present = study._payload(index, unit, unit.functions, limits)
    metadata = captured['metadata'][-1]
    assert [a['id'] for a in metadata['accesses']] == [f'access{i}' for i in range(16)]
    assert metadata['omitted_accesses'] == 5
    assert [c['name'] for c in metadata['calls']] == [f'call{i}' for i in range(24)]
    assert metadata['omitted_calls'] == 7
    assert present == {unit.consumer}
    assert allowed == {unit.consumer, 'state'} | {f'access{i}' for i in range(16)}


def test_omitted_bodies_still_nominate_declarations(data, captured):
    index, unit, limits = data
    omitted = 'a.c:2:omitted'
    _, allowed, present = study._payload(index, unit, [unit.consumer, omitted], replace(limits, source_chars=400))
    metadata = captured['metadata'][-1]
    assert metadata['omitted_bodies'] == [omitted]
    assert {'state', 'omitted', 'global:counter'} <= allowed
    assert omitted not in present
    assert 'omitted-access' not in allowed
    assert metadata['omitted_accesses'] == 5


def test_duplicate_function_entries_keep_body_order(data, captured):
    index, unit, limits = data
    study._payload(index, unit, [unit.consumer, unit.consumer], limits)
    assert captured['source'][-1].count('FUNCTION_ID ' + unit.consumer) == 2
    assert captured['metadata'][-1]['omitted_accesses'] == 5


def test_metadata_clipping_keeps_exact_evidence_ids(data, captured):
    index, unit, limits = data
    first = index.accesses[1]
    first.id = 'evidence-' + 'x' * 700
    first.object_origin = 'origin-' + 'y' * 700
    first.expression = 'not metadata'
    first.rhs = 'not metadata either'
    _, allowed, _ = study._payload(index, unit, unit.functions, limits)
    rendered = captured['metadata'][-1]['accesses'][0]
    assert rendered['id'] == first.id
    assert rendered['object_origin'] == first.object_origin[:512]
    assert 'expression' not in rendered and 'rhs' not in rendered
    assert first.id in allowed


def test_budget_shedding_conserves_counts_and_keeps_wrapping_each_render(data, captured):
    index, unit, limits = data
    for call in index.calls:
        call.arguments = ['argument-' + 'x' * 700] * 8
    _, allowed, _ = study._payload(index, unit, unit.functions, replace(limits, input_tokens=3000, output_tokens=250))
    metadata = captured['metadata'][-1]
    assert len(captured['metadata']) > 1
    assert len(captured['source']) == len(captured['metadata'])
    assert captured['kinds'] == ['cross-entry-metadata', 'cross-entry-source'] * len(captured['source'])
    assert all(source == captured['source'][0] for source in captured['source'])
    assert metadata['omitted_accesses'] + len(metadata['accesses']) == 21
    assert metadata['omitted_calls'] + len(metadata['calls']) == 31
    assert {a['id'] for a in metadata['accesses']} == {a for a in allowed if a.startswith('access')}


def test_metadata_arrays_are_traversed_once_without_dispatch(data, captured):
    index, unit, limits = data

    class Counted(list):
        scans = 0

        def __iter__(self):
            self.scans += 1
            return super().__iter__()

    index.accesses = Counted(index.accesses)
    index.calls = Counted(index.calls)
    study._payload(index, unit, unit.functions, limits)
    assert index.accesses.scans == index.calls.scans == 1


def test_inputs_and_returned_sets_remain_independent(data, captured):
    index, unit, limits = data
    before_index, before_unit = index.to_dict(), unit.to_dict()
    _, allowed, present = study._payload(index, unit, unit.functions, limits)
    expected = allowed.copy(), present.copy()
    allowed.clear()
    present.clear()
    _, allowed, present = study._payload(index, unit, unit.functions, limits)
    assert (allowed, present) == expected
    assert index.to_dict() == before_index
    assert unit.to_dict() == before_unit

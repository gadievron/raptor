"""Bounded catalogue retention preserves packets, path budgets and omissions."""

from dataclasses import replace

import pytest

from core.audit.cross_entry.dispatch import dispatch_catalogue
from core.audit.cross_entry.model import Access, Call
from core.audit.tests.test_dispatch_catalogue_work import catalogue, effects


@pytest.mark.parametrize('sites', [3, 4, 5, 100])
def test_packet_cap_counts_every_unique_effect(sites):
    index, rows = catalogue(''.join(f'ctx->field{i} = {i};\n' for i in range(sites)), calls=False)
    # Repeated occurrences with the same location/source count only once.
    index.accesses += [replace(index.accesses[0], id='duplicate'),
                       replace(index.accesses[-1], id='last-duplicate')]
    emitted, omitted = dispatch_catalogue(index, rows, 100000)
    assert [f['evidence_id'] for f in effects(emitted)] == ['a0', 'a1', 'a2']
    assert [f['kind'] for f, _ in emitted] == ['dispatch_path', 'callback_assignment'] + ['effect_fragment'] * 3
    assert omitted == sites - 3


def test_unrelated_records_do_not_change_catalogue_or_inputs():
    index, rows = catalogue('ctx->field = 1;\n', calls=False)
    expected = dispatch_catalogue(index, rows, 10000)
    for i in range(100):
        index.accesses.insert(0, Access(f'unrelated{i}', f'other{i}', 'other.c', 1, 0, 1,
                                       'T', 'ctx', 'field', 'write', 'ctx->field'))
        index.calls.append(Call(f'other{i}', 'work', [], 1))
    before = index.to_dict()
    assert dispatch_catalogue(index, rows, 10000) == expected
    assert index.to_dict() == before


@pytest.mark.parametrize('boundary', [-1, 0, 1])
def test_oversized_path_leaves_room_for_later_path(boundary):
    index, rows = catalogue('', calls=False)
    index.declarations['binding']['source'] = 'x' * 10000
    index.declarations['small'] = {'file': 'setup.c', 'line': 2, 'source': 'ops.next = f;'}
    rows[0]['dispatch_path'] = [
        {'caller': 'setup', 'evidence_id': 'binding', 'alias_evidence': ['missing']},
        {'caller': 'setup', 'evidence_id': 'small'},
        {'caller': 'setup', 'evidence_id': 'small'},
    ]
    rendered = '\nCONDITIONAL DISPATCH PATH EVIDENCE small (setup.c:2)\nops.next = f;\n'
    emitted, omitted = dispatch_catalogue(index, rows, 8 * len(rendered) + boundary)
    if boundary < 0:
        assert emitted == []
        assert omitted == 3  # One callback assignment and two unique paths.
    else:
        assert [(f['evidence_id'], text) for f, text in emitted] == [('small', rendered)]
        assert omitted == 2


@pytest.mark.parametrize('budget', [-10, 0, 1])
def test_unemitted_effects_and_paths_remain_counted(budget):
    index, rows = catalogue('ctx->a = 1;\nctx->b = 2;\n', calls=False)
    assert dispatch_catalogue(index, rows, budget) == ([], 4)


def test_empty_target_selection_returns_no_fragments():
    index, _ = catalogue('ctx->a = 1;\n', calls=True)
    assert dispatch_catalogue(index, [], 10000) == ([], 0)

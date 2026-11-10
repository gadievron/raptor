"""Affine subscripts preserve promoted arithmetic and caller witness identity."""

from dataclasses import replace

import pytest

from core.audit.array_bounds import bind_array_access, check_array_bounds
from core.audit.array_index import evaluate_array_index
from core.audit.literal_call import check_literal_calls, literal_call_witness_valid

SOURCE = 'int Read(unsigned Index){int Data[4]={0};if(Index>=0&&Index<4)return Data[Index+1];return 0;}'
CLAIM = 'Potential out-of-bounds read at `Data[Index+1]`.'


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
@pytest.mark.parametrize('spelling', ['unsigned', 'signed char'])
def test_defined_affine_index_exhibits_an_off_by_one(language, abi, spelling):
    pytest.importorskip('tree_sitter_' + language)
    source = SOURCE.replace('unsigned Index', spelling + ' Index')
    result = check_array_bounds(source, CLAIM, language=language, integer_abi=abi)
    assert result['violation'] is True, result
    assert result['model']['Index'] == 3 and result['witness_index'] == 4
    assert result['source_access']['index_operator'] == '+'
    assert result['source_access']['index_offset'] == 1


def test_tighter_guard_has_no_affine_bounds_counterexample():
    result = check_array_bounds(SOURCE.replace('Index<4', 'Index<3'), CLAIM, language='c', integer_abi='lp64')
    assert result['array_bounds_status'] == 'checked' and result['violation'] is False, result


def test_unsigned_subtraction_is_replayed_modulo_the_promoted_width():
    source = SOURCE.replace('Index<4', 'Index==0').replace('Index+1', 'Index-1')
    result = check_array_bounds(source, CLAIM.replace('Index+1', 'Index-1'), language='c', integer_abi='lp64')
    assert result['violation'] is True and result['model']['Index'] == 0, result
    assert result['witness_index'] == (1 << 32) - 1


def test_unsigned_addition_wrap_does_not_invent_a_large_witness_index():
    access = bind_array_access(SOURCE.replace('if(Index>=0&&Index<4)', ''), CLAIM, language='c', integer_abi='lp64')
    assert access.status == 'bound', access
    assert evaluate_array_index(access, {'Index': (1 << 32) - 1}, 'lp64') == 0
    from core.audit.array_bounds import _valid_witness
    assert not _valid_witness(access, {'Index': (1 << 32) - 1}, 'lp64')


def test_unproved_signed_prefix_is_not_silently_excluded():
    result = check_array_bounds(SOURCE.replace('unsigned Index', 'int Index'), CLAIM,
                                language='c', integer_abi='lp64')
    assert result['array_bounds_status'] == 'unavailable' and result['violation'] is None, result


@pytest.mark.parametrize('source,claim', [
    (SOURCE, CLAIM.replace('Index+1', 'Index+2')),
    (SOURCE.replace('Index+1', '1+Index'), CLAIM),
    (SOURCE.replace('Index+1', 'Index+Other'), CLAIM),
    (SOURCE.replace('Index+1', 'Index+1+1'), CLAIM),
    (SOURCE.replace('unsigned Index', 'float Index'), CLAIM),
    (SOURCE.replace('if(Index>=0&&Index<4)', 'Index=3;if(Index>=0&&Index<4)'), CLAIM),
    (SOURCE, 'No out-of-bounds read at `Data[Index+1]`.'),
    (SOURCE, CLAIM.replace('Data[Index+1]', 'Data[Index+1];return 0')),
])
def test_source_claim_type_effect_and_complete_expression_refusals(source, claim):
    result = check_array_bounds(source, claim, language='c', integer_abi='lp64')
    assert result['violation'] is None, result


@pytest.mark.parametrize('argument,verdict', [(3, 'violation'), (2, 'safe'), (4, 'guard-excluded')])
def test_literal_caller_uses_computed_index_not_the_parameter_value(argument, verdict):
    source = SOURCE + f'\nint Drive(void){{return Read({argument});}}\n'
    reply = check_literal_calls(source, 'Read', 'check-array-bounds', CLAIM, 'lp64', [2], 'c')
    assert reply['status'] == 'checked' and len(reply['calls']) == 1, reply
    call = reply['calls'][0]
    assert call['verdict'] == verdict, reply
    if verdict == 'violation':
        assert call['witness_index'] == 4
        assert literal_call_witness_valid(reply, call, 'check-array-bounds', CLAIM, 'lp64')
        assert not literal_call_witness_valid(reply, {**call, 'witness_index': 3}, 'check-array-bounds', CLAIM, 'lp64')
        from copy import deepcopy
        forged = deepcopy(reply)
        forged['callee_obligation']['index_offset'] = 2
        assert not literal_call_witness_valid(forged, call, 'check-array-bounds', CLAIM, 'lp64')


def test_index_metadata_cannot_choose_a_different_conversion():
    access = bind_array_access(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert access.status == 'bound'
    assert evaluate_array_index(replace(access, signed=True), {'Index': 3}, 'lp64') is None
    assert evaluate_array_index(replace(access, width=64), {'Index': 3}, 'lp64') is None


def test_affine_candidate_preparation_remains_solver_free(monkeypatch):
    from core.audit import array_bounds
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses

    def forbidden(*a, **kw):
        raise AssertionError('affine candidate acquired native proof credit')

    monkeypatch.setattr(array_bounds, 'guards_for_operation', forbidden)
    monkeypatch.setattr(array_bounds, '_solve_access', forbidden)
    gap = {'file': 'unit.c', 'name': 'Read', 'line_start': 1, 'line_end': 1}
    seed_arithmetic_hypotheses([gap], {'unit.c': SOURCE}, mode='quality', integer_abi='lp64')
    rows = [row for row in gap['injected_hypotheses'] if row['mechanism'] == CLAIM]
    assert len(rows) == 1, gap
    assert rows[0]['arithmetic_site']['binding_status'] == 'candidate'
    assert rows[0]['arithmetic_site']['index_offset'] == 1
    assert rows[0]['confidence'] == 'low' and 'verdict' not in rows[0]


@pytest.mark.slow
def test_real_confined_affine_array_worker_keeps_the_computed_index():
    from core.audit import sweep
    result = sweep.run_smt_verb_direct(file_path='unit.c', function_name='Read', verb='check-array-bounds',
                                      source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['witness_index'] == 4 and result.details['model']['Index'] == 3
    assert result.details['source_scope']['query_contract'] == 'common-width-array-guards-v15'
    assert result.details['oracle_scope'] == 'fixed-local-array-access'
    assert result.details['obligation'] == '(Index+1) < 0 OR (Index+1) >= 4'

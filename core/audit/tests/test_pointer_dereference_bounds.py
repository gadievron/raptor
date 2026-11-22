"""Pointer dereferences keep mathematical displacement semantics, never wrap."""

from dataclasses import replace

import pytest

from core.audit.array_bounds import (ArrayAccess, _valid_witness, array_access_candidate,
                                     bind_array_access, check_array_bounds)
from core.audit.array_index import evaluate_pointer_index, pointer_access_claim
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.literal_call import check_literal_calls, literal_call_witness_valid

SOURCE = 'int Read(unsigned Index){int Data[8]={0};if(Index<8)return *(Data+Index+1);return 0;}'
CLAIM = 'Potential out-of-bounds read at `*(Data+Index+1)`.'


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
def test_trailing_displacement_exhibits_an_off_by_one(language, abi):
    pytest.importorskip('tree_sitter_' + language)
    result = check_array_bounds(SOURCE, CLAIM, language=language, integer_abi=abi)
    assert result['violation'] is True, result
    assert result['model']['Index'] == 7 and result['witness_index'] == 8
    assert result['source_access']['index_semantics'] == 'pointer'
    assert result['source_access']['index_operator'] == '+'
    assert result['obligation'] == 'Index < 0 OR Index > 8 OR (Index+1) < 0 OR (Index+1) >= 8'


def test_tighter_guard_has_no_displacement_counterexample():
    result = check_array_bounds(SOURCE.replace('Index<8', 'Index<7'), CLAIM,
                                language='c', integer_abi='lp64')
    assert result['array_bounds_status'] == 'checked' and result['violation'] is False, result


def test_displacement_replay_is_mathematical_not_promoted_wrap():
    # Data[Index-1] at Index==0 wraps to 4294967295 in the promoted type;
    # *(Data+Index-1) reaches element -1 mathematically. One encoding for
    # both spellings would misreport one of the two witness indexes.
    source = SOURCE.replace('Index<8', 'Index==0').replace('Index+1', 'Index-1')
    claim = CLAIM.replace('Index+1', 'Index-1')
    result = check_array_bounds(source, claim, language='c', integer_abi='lp64')
    assert result['violation'] is True and result['model']['Index'] == 0, result
    assert result['witness_index'] == -1
    twin = check_array_bounds(source.replace('*(Data+Index-1)', 'Data[Index-1]'),
                              claim.replace('*(Data+Index-1)', 'Data[Index-1]'),
                              language='c', integer_abi='lp64')
    assert twin['violation'] is True and twin['witness_index'] == (1 << 32) - 1


def test_out_of_object_pointer_formation_is_flagged_with_an_in_bounds_final():
    # Index==12 lands *(Data+Index-6) on element 6, inside the extent, but
    # Data+12 already left the 8-element object: forming it is undefined.
    # A final-displacement-only obligation would mint a wrong refutation.
    source = SOURCE.replace('Index<8', 'Index==12').replace('Index+1', 'Index-6')
    result = check_array_bounds(source, CLAIM.replace('Index+1', 'Index-6'),
                                language='c', integer_abi='lp64')
    assert result['violation'] is True and result['model']['Index'] == 12, result
    assert result['witness_index'] == 6


def test_negative_intermediate_is_flagged_for_a_signed_index():
    # Index==-1 makes Data+Index undefined although the +1 lands on
    # element 0; the promoted-wrap encoding would wrongly refute this.
    source = SOURCE.replace('unsigned Index', 'int Index').replace('Index<8', 'Index==-1')
    result = check_array_bounds(source, CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is True and result['model']['Index'] == -1, result
    assert result['witness_index'] == 0


@pytest.mark.parametrize('spelling', ['*(&Data[Index]+1)', '*(Data+Index+1)'])
def test_address_of_subscript_carries_the_same_displacement(spelling):
    # C defines &Data[Index] as Data + Index without evaluating the
    # element, so either claim spelling binds either source spelling.
    source = SOURCE.replace('*(Data+Index+1)', '*(&Data[Index]+1)')
    claim = CLAIM.replace('*(Data+Index+1)', spelling)
    result = check_array_bounds(source, claim, language='c', integer_abi='lp64')
    assert result['violation'] is True and result['witness_index'] == 8, result
    assert result['source_access']['index_semantics'] == 'pointer'


@pytest.mark.parametrize('divisor,violation', [('8', False), ('9', True)])
def test_whole_addend_arithmetic_keeps_promoted_semantics(divisor, violation):
    source = f'int Read(unsigned Index){{int Data[8]={{0}};return *(Data+(Index%{divisor}));}}'
    claim = f'Potential out-of-bounds read at `*(Data+(Index%{divisor}))`.'
    result = check_array_bounds(source, claim, language='c', integer_abi='lp64')
    assert result['violation'] is violation, result
    assert result['source_access']['index_semantics'] == 'promoted'
    if violation:
        assert result['witness_index'] == 8


def test_bare_addend_matches_the_subscript_obligation():
    source = SOURCE.replace('Index<8', 'Index<9').replace('*(Data+Index+1)', '*(Data+Index)')
    claim = CLAIM.replace('*(Data+Index+1)', '*(Data+Index)')
    result = check_array_bounds(source, claim, language='c', integer_abi='lp64')
    assert result['violation'] is True and result['witness_index'] == 8, result
    safe = check_array_bounds(source.replace('Index<9', 'Index<8'), claim,
                              language='c', integer_abi='lp64')
    assert safe['violation'] is False, safe


@pytest.mark.parametrize('source,claim', [
    # The claimed arithmetic kind must match the source spelling exactly:
    # a promoted addend never binds a pointer displacement, or vice versa.
    (SOURCE, CLAIM.replace('Index+1', '(Index+1)')),
    (SOURCE.replace('Index+1);return', '(Index+1));return'), CLAIM),
    # A commuted base, literal-only index, folded double adjustment,
    # subtracted base, or compound inner subscript stays out of the frame.
    (SOURCE.replace('*(Data+Index+1)', '*(Index+Data+1)'), CLAIM.replace('Data+Index', 'Index+Data')),
    (SOURCE.replace('*(Data+Index+1)', '*(Data+4+1)'), CLAIM.replace('Index+1', '4+1')),
    (SOURCE.replace('*(Data+Index+1)', '*(Data+Index+1+1)'), CLAIM.replace('Index+1', 'Index+1+1')),
    (SOURCE.replace('*(Data+Index+1)', '*(Data-Index)'), CLAIM.replace('Data+Index+1', 'Data-Index')),
    (SOURCE.replace('*(Data+Index+1)', '*(&Data[Index+1]+1)'), CLAIM.replace('Data+Index+1', '&Data[Index+1]+1')),
    # A second dereference, an escape of the object, or an unquoted claim
    # cannot bind the single-access frame.
    (SOURCE.replace('return 0;', 'return *(Data+Index+1);'), CLAIM),
    (SOURCE.replace('return 0;', 'return Data[0];'), CLAIM),
    (SOURCE, CLAIM.replace('`*(Data+Index+1)`', '*(Data+Index+1)')),
])
def test_shape_and_frame_refusals(source, claim):
    result = check_array_bounds(source, claim, language='c', integer_abi='lp64')
    assert result['violation'] is None, result


def test_write_claims_never_bind_a_pointer_dereference():
    access = bind_array_access(SOURCE.replace('return *(Data+Index+1);', '*(Data+Index+1)=0;'),
                               'Out-of-bounds write at `*(Data+Index+1)`.',
                               language='c', integer_abi='lp64', access_kind='write')
    assert access.status == 'unavailable'
    stored = check_array_bounds(SOURCE, 'Value written out of bounds at `*(Data+Index+1)`.',
                                language='c', integer_abi='lp64')
    assert stored['violation'] is None


def test_pointer_candidate_binds_without_native_credit(monkeypatch):
    from core.audit import array_bounds

    def forbidden(*args, **kwargs):
        raise AssertionError('pointer candidate acquired native proof credit')

    monkeypatch.setattr(array_bounds, 'guards_for_operation', forbidden)
    monkeypatch.setattr(array_bounds, '_solve_access', forbidden)
    access = array_access_candidate(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert access.status == 'candidate' and access.index_semantics == 'pointer'
    assert (access.index_operator, access.index_offset) == ('+', 1)


def test_displacement_replay_requires_the_bound_conversion_frame():
    access = bind_array_access(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert access.status == 'bound' and access.index_semantics == 'pointer'
    assert evaluate_pointer_index(access, {'Index': 9}, 'lp64') == (9, 10)
    assert evaluate_pointer_index(replace(access, signed=True), {'Index': 9}, 'lp64') is None
    assert evaluate_pointer_index(replace(access, width=64), {'Index': 9}, 'lp64') is None
    assert evaluate_pointer_index(replace(access, index_operator='%'), {'Index': 9}, 'lp64') is None
    assert evaluate_pointer_index(access, {'Index': True}, 'lp64') is None
    # Guards still bind the witness: Index==9 violates `Index < 8`.
    assert not _valid_witness(access, {'Index': 9}, 'lp64')
    assert _valid_witness(access, {'Index': 7}, 'lp64')
    assert not _valid_witness(access, {'Index': 6}, 'lp64')


def test_pointer_claims_route_to_the_bounds_oracle():
    assert hypothesis_to_smt_verb(CLAIM) == 'check-array-bounds'
    assert hypothesis_to_smt_verb('Out-of-bounds write through `*(Data+Index+1)`.') == 'check-oob'


def test_literal_caller_frame_declines_pointer_claims():
    source = SOURCE + '\nint Drive(void){return Read(7);}\n'
    reply = check_literal_calls(source, 'Read', 'check-array-bounds', CLAIM, 'lp64', [2], 'c')
    assert reply['status'] == 'unavailable'
    assert reply['reason'] == 'a subscript access claim is required'


def test_forged_pointer_semantics_never_pass_the_caller_witness_gate():
    subscript_source = 'int Read(unsigned Index){int Data[4]={0};if(Index>=0&&Index<4)return Data[Index+1];return 0;}'
    subscript_claim = 'Potential out-of-bounds read at `Data[Index+1]`.'
    caller = subscript_source + '\nint Drive(void){return Read(3);}\n'
    reply = check_literal_calls(caller, 'Read', 'check-array-bounds', subscript_claim, 'lp64', [2], 'c')
    assert reply['status'] == 'checked' and reply['calls'][0]['verdict'] == 'violation'
    call = reply['calls'][0]
    assert literal_call_witness_valid(reply, call, 'check-array-bounds', subscript_claim, 'lp64')
    forged = {**reply, 'callee_obligation': {**reply['callee_obligation'], 'index_semantics': 'pointer'}}
    assert not literal_call_witness_valid(forged, call, 'check-array-bounds', subscript_claim, 'lp64')
    pointer_reply = {**reply, 'callee_obligation': dict(reply['callee_obligation'])}
    assert not literal_call_witness_valid(pointer_reply, call, 'check-array-bounds', CLAIM, 'lp64')


def test_unmodeled_semantics_values_solve_and_replay_nothing():
    from core.audit.array_bounds import _solve_access, _witness_violation
    access = bind_array_access(SOURCE, CLAIM, language='c', integer_abi='lp64')
    hybrid = replace(access, index_semantics='byte-offset')
    assert _solve_access(hybrid) == (None, None)
    assert _witness_violation(hybrid, {'Index': 7}, 'lp64') == (None, None)
    assert _solve_access(replace(access, index_operator='%')) == (None, None)


def test_claim_parser_keeps_the_arithmetic_kind():
    assert pointer_access_claim(CLAIM) == ('Data', 'Index', '+', 1, 'pointer')
    assert pointer_access_claim(CLAIM.replace('Index+1', '(Index%8)')) == ('Data', 'Index', '%', 8, 'promoted')
    assert pointer_access_claim(CLAIM.replace('*(Data+Index+1)', '*(&Data[Index]-2)')) == ('Data', 'Index', '-', 2, 'pointer')
    assert pointer_access_claim(CLAIM.replace('*(Data+Index+1)', 'Data[Index]')) is None
    assert pointer_access_claim(CLAIM.replace('*(Data+Index+1)', '*(Data+Index+1);return 0')) is None
    assert pointer_access_claim(None) is None


def test_bound_record_round_trips_with_its_semantics():
    from dataclasses import asdict
    access = bind_array_access(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert ArrayAccess(**asdict(access)) == access


@pytest.mark.slow
def test_real_confined_pointer_worker_keeps_the_mathematical_index():
    from core.audit import sweep
    result = sweep.run_smt_verb_direct(file_path='unit.c', function_name='Read', verb='check-array-bounds',
                                       source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['witness_index'] == 8 and result.details['model']['Index'] == 7
    assert result.details['oracle_scope'] == 'fixed-local-array-access'
    assert result.details['source_access']['index_semantics'] == 'pointer'

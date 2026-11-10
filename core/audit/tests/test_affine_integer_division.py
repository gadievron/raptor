"""Affine divisor expressions keep their own type before division conversions."""

import pytest

from core.audit.integer_division import check_integer_division

SOURCE = 'unsigned Read(unsigned Value,unsigned Count){return Value/(Count-1);}'
CLAIM = 'Potential division by zero in `Value / (Count-1)`.'


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source=SOURCE, claim=CLAIM, language='c', abi='lp64'):
    return check_integer_division(source, claim, language=language, integer_abi=abi)


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
@pytest.mark.parametrize('operator', ['/', '%'])
def test_affine_divisor_zero_has_a_source_replayed_witness(language, abi, operator):
    pytest.importorskip('tree_sitter_' + language)
    result = check(SOURCE.replace('/', operator), CLAIM.replace('/', operator), language, abi)
    assert result['violation'] is True and result['witness_validated'], result
    assert result['model']['Count'] == 1 and result['denominator'] == 0
    assert result['fault_kind'] == 'zero-divisor'
    assert result['proof_scope'] == 'function-entry-source-model'


@pytest.mark.parametrize('abi,expected', [('lp64', True), ('i16', False)])
@pytest.mark.parametrize('operator', ['/', '%'])
def test_denominator_promotion_precedes_the_final_division_conversion(abi, expected, operator):
    source = f'int Read(int Value,unsigned short Count){{if(Count==0)return Value{operator}(Count-1);return 0;}}'
    claim = f'Potential division overflow in `Value {operator} (Count-1)`.'
    result = check(source, claim, abi=abi)
    assert result['violation'] is expected, result
    if expected:
        assert result['denominator'] == -1 and result['numerator'] == -(1 << 31)
        assert result['fault_kind'] == 'signed-division-overflow'


@pytest.mark.parametrize('spelling,expected', [('long', True), ('unsigned long', False)])
def test_wider_numerator_converts_the_already_promoted_denominator(spelling, expected):
    source = f'{spelling} Read({spelling} Value,unsigned short Count){{if(Count==0)return Value/(Count-1);return 0;}}'
    result = check(source, 'Division overflow in `Value / (Count-1)`.')
    assert result['violation'] is expected, result
    if expected:
        assert result['numerator'] == -(1 << 63) and result['denominator'] == -1


@pytest.mark.parametrize('guard', ['Count==0', 'Count!=1'])
def test_unsigned_wrap_and_guard_exclusion_do_not_become_zero_divisors(guard):
    source = f'unsigned Read(unsigned Value,unsigned Count){{if({guard})return Value/(Count-1);return 0;}}'
    result = check(source)
    assert result['violation'] is False and not result['witness_validated'], result


@pytest.mark.parametrize('source', [
    'int Read(int Value,int Count){return Value/(Count-1);}',
    'unsigned Read(unsigned Value,unsigned Count){Count=1;return Value/(Count-1);}',
    'unsigned Read(unsigned Value,unsigned Count){if(Count<0)return Value/(Count-1);return 0;}',
    'unsigned Read(unsigned Value,unsigned Count){unknown();return Value/(Count-1);}',
    'unsigned Read(unsigned Value,unsigned Count){return Value/Count-1;}',
    'unsigned Read(unsigned Value,unsigned Count){if(Value==0)return Value/(Count-1);return Value/(Count-1);}',
])
def test_unsupported_signed_effects_unreachable_precedence_and_duplicate_sites_refuse(source):
    result = check(source)
    assert result['violation'] is None and not result['witness_validated'], result


@pytest.mark.parametrize('claim', [
    'No division by zero in `Value / (Count-1)`.',
    'Division by zero unless configured in `Value / (Count-1)`.',
    'Division by zero in `Value / (Count-2)`.',
    'Division by zero in `Value / (Count-1);return 0`.',
    'Division by zero in `Value / Count-1`.',
])
def test_full_closed_goal_and_actual_expression_must_match(claim):
    result = check(claim=claim)
    assert result['violation'] is None, result


@pytest.mark.parametrize('undecided', [1, 2])
def test_unknown_entry_or_fault_query_has_no_source_proof(monkeypatch, undecided):
    import z3
    from core.audit import integer_affine_division
    original = integer_affine_division.check_solver
    calls = []

    def injected(solver):
        calls.append(solver)
        return z3.unknown if len(calls) == undecided else original(solver)

    monkeypatch.setattr(integer_affine_division, 'check_solver', injected)
    result = check()
    assert len(calls) == undecided
    assert result['violation'] is None and not result['witness_validated'], result


def test_forged_divisor_witness_cannot_override_independent_replay(monkeypatch):
    from core.audit import integer_affine_division
    monkeypatch.setattr(integer_affine_division, 'format_vars', lambda *a, **kw: {'Value': 1, 'Count': 0})
    result = check()
    assert result['violation'] is None and not result['witness_validated'], result


def test_nested_zero_budget_is_never_extended():
    from core.smt_solver.session import query_budget
    with query_budget(0):
        result = check()
    assert result['violation'] is None and not result['witness_validated'], result


def test_pure_candidate_reaches_the_existing_division_dispatch(monkeypatch):
    from core.audit import integer_affine_division
    from core.audit.arithmetic_seeds import seed_arithmetic_hypotheses
    from core.audit.hypothesis_mapping import hypothesis_to_smt_verb

    def forbidden(*a, **kw):
        raise AssertionError('affine candidate entered native source proof')

    for name in ['guards_for_operation', 'PrefixIntegerModel', 'new_solver', 'check_solver', 'query_budget']:
        monkeypatch.setattr(integer_affine_division, name, forbidden)
    gap = {'file': 'unit.c', 'name': 'Read', 'line_start': 1, 'line_end': 1}
    seed_arithmetic_hypotheses([gap], {'unit.c': SOURCE}, mode='quality', integer_abi='lp64')
    rows = [row for row in gap['injected_hypotheses'] if row['arithmetic_site'].get('candidate_basis') == 'affine-divisor']
    assert len(rows) == 1, gap
    row = rows[0]
    assert row['mechanism'] == 'Potential zero divisor in `Value / (Count-1)`.'
    assert row['confidence'] == 'low' and row['arithmetic_site']['binding_status'] == 'candidate'
    assert 'verdict' not in row and hypothesis_to_smt_verb(row['mechanism']) == 'check-integer-division'


@pytest.mark.slow
def test_real_confined_affine_division_worker_binds_the_typed_expression():
    from core.audit import sweep
    result = sweep.run_smt_verb_direct(file_path='unit.c', function_name='Read', verb='check-integer-division',
                                      source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['denominator'] == 0 and result.details['witness_validated']
    assert result.details['source_scope']['query_contract'] == 'source-integer-division-v4'
    assert result.details['oracle_scope'] == 'integer-division-fault'

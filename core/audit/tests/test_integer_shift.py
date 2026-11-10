"""Source count faults use the promoted left width, never a common frame."""

import pytest

from core.audit.integer_shift import check_shift_count


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(source, claim='invalid shift count in `Value << Count`', abi='lp64', language='c'):
    return check_shift_count(source, claim, language=language, integer_abi=abi)


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('operator', ['<<', '>>'])
def test_wide_count_does_not_widen_the_shifted_value(language, operator):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    source = f'unsigned Read(unsigned Value,unsigned long Count){{if(Count==32)return Value{operator}Count;return 0;}}'
    result = check(source, f'invalid shift count in `Value {operator} Count`', language=language)
    assert result['violation'] is True and result['witness_validated'] is True
    assert result['count_value'] == 32
    assert result['source_operation']['left_promoted_width'] == 32
    assert result['source_operation']['count_promoted_width'] == 64


@pytest.mark.parametrize('count,expected', [(32, False), (64, True)])
def test_narrow_count_does_not_narrow_the_shifted_value(count, expected):
    result = check(f'unsigned long Read(unsigned long Value,unsigned Count){{if(Count=={count})return Value<<Count;return 0;}}')
    assert result['violation'] is expected
    assert result['source_operation']['left_promoted_width'] == 64
    assert result['source_operation']['count_promoted_width'] == 32


@pytest.mark.parametrize('spelling,abi,count,width,expected', [
    ('unsigned char','ilp32',8,32,False), ('unsigned short','ilp32',16,32,False),
    ('unsigned short','i16',16,16,True), ('unsigned short','ilp32',32,32,True),
])
def test_integer_promotions_apply_before_count_validation(spelling, abi, count, width, expected):
    source = f'int Read({spelling} Value,unsigned Count){{if(Count=={count})return Value<<Count;return 0;}}'
    result = check(source, abi=abi)
    assert result['violation'] is expected
    assert result['source_operation']['left_promoted_width'] == width


@pytest.mark.parametrize('expression,subject,count', [('1 << 32','oversized',32), ('1 >> -1','negative',-1),
                                                    ('1 << (-0x1)','negative',-1)])
def test_literal_faults_are_checked_without_inventing_entry_variables(expression, subject, count):
    result = check(f'int Read(void){{return {expression};}}', f'{subject} shift count in `{expression}`')
    assert result['violation'] is True and result['witness_validated'] is True
    assert result['model'] == {} and result['count_value'] == count


@pytest.mark.parametrize('subject,guard,expected', [
    ('negative','Count==32',False), ('oversized','Count==32',True),
    ('negative','Count<0',True), ('oversized','Count<0',False),
])
def test_specific_fault_subject_cannot_use_a_different_count_fault(subject, guard, expected):
    result = check(f'int Read(int Value,int Count){{if({guard})return Value<<Count;return 0;}}',
                   f'{subject} shift count in `Value << Count`')
    assert result['violation'] is expected
    if expected:
        assert result['fault_kind'] == subject


def test_guard_comparisons_widen_values_without_changing_shift_operand_types():
    source = ('int Read(int Value,long Count){if(Count==Value && Value>=0 && Value<32)'
              'return Value<<Count;return 0;}')
    result = check(source)
    assert result['violation'] is False
    assert result['source_operation']['left_promoted_width'] == 32
    assert result['source_operation']['count_promoted_width'] == 64


def test_unsatisfiable_entry_is_not_a_safe_operation_proof():
    result = check('int Read(int Value,int Count){if(Count>=0 && Count<0)return Value<<Count;return 0;}')
    assert result['violation'] is None and result['witness_validated'] is False
    assert 'entry path' in result['reason']


@pytest.mark.parametrize('source', [
    'int Read(int Value,int Count){if(Count==32){Count=0;return Value<<Count;}return 0;}',
    'int Read(int Value,int Count){int Prior=1/0;return Value<<Count;}',
    'int Read(int Value,int Count){return (Value+1)<<Count;}',
    'int Read(int Value,volatile int Count){return Value<<Count;}',
    'int Read(int Value,int Count){int Prior=Value<<Count;return Value<<Count;}',
    'int Read(int Value,unsigned long Count){if(Count==Value)return Value<<Count;return 0;}',
])
def test_unmodelled_types_mutations_prefixes_and_occurrences_decline(source):
    result = check(source)
    assert result['violation'] is None and result['witness_validated'] is False


@pytest.mark.parametrize('claim', ['zero shift count in `Value << Count`',
                                  'signed left shift overflow in `Value << Count`',
                                  'negative shift count and oversized shift count in `Value << Count`',
                                  'invalid shift count in `Value << (Count+1)`',
                                  'invalid shift count in `Value < < Count`',
                                  'invalid shift count in Value << Count'])
def test_unknown_subjects_and_compound_or_unquoted_expressions_decline(claim):
    assert check('int Read(int Value,int Count){return Value<<Count;}', claim)['violation'] is None


def test_target_abi_is_required():
    assert check('int Read(int Value,int Count){return Value<<Count;}', abi=None)['shift_status'] == 'unavailable'


def test_expired_query_budget_never_publishes_a_constant_fault():
    from core.smt_solver.session import query_budget
    with query_budget(0):
        result = check('int Read(void){return 1<<32;}', 'invalid shift count in `1 << 32`')
    assert result['violation'] is None and result['witness_validated'] is False
    assert 'budget' in result['reason']


def test_solver_unknown_does_not_read_a_stale_model(monkeypatch):
    from core.audit import integer_shift
    from core.smt_solver import z3
    monkeypatch.setattr(integer_shift, 'check_solver', lambda solver: z3.unknown)
    monkeypatch.setattr(integer_shift, 'format_vars', lambda *a, **kw: pytest.fail('unknown read model'))
    result = check('int Read(int Value,int Count){return Value<<Count;}')
    assert result['violation'] is None and 'model' not in result


@pytest.mark.parametrize('model', [{'Value':0,'Count':0}, {'Value':1<<40,'Count':32}, {'Value':0,'Count':True}])
def test_independent_replay_refuses_invalid_native_witnesses(monkeypatch, model):
    from core.audit import integer_shift
    monkeypatch.setattr(integer_shift, 'format_vars', lambda *a, **kw: model)
    result = check('unsigned Read(unsigned Value,unsigned Count){return Value<<Count;}')
    assert result['violation'] is None and result['witness_validated'] is False
    assert 'model' not in result


def test_mixed_operand_signedness_does_not_convert_the_count_to_unsigned():
    result = check('unsigned Read(unsigned Value,long Count){if(Count<0)return Value<<Count;return 0;}',
                   'negative shift count in `Value << Count`')
    assert result['violation'] is True and result['count_value'] < 0
    assert result['source_operation']['left_promoted_width'] == 32
    assert result['source_operation']['count_promoted_width'] == 64
    assert result['source_operation']['count_signed'] is True


def test_one_parameter_used_as_both_operands_retains_one_value_identity():
    result = check('int Read(int Count){if(Count==32)return Count<<Count;return 0;}',
                   'invalid shift count in `Count << Count`')
    assert result['violation'] is True
    assert result['model'] == {'Count':32}


def test_zero_and_multiple_definitions_decline_for_all_shared_selector_callers():
    from core.audit.arithmetic_operation import bind_arithmetic_operation
    for source, expected in [
        ('int Unrelated;', 'unbound'),
        ('int Helper(void){return 0;} int Read(int Value,int Count){return Value<<Count;}', 'ambiguous'),
    ]:
        result = check(source)
        assert result['shift_status'] == 'unavailable' and result['violation'] is None
        for operator in ['+', '/']:
            operation = bind_arithmetic_operation(source, ['Value', 'Count'], operator,
                                                  language='c', integer_abi='lp64')
            assert operation.status == expected

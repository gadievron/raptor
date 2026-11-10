"""Source conversion properties bind actual guards and target integer layouts."""

from types import SimpleNamespace

import pytest

from core.audit import integer_conversion


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


@pytest.fixture
def prototype():
    def probe(source, incoming='Value', destination='Small', abi='lp64', language='c'):
        hypothesis = f'Potential non-representable unsigned conversion in `{destination} = {incoming}`.'
        return integer_conversion.check_integer_conversion(source, hypothesis, language=language, integer_abi=abi)
    return SimpleNamespace(probe=probe)


def test_direct_unsigned_conversion_has_a_replayed_source_witness(prototype):
    source = 'int Read(unsigned Value){unsigned char Small=Value;return Small;}'
    result = prototype.probe(source)
    assert result['value_loss'] is True, result
    assert result['witness_validated'] and result['source_value'] > 255
    assert result['converted_value'] == result['source_value'] % 256
    assert result['source_types'] == {'Value': 'unsigned'}
    assert 'rule_id' not in result and 'grade' not in result


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('guard,expected', [('Value<=255', False), ('Value>255', True)])
def test_actual_guard_selects_value_loss_not_just_width(prototype, language, guard, expected):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    source = f'int Read(unsigned Value){{if({guard}){{unsigned char Small=Value;return Small;}}return 0;}}'
    result = prototype.probe(source, language=language)
    assert result['entry_feasible'] is True and result['value_loss'] is expected, result


def test_equal_width_sign_change_is_not_just_a_narrower_width_question(prototype):
    source = 'unsigned Read(int Value){if(Value<0){unsigned Small=Value;return Small;}return 0;}'
    result = prototype.probe(source)
    assert result['value_loss'] is True and result['source_value'] < 0, result
    assert result['destination_width'] == 32 and result['converted_value'] >= 0


@pytest.mark.parametrize('abi,expected', [('lp64', True), ('llp64', False)])
def test_target_layout_not_host_layout_controls_long_conversion(prototype, abi, expected):
    result = prototype.probe('int Read(unsigned long Value){unsigned Small=Value;return 0;}', abi=abi)
    assert result['value_loss'] is expected, result
    assert result['integer_abi']['name'] == abi


def test_infeasible_entry_is_not_a_safe_conversion_verdict(prototype):
    result = prototype.probe('int Read(unsigned Value){if(Value<0){unsigned char Small=Value;return Small;}return 0;}')
    assert result['entry_feasible'] is False and result['value_loss'] is None


@pytest.mark.parametrize('body', [
    'Value=0;unsigned char Small=Value;',
    'Before();unsigned char Small=Value;',
    'int Prior=1/0;unsigned char Small=Value;',
    'unsigned Value=10;unsigned char Small=Value;',
    'unsigned char Small=Value*0;',
    'unsigned char Small=(unsigned)Value;',
    'signed char Small=Value;',
    'unsigned char Small{Value};',
    'if(Value>0){unsigned char Small=Value;}else{unsigned char Small=Value;}',
])
def test_unsupported_conversion_frames_get_no_value_loss_verdict(prototype, body):
    result = prototype.probe('int Read(unsigned Value){' + body + 'return 0;}')
    assert result['conversion_status'] == 'unavailable' and result['value_loss'] is None, result


@pytest.mark.parametrize('parameter', ['volatile unsigned Value', 'size_t Value', 'unsigned *Value'])
def test_parameter_type_identity_must_be_builtin_and_stable(prototype, parameter):
    result = prototype.probe('int Read(' + parameter + '){unsigned char Small=Value;return Small;}')
    assert result['value_loss'] is None, result


@pytest.mark.parametrize('abi', [None, 'unknown'])
def test_missing_layout_is_not_borrowed_from_the_host(prototype, abi):
    assert prototype.probe('int Read(unsigned Value){unsigned char Small=Value;return Small;}', abi=abi)['value_loss'] is None


def test_boolean_storage_is_not_an_unsigned_modulo_conversion(prototype):
    source = 'int Read(unsigned Value){if(Value==2){_Bool Small=Value;return Small;}return 0;}'
    result = prototype.probe(source)
    assert result['conversion_status'] == 'unavailable' and result['value_loss'] is None, result


@pytest.mark.parametrize('language,spelling', [('c', '_Bool'), ('cpp', 'bool')])
def test_boolean_destinations_require_their_own_conversion_rule(prototype, language, spelling):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    source = f'int Read(unsigned Value){{if(Value==2){{{spelling} Small=Value;return Small;}}return 0;}}'
    assert prototype.probe(source, language=language)['value_loss'] is None


@pytest.mark.parametrize('hypothesis', [
    'no non-representable unsigned conversion in `Small = Value`',
    'non-representable unsigned conversion in `Small = Value` only if Value is negative',
    'non-representable unsigned conversion in `Small == Value`',
    'non-representable unsigned conversion in `Small = Value + 1`',
    'non-representable unsigned conversion in `Other = Value`',
    'non-representable signed conversion in `Small = Value`',
])
def test_unknown_goal_or_unbound_conversion_cannot_publish_a_witness(hypothesis):
    result = integer_conversion.check_integer_conversion(
        'int Read(unsigned Value){unsigned char Small=Value;return Small;}',
        hypothesis, language='c', integer_abi='lp64')
    assert result['value_loss'] is None and not result['witness_validated']


@pytest.mark.parametrize('phase', ['entry', 'conversion'])
def test_unknown_never_becomes_a_safe_or_loss_verdict(phase):
    from core.smt_solver import z3
    from core.testing.module_views import module_function_view

    calls = []
    def check(solver):
        calls.append(1)
        return z3.unknown if phase == 'entry' or len(calls) == 2 else z3.sat
    view = module_function_view(integer_conversion, bindings={'check_solver': check})
    result = view.check_integer_conversion(
        'int Read(unsigned Value){unsigned char Small=Value;return Small;}',
        'non-representable unsigned conversion in `Small = Value`', language='c', integer_abi='lp64')
    assert result['value_loss'] is None and not result['witness_validated']


def test_independent_replay_refuses_a_witness_outside_the_reaching_guard():
    from core.testing.module_views import module_function_view

    view = module_function_view(integer_conversion, bindings={'format_vars': lambda *a, **kw: {'Value': 0}})
    result = view.check_integer_conversion(
        'int Read(unsigned Value){if(Value>255){unsigned char Small=Value;return Small;}return 0;}',
        'non-representable unsigned conversion in `Small = Value`', language='c', integer_abi='lp64')
    assert result['value_loss'] is None and not result['witness_validated']


def test_candidate_types_do_not_enter_guard_or_solver_admission():
    from core.testing.module_views import module_function_view

    def forbidden(*a, **kw):
        raise AssertionError('conversion candidate entered native proof')
    view = module_function_view(integer_conversion, bindings={
        'guards_for_operation': forbidden, 'ComparisonModel': forbidden, 'new_solver': forbidden,
    })
    source = 'int Read(unsigned Value){Before();unsigned char Small=Value;return Small;}'
    candidates = view.conversion_candidates(source, language='c', integer_abi='lp64')
    assert len(candidates) == 1 and candidates[0]['destination_type'] == 'unsigned char'
    result = integer_conversion.check_integer_conversion(
        source, 'non-representable unsigned conversion in `Small = Value`', language='c', integer_abi='lp64')
    assert result['value_loss'] is None


def test_zero_parent_query_budget_cannot_publish_a_conversion_witness(prototype):
    from core.smt_solver.session import query_budget

    with query_budget(0):
        result = prototype.probe('int Read(unsigned Value){unsigned char Small=Value;return Small;}')
    assert result['value_loss'] is None and not result['witness_validated']

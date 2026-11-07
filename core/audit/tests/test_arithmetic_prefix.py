"""Source counterexamples require a supported, defined evaluated prefix."""

from dataclasses import asdict

import pytest

from core.audit.arithmetic_operation import bind_arithmetic_operation
from core.audit import sweep
from core.audit.probe_function_scope import source_binding, source_for_function


@pytest.fixture(autouse=True)
def grammar():
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


def source(prefix, *, extra='unsigned Extra', guard='Value > 0 && Step > 0', statement='return Value + Step;'):
    return f'unsigned Read(unsigned Value,unsigned Step,{extra}){{{prefix} if({guard}){{{statement}}} return 0;}}'


def bind(prefix, *, language='c', abi='ilp32', **kwargs):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    return bind_arithmetic_operation(source(prefix, **kwargs), ['Value', 'Step'], '+',
                                     language=language, integer_abi=abi)


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix', [
    pytest.param('int Ignored=(int)1e100;', id='out-of-range-float-cast'),
    pytest.param('(int)1e100;', id='discarded-float-conversion'),
    pytest.param('int Ignored=Value;', id='implicit-unsigned-to-signed'),
    pytest.param('short Ignored=(short)Value;', id='signed-narrowing-cast'),
    pytest.param('short Ignored=Extra;', id='implicit-narrowing'),
    pytest.param('volatile unsigned Ignored=Extra; (void)Ignored;', id='volatile-read'),
    pytest.param('"left" < "right";', id='unmodeled-pointer-comparison'),
])
def test_unmodeled_prefix_never_receives_source_guard_credit(prefix, language):
    result = bind(prefix, language=language)
    assert result.status == 'bound'
    assert result.guard_status == 'unavailable' and not result.premises


@pytest.mark.parametrize('prefix', [
    pytest.param('Extra == Extra;', id='overloaded-comparison'),
    pytest.param('int Ignored=Extra;', id='implicit-user-conversion'),
    pytest.param('if(Extra){}', id='implicit-bool-conversion'),
    pytest.param('[Extra](){};', id='capture-copy-constructor'),
    pytest.param('unsigned Ignored=7_suffix;', id='user-defined-literal'),
])
def test_cpp_implicit_calls_are_not_primitive_expression_effects(prefix):
    result = bind(prefix, language='cpp', extra='Widget Extra')
    assert result.status == 'bound' and result.guard_status == 'unavailable'


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix', [
    pytest.param('(void)Extra;', id='integer-discard'),
    pytest.param('unsigned Ignored=Extra;', id='same-domain-initializer'),
    pytest.param('unsigned char Ignored=Extra;', id='defined-unsigned-modulo'),
    pytest.param('int Ignored=(unsigned char)Extra;', id='narrow-then-safe-promote'),
    pytest.param('signed char Ignored=-1;', id='representable-negative-initializer'),
    pytest.param('int Ignored=Extra<10;', id='comparison-result-fits'),
    pytest.param('int Ignored=sizeof(Value + Step);', id='unevaluated-integer-result-type'),
    pytest.param('unsigned Ignored=sizeof(Value + Step);', id='unevaluated-unsigned-initializer'),
    pytest.param('int Ignored=sizeof((int)1e100);', id='unevaluated-unsafe-cast'),
    pytest.param('int Ignored=sizeof(char);', id='sizeof-char'),
    pytest.param('unsigned Ignored=sizeof(Extra);', id='sizeof-storage'),
])
def test_defined_primitive_prefixes_remain_supported(prefix, language):
    result = bind(prefix, language=language)
    assert result.status == 'bound' and result.guard_status == 'bound', result
    assert result.premises == ('Value > 0', 'Step > 0')


def test_signed_initializer_conversion_is_bound_to_the_target_abi():
    assert bind('int Ignored=Extra;', extra='long Extra', abi='ilp32').guard_status == 'bound'
    assert bind('int Ignored=Extra;', extra='long Extra', abi='lp64').guard_status == 'unavailable'


def test_signed_to_unsigned_initializer_conversion_is_defined_for_negative_inputs():
    assert bind('unsigned Ignored=Extra;', extra='int Extra').guard_status == 'bound'


def test_cast_after_the_selected_operation_does_not_hide_its_evaluation():
    assert bind('', statement='return (unsigned char)(Value + Step);').guard_status == 'bound'


def test_unevaluated_operands_do_not_execute_cpp_user_conversions():
    result = bind('unsigned Ignored=noexcept((int)Extra);', language='cpp', extra='Widget Extra')
    assert result.status == 'bound' and result.guard_status == 'bound'
    result = bind('unsigned Ignored=sizeof(Extra);', language='cpp', extra='Widget Extra')
    assert result.status == 'bound' and result.guard_status == 'bound'


def test_c_noexcept_spelling_is_an_ordinary_unmodeled_call():
    assert bind('unsigned Ignored=noexcept(Extra);').guard_status == 'unavailable'


def test_coroutine_suspension_cannot_be_ignored_before_the_site():
    pytest.importorskip('tree_sitter_cpp')
    text = ('Task Read(unsigned Value,unsigned Step,Awaitable Extra){co_await Extra;'
            'if(Value>0 && Step>0){unsigned Total=Value+Step;}}')
    result = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language='cpp', integer_abi='ilp32')
    assert result.status == 'bound' and result.guard_status == 'unavailable'


@pytest.mark.parametrize('language', ['c', 'cpp'])
def test_unmodeled_prefix_stops_before_the_solver_and_auxiliary_disproof(monkeypatch, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    from packages.exploit_feasibility import smt_verbs
    from core.audit.condition_smt import disprove_integer_overflow
    monkeypatch.setattr(smt_verbs, 'check_overflow', lambda *a, **kw: pytest.fail('unmodeled prefix reached SMT'))
    text = source('int Ignored=(int)1e100;')
    result = sweep._run_smt_verb_inner(file_path='record.' + language, function_name='Read', verb='check-overflow',
                                     source=text, hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    assert disprove_integer_overflow('integer overflow in `Value + Step`', text, file_path='record.' + language,
                                    function_name='Read', integer_abi='ilp32').disproved is None


@pytest.mark.parametrize('prefix', ['unsigned Width=sizeof(Value + Step);', '(void)Extra;',
                                   'int Ignored=(unsigned char)Extra;'])
def test_supported_prefix_keeps_real_source_smt_verdicts(prefix):
    pytest.importorskip('z3')
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb='check-overflow',
                                     source=source(prefix, guard='Value<=10 && Step<=10'),
                                     hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'refuted', result.details
    assert result.details['source_scope']['query_contract'] == 'common-width-integer-operands-v14'


@pytest.mark.parametrize('outcome', ['confirmed', 'refuted'])
def test_worker_from_before_prefix_definedness_contract_cannot_be_reused(monkeypatch, outcome):
    text = source('int Ignored=(int)1e100;')
    _, selected = source_for_function(text, 'record.c', 'Read')
    binding = source_binding(selected, 'Read', verb='check-overflow', integer_abi='ilp32',
                             hypothesis='integer overflow in `Value + Step`')
    binding['query_contract'] = 'common-width-integer-operands-v13'
    old = sweep.SweepResult(tool='smt', file_path='record.c', function_name='Read', rule_id='smt:check-overflow',
                            outcome=outcome, details={'source_scope': binding}, matches=[{'model': {}}])
    monkeypatch.setattr('core.audit.subproc_json.run_json_child', lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path='record.c', function_name='Read', verb='check-overflow',
                                         source=text, hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    assert result.details['source_scope_status'] == 'unbound-worker-result'


def test_initializer_nesting_declines_at_the_model_limit():
    prefix = 'int Ignored=' + '{' * 70 + '0' + '}' * 70 + ';'
    assert bind(prefix).guard_status == 'unavailable'


@pytest.mark.parametrize('abi', ['ilp32', 'lp64', 'i16'])
def test_all_primitive_initializer_domains_match_the_declared_target_storage(abi):
    from core.audit.arithmetic_types import integer_type
    spellings = ('signed char', 'unsigned char', 'short', 'unsigned short', 'int', 'unsigned', 'long', 'unsigned long')
    for source_type in spellings:
        incoming = integer_type(source_type, abi)
        low = -(1 << (incoming.width - 1)) if incoming.signed else 0
        high = (1 << (incoming.width - (1 if incoming.signed else 0))) - 1
        for destination_type in spellings:
            destination = integer_type(destination_type, abi)
            fits = (not destination.signed or -(1 << (destination.width - 1)) <= low <= high < (1 << (destination.width - 1)))
            result = bind(f'{destination_type} Ignored=Extra;', extra=source_type + ' Extra', abi=abi)
            assert (result.guard_status == 'bound') is fits, (abi, source_type, destination_type, result)


@pytest.mark.parametrize('outcome', ['confirmed', 'refuted'])
def test_array_worker_from_the_previous_guard_contract_is_rejected(monkeypatch, outcome):
    text = 'int Read(int Index){int Data[4]={0}; return Data[Index];}'
    _, selected = source_for_function(text, 'record.c', 'Read')
    hypothesis = 'out-of-bounds read at Data[Index]'
    binding = source_binding(selected, 'Read', verb='check-array-bounds', integer_abi='ilp32', hypothesis=hypothesis)
    binding['query_contract'] = 'common-width-array-guards-v3'
    old = sweep.SweepResult(tool='smt', file_path='record.c', function_name='Read', rule_id='smt:check-array-bounds',
                            outcome=outcome, details={'source_scope': binding}, matches=[{'model': {}}])
    monkeypatch.setattr('core.audit.subproc_json.run_json_child', lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path='record.c', function_name='Read', verb='check-array-bounds',
                                         source=text, hypothesis=hypothesis, integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    assert result.details['source_scope_status'] == 'unbound-worker-result'


def test_type_modifying_prefix_attributes_are_not_plain_integer_storage():
    result = bind('unsigned Ignored __attribute__((mode(DI)))=Extra;')
    assert result.guard_status == 'unavailable' and result.type_status == 'unavailable'


def test_unevaluated_atomic_storage_does_not_guess_a_plain_integer_size():
    result = bind('int Ignored=sizeof(Extra);', extra='_Atomic unsigned Extra')
    assert result.guard_status == 'unavailable'
    # An integer-to-unsigned conversion is defined even without an exact
    # sizeof bound; it adds no assumptions about the atomic representation.
    assert bind('unsigned Ignored=sizeof(Extra);', extra='_Atomic unsigned Extra').guard_status == 'bound'


def test_unevaluated_vector_operands_do_not_inherit_scalar_storage_size():
    extra = 'unsigned Extra __attribute__((vector_size(512)))'
    assert bind('signed char Ignored=sizeof(Extra+Extra);', extra=extra).guard_status == 'unavailable'
    assert bind('unsigned Ignored=sizeof(Extra+Extra);', extra=extra).guard_status == 'bound'

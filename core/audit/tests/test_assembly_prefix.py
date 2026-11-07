"""Inline assembly needs a source execution model before SMT proof credit."""

from dataclasses import asdict

import pytest

from core.audit import sweep
from core.audit.arithmetic_operation import bind_arithmetic_operation
from core.audit.condition_smt import disprove_integer_overflow
from core.audit.probe_function_scope import source_binding, source_for_function

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.fixture(autouse=True)
def grammar():
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


def source(prefix='', suffix=''):
    return ('unsigned Read(unsigned Value,unsigned Step){' + prefix
            + 'if(Value<10 && Step<10){return Value+Step;}' + suffix + 'return 0;}')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('position', ['before-guard', 'after-guard'])
@pytest.mark.parametrize('assembly', [
    'asm("");',
    '__asm__("");',
    '__asm__ volatile("" : "+r"(Value));',
    '__asm__("" : : "r"(Value));',
    '__asm__("" ::: "memory");',
])
def test_assembly_prefix_declines_without_running_a_solver(monkeypatch, language, assembly, position):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    from packages.exploit_feasibility import smt_verbs
    monkeypatch.setattr(smt_verbs, 'check_overflow', lambda *a, **kw: pytest.fail('assembly reached solver'))
    text = (source(assembly) if position == 'before-guard'
            else source().replace('return Value+Step;', assembly + 'return Value+Step;'))
    operation = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language=language, integer_abi='ilp32')
    assert operation.status == 'bound'
    assert operation.guard_status == operation.type_status == 'unavailable'
    result = sweep._run_smt_verb_inner(file_path='record.' + language, function_name='Read', verb='check-overflow',
                                     source=text, hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    assert disprove_integer_overflow('integer overflow in `Value + Step`', text, file_path='record.' + language,
                                    function_name='Read', integer_abi='ilp32').disproved is None


@pytest.mark.parametrize('language', ['c', 'cpp'])
def test_later_assembly_does_not_invalidate_an_earlier_source_site(language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    pytest.importorskip('z3')
    result = sweep._run_smt_verb_inner(file_path='record.' + language, function_name='Read', verb='check-overflow',
                                     source=source(suffix='asm("");'),
                                     hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'refuted', result.details


@pytest.mark.parametrize('language', ['c', 'cpp'])
def test_an_assembly_input_is_not_an_ordinary_arithmetic_site(language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    text = 'unsigned Read(unsigned Value,unsigned Step){asm("" : : "r"(Value+Step));return 0;}'
    result = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language=language, integer_abi='ilp32')
    assert result.status == 'bound' and result.guard_status == 'unavailable'


@pytest.mark.parametrize('outcome', ['confirmed', 'refuted'])
def test_pre_assembly_worker_contract_is_rejected(monkeypatch, outcome):
    text = source('asm("");')
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

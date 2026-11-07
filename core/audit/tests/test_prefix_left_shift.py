"""Left-shift obligations are consumed through source-bound audit verdicts."""

from dataclasses import asdict

import pytest

from core.audit import sweep
from core.audit.arithmetic_operation import bind_arithmetic_operation
from core.audit.probe_function_scope import source_binding, source_for_function

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


def source(prefix, extra='unsigned Extra'):
    return ('unsigned Read(unsigned Value,unsigned Step,' + extra + '){' + prefix
            + 'if(Value<10 && Step<10){return Value+Step;}return 0;}')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix,extra', [
    ('unsigned Local=Extra<<0;', 'unsigned Extra'),
    ('unsigned Local=Extra<<1;', 'unsigned Extra'),
    ('unsigned Local=Extra<<31;', 'unsigned Extra'),
    ('int Local=Extra<<1;', 'unsigned char Extra'),
    ('int Local=Extra<<23;', 'unsigned char Extra'),
    ('int Local=Extra<<15;', 'unsigned short Extra'),
    ('short Local=Extra<<1;', 'unsigned char Extra'),
    ('int Local=1<<3;', 'unsigned Extra'),
])
def test_defined_left_shift_prefix_reaches_real_source_verification(prefix, extra, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    result = sweep._run_smt_verb_inner(file_path='record.' + language, function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`',
                                     integer_abi='ilp32')
    assert result.outcome == 'refuted', result.details
    assert result.details['source_scope']['query_contract'] == 'common-width-integer-operands-v19'


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix,extra', [
    ('int Local=Extra<<0;', 'int Extra'),
    ('int Local=Extra<<24;', 'unsigned char Extra'),
    ('int Local=Extra<<16;', 'unsigned short Extra'),
    ('int Local=1<<31;', 'unsigned Extra'),
    ('unsigned Local=Extra<<32;', 'unsigned Extra'),
    ('unsigned Local=Extra<<-1;', 'unsigned Extra'),
    ('signed char Local=Extra<<1;', 'unsigned char Extra'),
])
def test_invalid_or_unmodeled_left_shift_does_not_get_verification_credit(prefix, extra, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    result = sweep._run_smt_verb_inner(file_path='record.' + language, function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`',
                                     integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []


def test_left_shift_uses_the_explicit_abi_promotions():
    text = source('int Local=Extra<<8;', 'unsigned char Extra')
    narrow = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language='c', integer_abi='i16')
    wide = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language='c', integer_abi='ilp32')
    assert narrow.guard_status == 'unavailable'
    assert wide.guard_status == wide.type_status == 'bound'


def test_auxiliary_disproof_uses_the_same_left_shift_prefix_proof():
    from core.audit.condition_smt import disprove_integer_overflow
    result = disprove_integer_overflow('integer overflow in `Value + Step`', source('unsigned Local=Extra<<1;'),
                                      file_path='record.c', function_name='Read', integer_abi='ilp32')
    assert result.disproved is True


@pytest.mark.parametrize('outcome', ['unknown', 'sat'])
def test_left_shift_nonproof_never_admits_the_prefix(monkeypatch, outcome):
    from core.audit import arithmetic_prefix_obligations as obligations
    from core.smt_solver import z3
    monkeypatch.setattr(obligations, 'check_solver', lambda solver: getattr(z3, outcome))
    result = bind_arithmetic_operation(source('unsigned Local=Extra<<1;'), ['Value', 'Step'], '+',
                                       language='c', integer_abi='ilp32')
    assert result.guard_status == result.type_status == 'unavailable'


@pytest.mark.parametrize('outcome', ['confirmed', 'refuted'])
def test_old_worker_contract_cannot_reuse_a_pre_shift_prefix_verdict(monkeypatch, outcome):
    text = source('unsigned Local=Extra<<1;')
    _, selected = source_for_function(text, 'record.c', 'Read')
    binding = source_binding(selected, 'Read', verb='check-overflow', integer_abi='ilp32',
                             hypothesis='integer overflow in `Value + Step`')
    binding['query_contract'] = 'common-width-integer-operands-v15'
    old = sweep.SweepResult(tool='smt', file_path='record.c', function_name='Read', rule_id='smt:check-overflow',
                            outcome=outcome, details={'source_scope': binding}, matches=[{'model': {}}])
    monkeypatch.setattr('core.audit.subproc_json.run_json_child', lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path='record.c', function_name='Read', verb='check-overflow',
                                         source=text, hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    assert result.details['source_scope_status'] == 'unbound-worker-result'

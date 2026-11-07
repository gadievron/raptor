"""A source proof must model function entry, not merely its body prefix."""

from dataclasses import asdict

import pytest

from core.audit import sweep
from core.audit.arithmetic_operation import bind_arithmetic_operation
from core.audit.array_bounds import check_array_bounds
from core.audit.condition_extraction import _get_parser
from core.audit.function_execution_frame import ordinary_function_frame
from core.audit.probe_function_scope import source_binding, source_for_function


@pytest.fixture(autouse=True)
def grammar():
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


def arithmetic(header='unsigned Read(unsigned Value,unsigned Step)', tail='', safe=False):
    guard = 'Value<10 && Step<10' if safe else 'Value>0 && Step>0'
    return header + '{if(' + guard + '){unsigned Local=Value+Step;}' + tail + 'return 0;}'


@pytest.mark.parametrize('extra', [
    'unsigned Extra[Value]',
    'unsigned Extra[1][(Value=0,1)]',
    'unsigned (*Extra)[(Value++,1)]',
    'unsigned Extra[1][SideEffect(&Value)]',
    'unsigned Extra[1][Value+Step]',
    'typeof(Value) Extra',
    '__typeof__(Value) Extra',
])
def test_parameter_type_evaluation_is_declined_before_any_solver_query(monkeypatch, extra):
    from packages.exploit_feasibility import smt_verbs
    monkeypatch.setattr(smt_verbs, 'check_overflow', lambda *a, **kw: pytest.fail('unmodeled entry reached solver'))
    text = arithmetic('unsigned Read(unsigned Value,unsigned Step,' + extra + ')')
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb='check-overflow',
                                     source=text, hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    operation = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language='c', integer_abi='ilp32')
    assert operation.status == 'unavailable'


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('header', [
    '__attribute__((naked)) unsigned Read(unsigned Value,unsigned Step)',
    'unsigned Read(unsigned Value,unsigned Step) __attribute__((noinline))',
    'unsigned Read(unsigned Value,unsigned Step,unsigned Extra __attribute__((mode(DI))))',
])
def test_function_and_unused_parameter_attributes_are_not_ordinary_entry(header, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    operation = bind_arithmetic_operation(arithmetic(header), ['Value', 'Step'], '+', language=language, integer_abi='ilp32')
    assert operation.status == 'unavailable'


@pytest.mark.parametrize('suspension', ['co_await Waiting;', 'co_yield 0;', 'co_return;'])
@pytest.mark.parametrize('before', [False, True])
def test_a_coroutine_is_not_an_ordinary_function_even_when_suspension_follows_the_site(suspension, before):
    pytest.importorskip('tree_sitter_cpp')
    header = 'Task Read(unsigned Value,unsigned Step,Awaitable Waiting)'
    text = header + '{' + (suspension if before else '') + 'if(Value>0 && Step>0){unsigned Local=Value+Step;}' + ('' if before else suspension) + '}'
    root = _get_parser('cpp').parse(text.encode()).root_node
    assert not root.has_error
    assert not ordinary_function_frame(root.named_children[0], text.encode(), 'cpp')
    assert bind_arithmetic_operation(text, ['Value', 'Step'], '+', language='cpp', integer_abi='ilp32').status == 'unavailable'


@pytest.mark.parametrize('header,language', [
    ('unsigned Read(unsigned Value,unsigned Step)', 'c'),
    ('static inline unsigned Read(unsigned Value,unsigned Step)', 'c'),
    ('extern unsigned Read(unsigned Value,unsigned Step)', 'c'),
    ('const unsigned Read(unsigned Value,unsigned Step)', 'c'),
    ('unsigned *Read(unsigned Value,unsigned Step)', 'c'),
    ('unsigned Read(unsigned Value,unsigned Step,unsigned Extra[4])', 'c'),
    ('unsigned Read(unsigned Value,unsigned Step,unsigned Extra[])', 'c'),
    ('unsigned Read(unsigned Value,unsigned Step,unsigned Extra[1][4])', 'c'),
    ('constexpr unsigned Read(unsigned Value,unsigned Step) noexcept', 'cpp'),
    ('auto Read(unsigned Value,unsigned Step) -> unsigned', 'cpp'),
])
def test_ordinary_qualifiers_and_return_declarators_preserve_arithmetic_binding(header, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    result = bind_arithmetic_operation(arithmetic(header, safe=True), ['Value', 'Step'], '+', language=language, integer_abi='ilp32')
    assert result.status == 'bound' and result.type_status == 'bound', result


def test_a_nested_coroutine_does_not_change_the_owners_execution_mode():
    pytest.importorskip('tree_sitter_cpp')
    text = arithmetic(tail='auto Unused=[](Awaitable Waiting)->Task{co_await Waiting;};', safe=True)
    root = _get_parser('cpp').parse(text.encode()).root_node
    assert not root.has_error
    assert ordinary_function_frame(root.named_children[0], text.encode(), 'cpp')
    result = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language='cpp', integer_abi='ilp32')
    assert result.status == 'bound' and result.type_status == 'bound', result


@pytest.mark.parametrize('head', [
    '__attribute__((noinline)) int Read(int Index)',
    'int Read(int Index) __attribute__((noinline))',
])
def test_array_consumer_checks_both_function_attribute_positions(head):
    pytest.importorskip('z3')
    text = head + '{int Data[4]={0};if(Index>=0 && Index<=4){return Data[Index];}return 0;}'
    result = check_array_bounds(text, 'out-of-bounds read at Data[Index]', language='c', integer_abi='ilp32')
    assert result['array_bounds_status'] == 'unavailable' and result['violation'] is None


def test_auxiliary_disproof_cannot_ignore_parameter_entry_evaluation():
    pytest.importorskip('z3')
    from core.audit.condition_smt import disprove_integer_overflow
    text = arithmetic('unsigned Read(unsigned Value,unsigned Step,unsigned Extra[1][Value+Step])', safe=True)
    result = disprove_integer_overflow('integer overflow in `Value + Step`', text,
                                      file_path='record.c', function_name='Read', integer_abi='ilp32')
    assert result.disproved is None


@pytest.mark.parametrize('verb,version', [('check-overflow', 'common-width-integer-operands-v17'),
                                        ('check-array-bounds', 'common-width-array-guards-v6')])
@pytest.mark.parametrize('outcome', ['confirmed', 'refuted'])
def test_old_function_frame_worker_contracts_cannot_supply_verdicts(monkeypatch, verb, version, outcome):
    text = arithmetic()
    hypothesis = 'integer overflow in `Value + Step`'
    if verb == 'check-array-bounds':
        text = 'int Read(int Index){int Data[4]={0};if(Index<=4){return Data[Index];}return 0;}'
        hypothesis = 'out-of-bounds read at Data[Index]'
    _, selected = source_for_function(text, 'record.c', 'Read')
    binding = source_binding(selected, 'Read', verb=verb, integer_abi='ilp32', hypothesis=hypothesis)
    binding['query_contract'] = version
    old = sweep.SweepResult(tool='smt', file_path='record.c', function_name='Read', rule_id='smt:' + verb,
                            outcome=outcome, details={'source_scope': binding}, matches=[{'model': {}}])
    monkeypatch.setattr('core.audit.subproc_json.run_json_child', lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path='record.c', function_name='Read', verb=verb,
                                         source=text, hypothesis=hypothesis, integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    assert result.details['source_scope_status'] == 'unbound-worker-result'


def test_requires_clause_does_not_supply_an_unconstrained_runtime_entry():
    pytest.importorskip('tree_sitter_cpp')
    text = ('template<typename Unused> unsigned Read(unsigned Value,unsigned Step) requires(false)'
            '{if(Value>0 && Step>0){return Value+Step;}return 0;}')
    root = _get_parser('cpp').parse(text.encode()).root_node
    assert not root.has_error
    result = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language='cpp', integer_abi='ilp32')
    assert result.status == 'unavailable'


def test_c_identifier_spelling_does_not_make_a_coroutine():
    text = arithmetic(tail='co_await();', safe=True)
    root = _get_parser('c').parse(text.encode()).root_node
    assert not root.has_error
    assert ordinary_function_frame(root.named_children[0], text.encode(), 'c')
    result = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language='c', integer_abi='ilp32')
    assert result.status == 'bound' and result.type_status == 'bound'


@pytest.mark.parametrize('header,language', [
    ('static inline int Read(int Index)', 'c'),
    ('const int Read(int Index)', 'c'),
    ('constexpr int Read(int Index) noexcept', 'cpp'),
])
def test_array_consumer_preserves_supported_ordinary_qualifiers(header, language):
    pytest.importorskip('z3')
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    text = header + '{int Data[4]={0};if(Index>=0 && Index<=4){return Data[Index];}return 0;}'
    result = check_array_bounds(text, 'out-of-bounds read at Data[Index]', language=language, integer_abi='ilp32')
    assert result['array_bounds_status'] == 'checked' and result['violation'] is True, result
    assert result['witness_index'] == 4


def test_audit_chain_cannot_promote_a_body_only_proof_with_unmodeled_parameter_entry(tmp_path, monkeypatch):
    from core.audit import orchestrator as orch
    text = arithmetic('unsigned Read(unsigned Value,unsigned Step,unsigned Extra[1][Value+Step])')
    (tmp_path / 'record.c').write_text(text)
    calls = []

    def worker(**request):
        calls.append(request['verb'])
        return sweep._run_smt_verb_inner(**request)

    monkeypatch.setattr(sweep, '_smt_verb_in_subprocess', worker)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out', integer_abi='ilp32')
    result = orch._run_tool_chain([{'type': 'smt', 'config': {'verb': 'check-overflow'}}], config=config,
                                 file_path='record.c', function_name='Read', line_start=1, source=text,
                                 hypothesis='integer overflow in `Value + Step`')
    assert calls == ['check-overflow'] and result == []


@pytest.mark.parametrize('initializer', ['', ': Member(Value=0)'])
def test_constructor_setup_is_not_treated_as_an_ordinary_function_body(initializer):
    pytest.importorskip('tree_sitter_cpp')
    text = ('struct Record { int Member; Record(unsigned Value,unsigned Step)' + initializer
            + '{if(Value>0 && Step>0){unsigned Local=Value+Step;}} };')
    root = _get_parser('cpp').parse(text.encode()).root_node
    assert not root.has_error
    result = bind_arithmetic_operation(text, ['Value', 'Step'], '+', language='cpp', integer_abi='ilp32')
    assert result.status == 'unavailable'


def test_constructor_parameter_rewrite_cannot_supply_a_body_only_overflow_verdict():
    pytest.importorskip('tree_sitter_cpp')
    pytest.importorskip('z3')
    text = ('struct Record {int Member;Record(unsigned Value,unsigned Step):Member(Value=0)'
            '{if(Value>0 && Step>0){unsigned Local=Value+Step;}}};')
    result = sweep._run_smt_verb_inner(file_path='record.cpp', function_name='Record', verb='check-overflow',
                                     source=text, hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []

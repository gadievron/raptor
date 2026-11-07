"""Compound source prefixes preserve promotions and every intermediate fault."""

from dataclasses import asdict

import pytest

from core.audit import sweep
from core.audit.arithmetic_operation import bind_arithmetic_operation
from core.audit.arithmetic_prefix import PrefixIntegerModel
from core.audit.condition_extraction import _get_parser
from core.audit.integer_abi import resolve_integer_abi
from core.audit.probe_function_scope import source_binding, source_for_function

pytestmark = pytest.mark.usefixtures("overflow_disproof_unit_worker")


@pytest.fixture(autouse=True)
def dependencies(monkeypatch):
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')
    from core.audit import arithmetic_prefix_obligations
    # These cases assert expression semantics, not a machine-speed deadline.
    # The production budget/refusal policy has its own deterministic tests.
    monkeypatch.setattr(arithmetic_prefix_obligations, '_BUDGET_MS', 5000)


def source(prefix, extra='unsigned Extra'):
    return ('unsigned Read(unsigned Value,unsigned Step,' + extra + '){' + prefix
            + 'if(Value<10 && Step<10){return Value+Step;}return 0;}')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix,extra', [
    ('unsigned Local=(Extra+1)*2;', 'unsigned Extra'),
    ('int Local=(Extra/2)+1;', 'int Extra'),
    ('int Local=(Extra*2)+1;', 'unsigned char Extra'),
    ('int Local=(Extra/2)*2;', 'int Extra'),
    ('int Local=Extra>>1;', 'unsigned Extra'),
    ('unsigned Local=Extra>>(Count%32);', 'unsigned Extra,unsigned Count'),
    ('int Local=(Extra<<1)+1;', 'unsigned char Extra'),
    ('int Local=(int)(Extra/2);', 'unsigned Extra'),
    ('int Local=-Extra;', 'unsigned char Extra'),
    ('int Local=-(Extra/2);', 'int Extra'),
    ('unsigned Local=-Extra;', 'unsigned Extra'),
    ('int Local=~Extra;', 'unsigned char Extra'),
    ('int Local=~Extra;', 'int Extra'),
    ('int Local=+Extra;', 'int Extra'),
    ('int Local=(Extra>0)*2;', 'int Extra'),
])
def test_compound_and_unary_prefixes_reach_real_overflow_disproof(prefix, extra, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    result = sweep._run_smt_verb_inner(file_path='record.' + language, function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'refuted', result.details
    assert result.details['source_scope']['query_contract'] == 'common-width-integer-operands-v18'


@pytest.mark.parametrize('prefix,extra', [
    ('int Local=(Extra+1)-1;', 'int Extra'),
    ('int Local=(Extra*2)/2;', 'int Extra'),
    ('int Local=(Extra/-1)*0;', 'int Extra'),
    ('int Local=-(Extra);', 'int Extra'),
    ('unsigned Local=(-Extra)*0;', 'int Extra'),
    ('unsigned Local=Extra>>(Count%33);', 'unsigned Extra,unsigned Count'),
    ('unsigned Local=Extra/(Count%32);', 'unsigned Extra,unsigned Count'),
    ('int Local=(int)(Extra+1);', 'unsigned Extra'),
    ('int Local=-(int)Extra;', 'unsigned Extra'),
    ('int Local=Local+1;', 'int Extra'),
    ('unsigned Local=(Extra+Signed)*2;', 'unsigned Extra,int Signed'),
])
def test_invalid_intermediate_steps_cannot_be_erased_by_a_safe_final_value(prefix, extra):
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []


def test_nested_proofs_share_one_query_cap(monkeypatch):
    from core.audit import arithmetic_prefix_obligations as obligations
    real_check = obligations.check_solver
    calls = []

    def check(solver):
        calls.append(solver)
        return real_check(solver)

    monkeypatch.setattr(obligations, 'check_solver', check)
    expression = 'Extra'
    for _ in range(9):
        expression = '(' + expression + '/2)'
    result = bind_arithmetic_operation(source('int Local=' + expression + ';', 'int Extra'), ['Value', 'Step'], '+',
                                       language='c', integer_abi='ilp32')
    assert result.guard_status == 'unavailable' and 0 < len(calls) <= 8


@pytest.mark.parametrize('verb,version', [('check-overflow', 'common-width-integer-operands-v16'),
                                        ('check-array-bounds', 'common-width-array-guards-v5')])
def test_old_worker_cannot_supply_a_compound_prefix_result(monkeypatch, verb, version):
    text = source('unsigned Local=(Extra+1)*2;')
    hypothesis = 'integer overflow in `Value + Step`'
    if verb == 'check-array-bounds':
        text = ('int Read(int Index,unsigned Extra){int Data[4]={0};unsigned Local=(Extra+1)*2;'
                'if(Index>=0 && Index<=4){return Data[Index];}return 0;}')
        hypothesis = 'out-of-bounds read at Data[Index]'
    _, selected = source_for_function(text, 'record.c', 'Read')
    binding = source_binding(selected, 'Read', verb=verb, integer_abi='ilp32', hypothesis=hypothesis)
    binding['query_contract'] = version
    old = sweep.SweepResult(tool='smt', file_path='record.c', function_name='Read', rule_id='smt:' + verb,
                            outcome='confirmed', details={'source_scope': binding}, matches=[{'model': {}}])
    monkeypatch.setattr('core.audit.subproc_json.run_json_child', lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path='record.c', function_name='Read', verb=verb,
                                         source=text, hypothesis=hypothesis, integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    assert result.details['source_scope_status'] == 'unbound-worker-result'


@pytest.mark.parametrize('expression', ['(Extra/2)+1', '(Extra*2)-1', '-(Extra/2)', '~Extra', '+Extra',
                                      '(Extra<<1)+1', '(Extra>>1)+1'])
@pytest.mark.parametrize('spelling', ['signed char', 'unsigned char'])
def test_compound_result_domains_contain_every_independent_integer_value(expression, spelling):
    data = f'int Read({spelling} Extra){{return {expression};}}'.encode()
    root = _get_parser('c').parse(data).root_node
    function = root.named_children[0]
    returned = function.child_by_field_name('body').named_children[0].named_children[0]
    domain = PrefixIntegerModel(data, 'c', resolve_integer_abi('ilp32')).value_domain(returned)
    if spelling == 'signed char' and ('<<' in expression or '>>' in expression):
        assert domain is None  # negative signed shifts retain their strict refusals
        return
    assert domain is not None
    for value in range(-128, 128) if spelling == 'signed char' else range(256):
        quotient = -(abs(value) // 2) if value < 0 else value // 2
        expected = {
            '(Extra/2)+1': quotient + 1,
            '(Extra*2)-1': value * 2 - 1,
            '-(Extra/2)': -quotient,
            '~Extra': -value - 1,
            '+Extra': value,
            '(Extra<<1)+1': value * 2 + 1,
            '(Extra>>1)+1': value // 2 + 1,
        }[expression]
        assert domain[0] <= expected <= domain[1], (expression, spelling, value, domain)


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix,extra', [
    ('unsigned Local=(Extra+1)*2;', 'unsigned Extra'),
    ('unsigned Local=Extra>>(Count%32);', 'unsigned Extra,unsigned long Count'),
    ('int Local=-Extra;', 'unsigned char Extra'),
    ('int Local=~Extra;', 'int Extra'),
    ('int Local=-(Extra/2);', 'int Extra'),
])
def test_array_verification_consumes_compound_and_unary_prefixes(prefix, extra, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    from core.audit.array_bounds import check_array_bounds
    text = ('int Read(int Index,' + extra + '){int Data[4]={0};' + prefix
            + 'if(Index>=0 && Index<=4){return Data[Index];}return 0;}')
    result = check_array_bounds(text, 'out-of-bounds read at Data[Index]', language=language, integer_abi='lp64')
    assert result['array_bounds_status'] == 'checked' and result['violation'] is True, result
    assert result['witness_index'] == 4 and 'Local' not in result['model']


@pytest.mark.parametrize('prefix', ['int Local=-Extra;', 'int Local=(Extra*2)/2;', 'int Local=~(-Extra);'])
def test_array_consumer_does_not_skip_undefined_unary_or_compound_steps(prefix):
    from core.audit.array_bounds import check_array_bounds
    text = ('int Read(int Index,int Extra){int Data[4]={0};' + prefix
            + 'if(Index>=0 && Index<=4){return Data[Index];}return 0;}')
    result = check_array_bounds(text, 'out-of-bounds read at Data[Index]', language='c', integer_abi='ilp32')
    assert result['array_bounds_status'] == 'unavailable' and result['violation'] is None


def test_deep_compounds_decline_before_any_unbounded_proof_work(monkeypatch):
    from core.audit import arithmetic_prefix_obligations as obligations
    monkeypatch.setattr(obligations, 'check_solver', lambda *a: pytest.fail('depth-limited expression reached SMT'))
    expression = 'Extra'
    for _ in range(70):
        expression = '(' + expression + '*1)'
    result = bind_arithmetic_operation(source('int Local=' + expression + ';', 'int Extra'), ['Value', 'Step'], '+',
                                       language='c', integer_abi='ilp32')
    assert result.status == 'bound' and result.guard_status == 'unavailable'


@pytest.mark.parametrize('prefix', ['int Local=-Extra;', 'int Local=(Extra/2)+1;'])
def test_auxiliary_disproof_uses_the_compound_expression_model(prefix):
    from core.audit.condition_smt import disprove_integer_overflow
    result = disprove_integer_overflow('integer overflow in `Value + Step`', source(prefix, 'unsigned char Extra'),
                                      file_path='record.c', function_name='Read', integer_abi='ilp32')
    assert result.disproved is True


def test_unsigned_count_width_is_preserved_through_a_nested_remainder():
    text = source('unsigned Local=Extra<<(Count%32);', 'unsigned Extra,unsigned long Count')
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb='check-overflow',
                                     source=text, hypothesis='integer overflow in `Value + Step`', integer_abi='lp64')
    assert result.outcome == 'refuted', result.details


@pytest.mark.parametrize('defined', [False, True])
def test_real_audit_chain_promotes_only_a_defined_compound_prefix(tmp_path, monkeypatch, defined):
    from core.audit import orchestrator as orch, evidence_grade
    prefix = 'int Local=-(Extra/2);' if defined else 'int Local=-Extra;'
    text = ('int Read(int Index,int Extra){int Data[4]={0};' + prefix
            + 'if(Index>=0 && Index<=4){return Data[Index];}return 0;}')
    (tmp_path / 'record.c').write_text(text)
    calls = []

    def worker(**request):
        calls.append(request['verb'])
        return sweep._run_smt_verb_inner(**request)

    monkeypatch.setattr(sweep, '_smt_verb_in_subprocess', worker)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out', integer_abi='ilp32')
    result = orch._run_tool_chain([{'type': 'smt', 'config': {'verb': 'check-oob'}}], config=config,
                                 file_path='record.c', function_name='Read', line_start=1, source=text,
                                 hypothesis='out-of-bounds read at Data[Index]')
    assert calls[0] == 'check-array-bounds'
    if defined:
        assert result == ['smt:check-array-bounds']
        assert evidence_grade.is_verification_evidence(result[0])
    else:
        assert 'check-oob' in calls
        assert not any(evidence_grade.is_verification_evidence(rule) for rule in result)

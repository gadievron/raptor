"""New arithmetic obligations are consumed by real source verification."""

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


@pytest.fixture
def semantic_prefix_budget(monkeypatch):
    from core.audit import arithmetic_prefix_obligations

    # Proof semantics are independent of the production soft deadline.
    # Deadline, query-cap and non-proof controls keep their default budget.
    monkeypatch.setattr(arithmetic_prefix_obligations, '_BUDGET_MS', 5000)


def source(prefix, extra='unsigned Extra'):
    return ('unsigned Read(unsigned Value,unsigned Step,' + extra + '){' + prefix
            + 'if(Value<10 && Step<10){return Value+Step;}return 0;}')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix,extra', [
    ('unsigned Ignored=Extra/2;', 'unsigned Extra'),
    ('unsigned Ignored=Extra%3;', 'unsigned Extra'),
    ('int Ignored=Extra/2;', 'int Extra'),
    ('int Ignored=Extra%3;', 'int Extra'),
    ('int Ignored=Extra/-2;', 'int Extra'),
    ('unsigned Ignored=Extra>>3;', 'unsigned Extra'),
    ('int Ignored=Extra>>3;', 'unsigned char Extra'),
    ('unsigned Ignored=Extra>>Count;', 'unsigned Extra,bool Count'),
])
@pytest.mark.usefixtures("semantic_prefix_budget")
def test_safe_prefix_arithmetic_reaches_the_real_source_verifier(language, prefix, extra):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    if language == 'c':
        extra = extra.replace('bool Count', '_Bool Count')
    result = sweep._run_smt_verb_inner(file_path='record.' + language, function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`',
                                     integer_abi='ilp32')
    assert result.outcome == 'refuted', result.details
    assert result.details['source_scope']['query_contract'] == 'common-width-integer-operands-v25'


@pytest.mark.parametrize('prefix,extra', [
    ('unsigned Ignored=Value/Extra;', 'unsigned Extra'),
    ('unsigned Ignored=Value%Extra;', 'unsigned Extra'),
    ('int Ignored=Extra/-1;', 'int Extra'),
    ('int Ignored=Extra%-1;', 'int Extra'),
    ('unsigned Ignored=Extra>>32;', 'unsigned Extra'),
    ('unsigned Ignored=Extra>>-1;', 'unsigned Extra'),
    ('unsigned Ignored=Extra>>Count;', 'unsigned Extra,unsigned char Count'),
    ('int Ignored=Extra>>1;', 'int Extra'),
])
def test_fault_or_missing_language_assumption_never_receives_source_credit(prefix, extra):
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`',
                                     integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []


@pytest.mark.parametrize('outcome', ['unknown', 'sat'])
def test_nonproof_cannot_admit_a_prefix(monkeypatch, outcome):
    from core.audit import arithmetic_prefix_obligations as obligations
    from core.smt_solver import z3
    monkeypatch.setattr(obligations, 'check_solver', lambda solver: getattr(z3, outcome))
    result = bind_arithmetic_operation(source('unsigned Ignored=Extra/2;'), ['Value', 'Step'], '+',
                                       language='c', integer_abi='ilp32')
    assert result.guard_status == result.type_status == 'unavailable'


def test_prefix_definedness_queries_have_a_per_binding_cap(monkeypatch):
    from core.audit import arithmetic_prefix_obligations as obligations
    real_check = obligations.check_solver
    checks = []

    def count(solver):
        checks.append(solver)
        return real_check(solver)

    monkeypatch.setattr(obligations, 'check_solver', count)
    prefix = ''.join(f'unsigned Local{index}=Extra/2;' for index in range(9))
    result = bind_arithmetic_operation(source(prefix), ['Value', 'Step'], '+', language='c', integer_abi='ilp32')
    assert result.guard_status == 'unavailable' and len(checks) <= 8
    assert checks


def test_expired_budget_does_not_allocate_a_solver(monkeypatch):
    from core.audit import arithmetic_prefix_obligations as obligations
    from core.smt_solver import z3
    budget = obligations.PrefixProofBudget()
    budget.deadline = 1.0
    monkeypatch.setattr(obligations, 'monotonic', lambda: 2.0)
    monkeypatch.setattr(obligations, 'new_solver', lambda **kw: pytest.fail('expired query allocated solver'))
    assert not budget.impossible(z3.BoolVal(False), [])
    assert budget.checks == 0


@pytest.mark.parametrize('outcome', ['confirmed', 'refuted'])
def test_pre_definedness_worker_contract_cannot_supply_a_verdict(monkeypatch, outcome):
    text = source('unsigned Ignored=Extra/2;')
    _, selected = source_for_function(text, 'record.c', 'Read')
    binding = source_binding(selected, 'Read', verb='check-overflow', integer_abi='ilp32',
                             hypothesis='integer overflow in `Value + Step`')
    binding['query_contract'] = 'common-width-integer-operands-v14'
    old = sweep.SweepResult(tool='smt', file_path='record.c', function_name='Read', rule_id='smt:check-overflow',
                            outcome=outcome, details={'source_scope': binding}, matches=[{'model': {}}])
    monkeypatch.setattr('core.audit.subproc_json.run_json_child', lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path='record.c', function_name='Read', verb='check-overflow',
                                         source=text, hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    assert result.details['source_scope_status'] == 'unbound-worker-result'


@pytest.mark.parametrize('prefix', [
    'unsigned Local=Local;',
    'unsigned Local=(unsigned)Local;',
    'unsigned Local=Local/2;',
    'unsigned Local=Local%3;',
    'unsigned Local=Local>>1;',
    'unsigned Earlier=1,Local=Local;',
])
def test_a_self_initializer_does_not_get_a_defined_value_from_its_storage_type(prefix):
    result = bind_arithmetic_operation(source(prefix), ['Value', 'Step'], '+', language='c', integer_abi='ilp32')
    assert result.guard_status == result.type_status == 'unavailable'


@pytest.mark.usefixtures("semantic_prefix_budget")
def test_sizeof_a_local_in_its_initializer_does_not_read_an_indeterminate_value():
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb='check-overflow',
                                     source=source('unsigned Local=sizeof(Local);'),
                                     hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
    assert result.outcome == 'refuted', result.details


@pytest.mark.usefixtures("semantic_prefix_budget")
def test_auxiliary_disproof_consumes_the_same_defined_prefix_model():
    from core.audit.condition_smt import disprove_integer_overflow
    text = source('int Local=Extra/2;', extra='int Extra')
    result = disprove_integer_overflow('integer overflow in `Value + Step`', text,
                                      file_path='record.c', function_name='Read', integer_abi='ilp32')
    assert result.disproved is True


@pytest.mark.parametrize('spelling', ['signed char', 'unsigned char'])
@pytest.mark.parametrize('operator', ['/', '%'])
@pytest.mark.parametrize('divisor', [-7, -2, -1, 1, 2, 3, 7])
def test_proven_prefix_result_domains_contain_every_independent_integer_result(spelling, operator, divisor, monkeypatch):
    from core.audit.arithmetic_prefix import PrefixIntegerModel
    from core.audit import arithmetic_prefix_obligations
    # Interval correctness is independent of the production soft deadline.
    monkeypatch.setattr(arithmetic_prefix_obligations, '_BUDGET_MS', 5000)
    from core.audit.condition_extraction import _get_parser
    from core.audit.integer_abi import resolve_integer_abi
    data = f'int Read({spelling} Extra){{return Extra {operator} {divisor};}}'.encode()
    root = _get_parser('c').parse(data).root_node
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == 'binary_expression':
            break
        pending.extend(node.named_children)
    else:
        pytest.fail('fixture did not parse its arithmetic expression')
    model = PrefixIntegerModel(data, 'c', resolve_integer_abi('ilp32'))
    domain = model.value_domain(node)
    assert domain is not None
    low, high = domain
    values = range(-128, 128) if spelling == 'signed char' else range(256)
    for value in values:
        magnitude = abs(value) // abs(divisor)
        quotient = -magnitude if (value < 0) != (divisor < 0) else magnitude
        result = quotient if operator == '/' else value - divisor * quotient
        assert low <= result <= high, (spelling, operator, divisor, value, domain)

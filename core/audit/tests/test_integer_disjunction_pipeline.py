"""Diagnostic OR receipts and conservative solver-free QUALITY discovery."""
import pytest
from core.audit import arithmetic_seeds, integer_conjunction, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding
from core.audit.smt_evidence import is_diagnostic_smt_rule, is_non_refuting_smt_rule

SOURCE = 'int Read(int Value){if(Value != 0 || Value != 1)return 1;return 0;}'
CLAIM = 'Condition is always true in `Value != 0 || Value != 1`.'
VERB = 'check-integer-comparison'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def test_worker_receipt_remains_diagnostic_and_exactly_bound():
    result = sweep._run_smt_verb_inner(file_path='unit.c', function_name='Read', verb=VERB,
                                       source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == 'confirmed' and result.matches, result.errors
    assert result.details['source_scope'] == source_binding(SOURCE, 'Read', verb=VERB, hypothesis=CLAIM, integer_abi='lp64')
    assert result.details['source_scope']['query_contract'] == 'source-integer-comparison-v8'
    assert result.details['checked_property'] == 'constant-integer-disjunction'
    assert is_diagnostic_smt_rule('smt:'+VERB) and is_non_refuting_smt_rule('smt:'+VERB)


def test_quality_candidates_never_enter_solver_and_remain_idempotent(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('discovery entered proof')
    for name in ('ComparisonModel', 'guards_for_operation', 'new_solver'):
        monkeypatch.setattr(integer_conjunction, name, forbidden)
    gap = dict(file='unit.c', name='Read', line_start=1, line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap], {'unit.c': SOURCE}, mode='quality', integer_abi='lp64') == 1
    assert gap['injected_hypotheses'][0]['mechanism'] == CLAIM
    assert hypothesis_to_smt_verb(CLAIM) == VERB
    assert gap['injected_hypotheses'][0]['arithmetic_site']['binding_status'] == 'candidate'
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap], {'unit.c': SOURCE}, mode='quality', integer_abi='lp64') == 0
    other = dict(file='unit.c', name='Read', line_start=1, line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([other], {'unit.c': SOURCE}, mode='security', integer_abi='lp64') == 0

@pytest.mark.parametrize('expression,expected', [
    ('Value != 0 || Value != 1', 1), ('Value < 0 || Value >= 0', 1),
    ('Value != 0 || Value != 0', 0), ('Value < 0 || Value > 0', 0),
    ('Value != 1 || Value != 0x1', 0), ('Value != 0 || Value != 1U', 0),
])
def test_pure_filter_uses_converted_value_distinctness_and_exhaustive_relations(expression, expected):
    source = SOURCE.replace('Value != 0 || Value != 1', expression)
    assert len(integer_conjunction.disjunction_candidates(source, language='c', integer_abi='lp64')) == expected

@pytest.mark.slow
def test_real_confined_disjunction_receipt():
    result = sweep.run_smt_verb_direct(file_path='unit.c', function_name='Read', verb=VERB,
                                      source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['source_scope']['query_contract'] == 'source-integer-comparison-v8'
    assert result.details['checked_property'] == 'constant-integer-disjunction'
    assert result.details['entry_witness_validated']

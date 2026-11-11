"""Diagnostic conjunction receipts and solver-free QUALITY leads."""
import pytest
from core.audit import arithmetic_seeds, integer_conjunction, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding
from core.audit.smt_evidence import is_diagnostic_smt_rule, is_non_refuting_smt_rule

SOURCE = 'int Read(int Value){if(Value < 0 && Value >= 0)return 1;return 0;}'
CLAIM = 'Condition is always false in `Value < 0 && Value >= 0`.'
VERB = 'check-integer-comparison'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def test_receipt_is_diagnostic_and_binds_exact_source_hypothesis_and_abi():
    result = sweep._run_smt_verb_inner(file_path='unit.c', function_name='Read', verb=VERB,
                                       source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == 'confirmed' and result.matches, result.errors
    assert result.details['source_scope'] == source_binding(SOURCE, 'Read', verb=VERB, hypothesis=CLAIM, integer_abi='lp64')
    assert result.details['source_scope']['query_contract'] == 'source-integer-comparison-v10'
    assert result.details['checked_property'] == 'constant-integer-conjunction'
    assert is_diagnostic_smt_rule('smt:'+VERB) and is_non_refuting_smt_rule('smt:'+VERB)


def test_quality_discovery_is_solver_free_bounded_and_idempotent(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('candidate discovery entered proof')
    for name in ('ComparisonModel', 'guards_for_operation', 'new_solver'):
        monkeypatch.setattr(integer_conjunction, name, forbidden)
    gap = dict(file='unit.c', name='Read', line_start=1, line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap], {'unit.c': SOURCE}, mode='quality', integer_abi='lp64') == 1
    row = gap['injected_hypotheses'][0]
    assert row['mechanism'] == CLAIM and hypothesis_to_smt_verb(CLAIM) == VERB
    assert row['arithmetic_site']['binding_status'] == 'candidate'
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap], {'unit.c': SOURCE}, mode='quality', integer_abi='lp64') == 0
    for source, mode in [(SOURCE, 'security'), (SOURCE.replace('Value >= 0', 'Value < 10'), 'quality')]:
        other = dict(file='unit.c', name='Read', line_start=1, line_end=1)
        assert arithmetic_seeds.seed_arithmetic_hypotheses([other], {'unit.c': source}, mode=mode, integer_abi='lp64') == 0

@pytest.mark.slow
def test_real_confined_conjunction_receipt():
    result = sweep.run_smt_verb_direct(file_path='unit.c', function_name='Read', verb=VERB,
                                      source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['source_scope']['query_contract'] == 'source-integer-comparison-v10'
    assert result.details['checked_property'] == 'constant-integer-conjunction'
    assert result.details['entry_witness_validated']

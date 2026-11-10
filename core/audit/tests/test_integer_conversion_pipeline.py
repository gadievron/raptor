"""Source conversion value loss is diagnostic, scoped and non-refuting."""

import builtins
from copy import deepcopy
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from core.audit import arithmetic_seeds, evidence_grade, integer_conversion, orchestrator, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding
from core.audit.smt_evidence import is_diagnostic_smt_rule, is_non_refuting_smt_rule
from core.testing.module_views import module_function_view

SOURCE = 'int Read(unsigned Value){if(Value>255){unsigned char Small=Value;return Small;}return 0;}'
CLAIM = 'Potential non-representable unsigned conversion in `Small = Value`.'
VERB = 'check-integer-conversion'


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


@pytest.mark.parametrize('safe', [False, True])
def test_source_receipt_binds_conversion_goal_abi_and_diagnostic_scope(safe):
    source = SOURCE.replace('Value>255', 'Value<=255') if safe else SOURCE
    result = sweep._run_smt_verb_inner(file_path='unit.c', function_name='Read', verb=VERB,
                                      source=source, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == ('inconclusive' if safe else 'confirmed'), result.errors
    assert bool(result.matches) is not safe
    assert result.details['value_loss'] is not safe
    assert result.details['witness_validated'] is not safe
    assert result.details['oracle_scope'] == 'source-unsigned-conversion'
    binding = result.details['source_scope']
    assert binding == source_binding(source, 'Read', verb=VERB, hypothesis=CLAIM, integer_abi='lp64')
    assert binding['query_contract'] == 'source-unsigned-conversion-v1'
    assert binding['integer_abi']['name'] == 'lp64' and binding['hypothesis_sha256']


@pytest.mark.parametrize('suffix', ['', ':witness', ':guessed'])
def test_proven_value_loss_does_not_verify_bug_intent_or_clear_a_function(suffix):
    stamp = 'smt:' + VERB + suffix
    assert is_diagnostic_smt_rule(stamp) and is_non_refuting_smt_rule(stamp)
    assert not evidence_grade.is_verification_evidence(stamp)
    assert not orchestrator._promotion_grade_receipt(stamp)
    assert sweep.get_smt_verb_role(VERB) == 'detection'


@pytest.fixture(scope='module')
def actual_worker_reply():
    result = sweep._run_smt_verb_inner(file_path='unit.c', function_name='Read', verb=VERB,
                                      source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == 'confirmed'
    return asdict(result)


@pytest.mark.parametrize('changed', [None, 'hypothesis_sha256', 'integer_abi', 'query_contract', 'sha256'])
def test_parent_rejects_an_unbound_worker_conversion_result(actual_worker_reply, changed):
    data = deepcopy(actual_worker_reply)
    if changed:
        data['details']['source_scope'][changed] = 'other'

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'subproc_json' and level == 1:
            return SimpleNamespace(run_json_child=lambda *a, **kw: data)
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(sweep, import_hook=local_import)
    result = view._smt_verb_in_subprocess(file_path='unit.c', function_name='Read', verb=VERB,
                                        source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == ('confirmed' if changed is None else 'inconclusive')
    assert bool(result.matches) is (changed is None)


@pytest.mark.parametrize('abi,goal', [(None, CLAIM), ('lp64', CLAIM.replace('Small = Value', 'Other = Value')),
                                    ('lp64', 'no ' + CLAIM)])
def test_missing_layout_or_unbound_objective_has_no_receipt(abi, goal):
    result = sweep._run_smt_verb_inner(file_path='unit.c', function_name='Read', verb=VERB,
                                      source=SOURCE, hypothesis=goal, integer_abi=abi)
    assert result.outcome == 'inconclusive' and result.matches == []


def test_quality_candidate_reaches_the_existing_review_path_without_native_prep():
    def forbidden(*a, **kw):
        raise AssertionError('candidate discovery entered conversion proof')
    conversion = module_function_view(integer_conversion, bindings={
        'guards_for_operation': forbidden, 'ComparisonModel': forbidden, 'new_solver': forbidden,
    })

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'integer_conversion' and level == 1:
            return conversion
        return builtins.__import__(name, globals, locals, fromlist, level)

    producer = module_function_view(arithmetic_seeds, import_hook=local_import)
    source = 'int Read(unsigned Value){Before();unsigned char Small=Value;return Small;}'
    gap = {'file': 'unit.c', 'name': 'Read', 'line_start': 1, 'line_end': 1}
    assert producer.seed_arithmetic_hypotheses([gap], {'unit.c': source}, mode='quality', integer_abi='lp64') == 1
    row = gap['injected_hypotheses'][0]
    assert row['confidence'] == 'low' and row['arithmetic_site']['binding_status'] == 'candidate'
    assert row['arithmetic_site']['claim_kind'] == 'unsigned-conversion-loss'
    assert 'verdict' not in row and 'confirmed' not in row
    assert hypothesis_to_smt_verb(row['mechanism']) == VERB
    result = sweep._run_smt_verb_inner(file_path='unit.c', function_name='Read', verb=VERB,
                                      source=source, hypothesis=row['mechanism'], integer_abi='lp64')
    assert result.outcome == 'inconclusive' and result.matches == []


def test_existing_quality_leads_keep_priority_over_new_conversions():
    source = ('int Read(unsigned Index,int Value,int Count){int Data[4]={0};'
              'int Ratio=Value/Count;unsigned char Small=Value;'
              'if(Index<0)return 0;return Data[Index];}')
    gap = {'file': 'unit.c', 'name': 'Read', 'line_start': 1, 'line_end': 1}
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap], {'unit.c': source}, mode='quality', integer_abi='lp64') == 4
    assert [row['arithmetic_site']['claim_kind'] for row in gap['injected_hypotheses']] == [
        'zero-divisor', 'signed-division-overflow', 'constant-comparison-false', 'fixed-array-read']


@pytest.mark.slow
def test_real_confined_conversion_worker_keeps_the_source_property_diagnostic():
    result = sweep.run_smt_verb_direct(file_path='unit.c', function_name='Read', verb=VERB,
                                      source=SOURCE, hypothesis=CLAIM, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['witness_validated'] and not result.errors
    assert result.details['source_value'] > 255
    assert result.details['oracle_scope'] == 'source-unsigned-conversion'
    assert result.details['source_scope']['query_contract'] == 'source-unsigned-conversion-v1'
    assert not evidence_grade.is_verification_evidence(result.rule_id)

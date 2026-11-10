"""Explicit condition-truth receipts remain diagnostic and exactly source bound."""
import builtins
from copy import deepcopy
from dataclasses import asdict
from types import SimpleNamespace
import pytest
from core.audit import arithmetic_seeds, evidence_grade, integer_condition, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding
from core.audit.smt_evidence import is_diagnostic_smt_rule,is_non_refuting_smt_rule
from core.testing.module_views import module_function_view

SOURCE='int Read(unsigned Flags){if(Flags & 4 == 0)return 1;return 0;}'
CLAIM='Condition is always false in `Flags & 4 == 0`.'
VERB='check-integer-comparison'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def test_source_truth_receipt_binds_new_goal_and_actual_ast():
    result=sweep._run_smt_verb_inner(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed' and result.matches,result.errors
    assert result.details['constant_truth'] is False and result.details['entry_witness_validated']
    assert result.details['checked_property']=='constant-bitwise-condition'
    assert result.details['source_scope']==source_binding(SOURCE,'Read',verb=VERB,hypothesis=CLAIM,integer_abi='lp64')
    assert result.details['source_scope']['query_contract']=='source-integer-comparison-v8'

@pytest.mark.parametrize('suffix',['',':witness',':model',':unknown'])
def test_constant_condition_is_not_defect_intent_or_function_refutation(suffix):
    rule='smt:'+VERB+suffix
    assert is_diagnostic_smt_rule(rule) and is_non_refuting_smt_rule(rule)
    assert not evidence_grade.is_verification_evidence(rule)
    assert sweep.get_smt_verb_role(VERB)=='detection'

@pytest.mark.parametrize('field',['sha256','hypothesis_sha256','integer_abi','query_contract'])
def test_parent_rejects_changed_condition_worker_binding(field):
    reply=asdict(sweep._run_smt_verb_inner(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64'))
    assert reply['outcome']=='confirmed'
    reply=deepcopy(reply);reply['details']['source_scope'][field]='changed'
    def importer(name,globals=None,locals=None,fromlist=(),level=0):
        if name=='subproc_json' and level==1:return SimpleNamespace(run_json_child=lambda *a,**kw:reply)
        return builtins.__import__(name,globals,locals,fromlist,level)
    view=module_function_view(sweep,import_hook=importer)
    result=view._smt_verb_in_subprocess(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='inconclusive' and not result.matches


def test_quality_condition_candidates_are_pure_and_do_not_generalize_true_rhs(monkeypatch):
    def forbidden(*a,**kw):raise AssertionError('candidate discovery entered native condition proof')
    for name in ('guards_for_operation','ComparisonModel','new_solver'):
        monkeypatch.setattr(integer_condition,name,forbidden)
    gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==1
    row=gap['injected_hypotheses'][0]
    assert row['mechanism']==CLAIM and row['arithmetic_site']['binding_status']=='candidate'
    assert hypothesis_to_smt_verb(row['mechanism'])==VERB
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==0
    other=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([other],{'unit.c':SOURCE.replace('4 == 0','4 != 0')},mode='quality',integer_abi='lp64')==0

@pytest.mark.slow
def test_real_confined_actual_condition_receipt():
    result=sweep.run_smt_verb_direct(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed',result.errors
    assert result.details['constant_truth'] is False and result.details['entry_witness_validated']
    assert result.details['source_scope']['query_contract']=='source-integer-comparison-v8'
    assert result.details['checked_property']=='constant-bitwise-condition'

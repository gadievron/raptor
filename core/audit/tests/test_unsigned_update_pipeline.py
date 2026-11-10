"""Unsigned object-wrap receipts remain diagnostic and exactly source bound."""
import builtins
from copy import deepcopy
from dataclasses import asdict
from types import SimpleNamespace
import pytest
from core.audit import arithmetic_seeds,evidence_grade,sweep,unsigned_update
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding
from core.audit.smt_evidence import is_diagnostic_smt_rule,is_non_refuting_smt_rule
from core.testing.module_views import module_function_view

SOURCE='int Read(unsigned char Value){Value++;return 0;}'
CLAIM='Potential unsigned increment wrap in `Value++`.'
VERB='check-integer-update'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def test_receipt_uses_neutral_update_scope_and_exact_input_binding():
    result=sweep._run_smt_verb_inner(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed' and result.matches,result.errors
    assert result.details['oracle_scope']=='source-integer-update'
    assert result.details['source_scope']==source_binding(SOURCE,'Read',verb=VERB,hypothesis=CLAIM,integer_abi='lp64')
    assert result.details['source_scope']['query_contract']=='source-integer-update-v3'
    assert result.details['mathematical_result']==256 and result.details['stored_result']==0
    assert hypothesis_to_smt_verb(CLAIM)==VERB

@pytest.mark.parametrize('suffix',['',':witness',':model',':unknown'])
def test_defined_wrap_never_becomes_verification_or_function_refutation(suffix):
    rule='smt:'+VERB+suffix
    assert is_diagnostic_smt_rule(rule) and is_non_refuting_smt_rule(rule)
    assert not evidence_grade.is_verification_evidence(rule)

@pytest.mark.parametrize('field',['sha256','hypothesis_sha256','integer_abi','query_contract'])
def test_parent_rejects_changed_unsigned_worker_binding(field):
    reply=asdict(sweep._run_smt_verb_inner(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64'))
    assert reply['outcome']=='confirmed'
    reply=deepcopy(reply);reply['details']['source_scope'][field]='changed'
    def importer(name,globals=None,locals=None,fromlist=(),level=0):
        if name=='subproc_json' and level==1:
            return SimpleNamespace(run_json_child=lambda *args,**kwargs:reply)
        return builtins.__import__(name,globals,locals,fromlist,level)
    view=module_function_view(sweep,import_hook=importer)
    result=view._smt_verb_in_subprocess(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='inconclusive' and not result.matches


def test_quality_discovery_is_pure_appended_and_idempotent(monkeypatch):
    def forbidden(*args,**kwargs):
        raise AssertionError('discovery entered unsigned proof')
    for name in ('ComparisonModel','guards_for_operation','new_solver'):
        monkeypatch.setattr(unsigned_update,name,forbidden)
    gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==1
    row=gap['injected_hypotheses'][0]
    assert row['mechanism']==CLAIM and row['arithmetic_site']['binding_status']=='candidate'
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==0
    other=dict(file='unit.c',name='Read',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([other],{'unit.c':SOURCE},mode='security',integer_abi='lp64')==0

@pytest.mark.slow
def test_real_confined_unsigned_update_receipt():
    result=sweep.run_smt_verb_direct(file_path='unit.c',function_name='Read',verb=VERB,source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed',result.errors
    assert result.details['oracle_scope']=='source-integer-update'
    assert result.details['source_scope']['query_contract']=='source-integer-update-v3'
    assert result.details['model']=={'Value':255} and result.details['stored_result']==0
    assert result.details['witness_validated']

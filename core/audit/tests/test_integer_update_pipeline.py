"""Integer-update source receipts remain diagnostic and non-refuting."""
import builtins
from copy import deepcopy
from dataclasses import asdict
from types import SimpleNamespace
import pytest
from core.audit import arithmetic_seeds, evidence_grade, integer_update, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding
from core.audit.smt_evidence import is_diagnostic_smt_rule, is_non_refuting_smt_rule
from core.testing.module_views import module_function_view

SOURCE='int Update(int Value){return ++Value;}'
CLAIM='Potential signed increment overflow in `++Value`.'
VERB='check-integer-update'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')

@pytest.mark.parametrize('safe',[False,True])
def test_source_binding_and_observation(safe):
    source=SOURCE.replace('return ++Value;','if(Value<100)return ++Value;return 0;') if safe else SOURCE
    result=sweep._run_smt_verb_inner(file_path='unit.c',function_name='Update',verb=VERB,
                                    source=source,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome==('inconclusive' if safe else 'confirmed'),result.errors
    assert bool(result.matches) is not safe
    assert result.details['oracle_scope']=='source-signed-update'
    binding=source_binding(source,'Update',verb=VERB,hypothesis=CLAIM,integer_abi='lp64')
    assert result.details['source_scope']==binding
    assert binding['query_contract']=='source-signed-update-v2'
    assert binding['integer_abi']['name']=='lp64' and binding['hypothesis_sha256']

@pytest.mark.parametrize('suffix',['',':witness',':model',':unknown'])
def test_diagnostic_variants_cannot_promote_or_refute(suffix):
    rule='smt:'+VERB+suffix
    assert is_diagnostic_smt_rule(rule) and is_non_refuting_smt_rule(rule)
    assert not evidence_grade.is_verification_evidence(rule)
    assert sweep.get_smt_verb_role(VERB)=='detection'

@pytest.mark.parametrize('field',['sha256','hypothesis_sha256','integer_abi','query_contract'])
def test_parent_rejects_changed_worker_binding(field):
    reply=asdict(sweep._run_smt_verb_inner(file_path='unit.c',function_name='Update',verb=VERB,
                  source=SOURCE,hypothesis=CLAIM,integer_abi='lp64'))
    assert reply['outcome']=='confirmed'
    reply=deepcopy(reply);reply['details']['source_scope'][field]='changed'
    def importer(name,globals=None,locals=None,fromlist=(),level=0):
        if name=='subproc_json' and level==1:
            return SimpleNamespace(run_json_child=lambda *a,**kw:reply)
        return builtins.__import__(name,globals,locals,fromlist,level)
    view=module_function_view(sweep,import_hook=importer)
    result=view._smt_verb_in_subprocess(file_path='unit.c',function_name='Update',verb=VERB,
                                     source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='inconclusive' and not result.matches


def test_quality_discovery_is_pure_typed_and_reentrant(monkeypatch):
    def forbidden(*a,**kw):raise AssertionError('prep entered native proof')
    for name in ('guards_for_operation','ComparisonModel','new_solver'):
        monkeypatch.setattr(integer_update,name,forbidden)
    gap=dict(file='unit.c',name='Update',line_start=1,line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==1
    seed=gap['injected_hypotheses'][0]
    assert seed['mechanism']==CLAIM and seed['arithmetic_site']['binding_status']=='candidate'
    assert hypothesis_to_smt_verb(seed['mechanism'])==VERB
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap],{'unit.c':SOURCE},mode='quality',integer_abi='lp64')==0
    for spelling in ('short','unsigned'):
        other=dict(file='unit.c',name='Update',line_start=1,line_end=1)
        assert arithmetic_seeds.seed_arithmetic_hypotheses([other],{'unit.c':SOURCE.replace('int Value',spelling+' Value')},mode='quality',integer_abi='lp64')==0

@pytest.mark.slow
def test_actual_confined_update_receipt():
    result=sweep.run_smt_verb_direct(file_path='unit.c',function_name='Update',verb=VERB,
                                    source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed',result.errors
    assert result.details['model']=={'Value':2147483647}
    assert result.details['witness_validated'] and result.details['source_scope']['query_contract']=='source-signed-update-v2'
    assert result.details['oracle_scope']=='source-signed-update'

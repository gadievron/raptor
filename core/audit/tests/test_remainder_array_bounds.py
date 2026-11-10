"""C remainder array indices preserve signedness and caller replay."""
from dataclasses import replace
import pytest
from core.audit import arithmetic_seeds, array_bounds, array_index, sweep
from core.audit.literal_call import check_literal_calls, literal_call_witness_valid
from core.testing.module_views import module_function_view

SOURCE='int Read(int Index){int Data[4]={0};return Data[Index%4];}'
CLAIM='Potential out-of-bounds read at `Data[Index%4]`.'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')

@pytest.mark.parametrize('language',['c','cpp'])
@pytest.mark.parametrize('abi',['lp64','llp64','i16'])
def test_negative_c_remainder_is_an_actual_index(language,abi):
    result=array_bounds.check_array_bounds(SOURCE,CLAIM,language=language,integer_abi=abi)
    assert result['violation'] is True,result
    assert -4<result['witness_index']<0
    value=result['model']['Index']
    assert result['witness_index']==value+(abs(value)//4)*4
    assert result['source_access']['index_operator']=='%'
    assert result['source_access']['index_offset']==4

@pytest.mark.parametrize('source,claim', [
    (SOURCE.replace('int Index','unsigned Index'),CLAIM),
    (SOURCE.replace('return Data','if(Index>=0)return Data').replace('];}','];return 0;}'),CLAIM),
    (SOURCE.replace('Index%4','Index%1'),CLAIM.replace('Index%4','Index%1')),
])
def test_safe_modulo_frames_do_not_find_a_counterexample(source,claim):
    result=array_bounds.check_array_bounds(source,claim,language='c',integer_abi='lp64')
    assert result['array_bounds_status']=='checked' and result['violation'] is False,result


def test_unsigned_large_divisor_still_needs_the_real_array_extent():
    source=SOURCE.replace('int Index','unsigned Index').replace('Index%4','Index%8')
    result=array_bounds.check_array_bounds(source,CLAIM.replace('Index%4','Index%8'),language='c',integer_abi='lp64')
    assert result['violation'] is True and 4<=result['witness_index']<8,result

@pytest.mark.parametrize('expression',['Index%0','Index%-1','Index%Other','Index%4+1','4%Index'])
def test_invalid_or_unsupported_remainder_frames_refuse(expression):
    result=array_bounds.check_array_bounds(SOURCE.replace('Index%4',expression),CLAIM.replace('Index%4',expression),
                                           language='c',integer_abi='lp64')
    assert result['violation'] is None,result


def test_exact_divisor_and_closed_goal_are_required():
    assert array_bounds.check_array_bounds(SOURCE,CLAIM.replace('Index%4','Index%3'),language='c',integer_abi='lp64')['violation'] is None
    assert array_bounds.check_array_bounds(SOURCE,'No '+CLAIM,language='c',integer_abi='lp64')['violation'] is None


def test_python_replay_uses_c_truncation_and_rejects_invalid_forged_divisor():
    access=array_bounds.bind_array_access(SOURCE,CLAIM,language='c',integer_abi='lp64')
    assert access.status=='bound',access
    assert array_index.evaluate_array_index(access,{'Index':-1},'lp64')==-1
    assert array_index.evaluate_array_index(access,{'Index':-5},'lp64')==-1
    assert array_index.evaluate_array_index(replace(access,index_offset=0),{'Index':-1},'lp64') is None

@pytest.mark.parametrize('argument,verdict',[(-1,'violation'),(1,'safe'),(-4,'safe')])
def test_literal_caller_replays_computed_remainder(argument,verdict):
    source=SOURCE+f'\nint Drive(void){{return Read({argument});}}\n'
    reply=check_literal_calls(source,'Read','check-array-bounds',CLAIM,'lp64',[2],'c')
    assert reply['status']=='checked' and len(reply['calls'])==1,reply
    call=reply['calls'][0]
    assert call['verdict']==verdict,reply
    if verdict=='violation':
        assert call['witness_index']==-1
        assert literal_call_witness_valid(reply,call,'check-array-bounds',CLAIM,'lp64')
        assert not literal_call_witness_valid(reply,{**call,'witness_index':3},'check-array-bounds',CLAIM,'lp64')
    assert reply['binding']['query_contract']=='common-width-literal-frame-v17'


def test_pure_candidates_require_possible_negative_or_large_remainder():
    def forbidden(*a,**kw):raise AssertionError('candidate enumeration entered solver')
    guards=module_function_view(array_bounds,bindings={'guards_for_operation':forbidden})
    import builtins
    def importer(name,globals=None,locals=None,fromlist=(),level=0):
        if name=='array_bounds' and level==1:return guards
        return builtins.__import__(name,globals,locals,fromlist,level)
    producer=module_function_view(arithmetic_seeds,import_hook=importer)
    for spelling,divisor,expected in [('int',4,1),('unsigned',4,0),('int',1,0),('unsigned',8,1)]:
        source=SOURCE.replace('int Index',spelling+' Index').replace('Index%4',f'Index%{divisor}')
        gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
        assert producer.seed_arithmetic_hypotheses([gap],{'unit.c':source},mode='quality',integer_abi='lp64')==expected,gap
        if expected:
            row=gap['injected_hypotheses'][0]
            assert row['arithmetic_site']['index_operator']=='%' and row['arithmetic_site']['binding_status']=='candidate'

@pytest.mark.slow
def test_real_confined_remainder_index_receipt():
    result=sweep.run_smt_verb_direct(file_path='unit.c',function_name='Read',verb='check-array-bounds',
                                    source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed',result.errors
    assert result.details['witness_index']<0
    assert result.details['source_scope']['query_contract']=='common-width-array-guards-v16'
    assert '(Index%4)' in result.details['obligation']

"""Mask indices bind the real promoted bitwise expression and array extent."""
import builtins
from dataclasses import replace
import pytest
from core.audit import arithmetic_seeds, array_bounds, array_index, sweep
from core.audit.literal_call import check_literal_calls, literal_call_witness_valid
from core.smt_solver.session import query_budget
from core.testing.module_views import module_function_view

SOURCE='int Read(int Index){int Data[4]={0};return Data[Index&4];}'
CLAIM='Potential out-of-bounds read at `Data[Index&4]`.'

@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')

@pytest.mark.parametrize('language',['c','cpp'])
@pytest.mark.parametrize('abi',['lp64','llp64','i16'])
@pytest.mark.parametrize('spelling',['int','unsigned'])
def test_mask_equal_to_extent_can_select_the_extent(language,abi,spelling):
    pytest.importorskip('tree_sitter_'+language)
    result=array_bounds.check_array_bounds(SOURCE.replace('int Index',spelling+' Index'),CLAIM,language=language,integer_abi=abi)
    assert result['violation'] is True and result['witness_index']==4,result
    assert result['model']['Index']&4==4
    assert result['source_access']['index_operator']=='&'

@pytest.mark.parametrize('mask',[0,3])
def test_mask_below_extent_has_no_outside_index(mask):
    result=array_bounds.check_array_bounds(SOURCE.replace('Index&4',f'Index&{mask}'),CLAIM.replace('Index&4',f'Index&{mask}'),language='c',integer_abi='lp64')
    assert result['array_bounds_status']=='checked' and result['violation'] is False,result


def test_extent_need_not_be_a_power_of_two():
    result=array_bounds.check_array_bounds(SOURCE.replace('Data[4]','Data[3]').replace('Index&4','Index&3'),CLAIM.replace('Index&4','Index&3'),language='c',integer_abi='lp64')
    assert result['violation'] is True and result['witness_index']==3,result

@pytest.mark.parametrize('spelling,violation',[('signed char',True),('unsigned char',False)])
def test_narrow_promotion_preserves_signed_extension(spelling,violation):
    result=array_bounds.check_array_bounds(SOURCE.replace('int Index',spelling+' Index').replace('Index&4','Index&256'),CLAIM.replace('Index&4','Index&256'),language='c',integer_abi='lp64')
    assert result['violation'] is violation,result
    if violation:
        assert result['model']['Index']<0 and result['witness_index']==256

@pytest.mark.parametrize('condition,violation',[('Index<4',True),('Index>=0&&Index<4',False)])
def test_upper_only_signed_guard_does_not_exclude_mask_bits(condition,violation):
    source=SOURCE.replace('return Data',f'if({condition})return Data').replace('];}','];return 0;}')
    result=array_bounds.check_array_bounds(source,CLAIM,language='c',integer_abi='lp64')
    assert result['violation'] is violation,result
    if violation:assert result['model']['Index']<0 and result['witness_index']==4

@pytest.mark.parametrize('expression', ['Index&-1','Index&0xffffffffU','Index&2147483648','Index&Other','Index&4+1','Index|4','Index&&4','4&Index'])
def test_unknown_conversion_expression_and_operator_frames_refuse(expression):
    result=array_bounds.check_array_bounds(SOURCE.replace('Index&4',expression),CLAIM.replace('Index&4',expression),language='c',integer_abi='lp64')
    assert result['violation'] is None,result


def test_claim_cannot_change_mask_or_complete_goal():
    assert array_bounds.check_array_bounds(SOURCE,CLAIM.replace('Index&4','Index&3'),language='c',integer_abi='lp64')['violation'] is None
    assert array_bounds.check_array_bounds(SOURCE,'No '+CLAIM,language='c',integer_abi='lp64')['violation'] is None


def test_python_replay_preserves_negative_twos_complement_bits():
    access=array_bounds.bind_array_access(SOURCE,CLAIM,language='c',integer_abi='lp64')
    assert access.status=='bound',access
    assert array_index.evaluate_array_index(access,{'Index':-1},'lp64')==4
    assert array_index.evaluate_array_index(replace(access,index_offset=-1),{'Index':-1},'lp64') is None

@pytest.mark.parametrize('argument,verdict',[(4,'violation'),(-1,'violation'),(3,'safe')])
def test_literal_caller_mask_replay_and_forged_witness(argument,verdict):
    reply=check_literal_calls(SOURCE+f'\nint Drive(void){{return Read({argument});}}\n','Read','check-array-bounds',CLAIM,'lp64',[2],'c')
    assert reply['status']=='checked' and len(reply['calls'])==1,reply
    call=reply['calls'][0];assert call['verdict']==verdict,reply
    if verdict=='violation':
        assert call['witness_index']==4
        assert literal_call_witness_valid(reply,call,'check-array-bounds',CLAIM,'lp64')
        assert not literal_call_witness_valid(reply,{**call,'witness_index':0},'check-array-bounds',CLAIM,'lp64')
    assert reply['binding']['query_contract']=='common-width-literal-frame-v17'


def test_empty_budget_does_not_grant_a_mask_counterexample():
    with query_budget(0):
        result=array_bounds.check_array_bounds(SOURCE,CLAIM,language='c',integer_abi='lp64')
    assert result['violation'] is None,result


def test_mask_discovery_is_pure_and_respects_unsigned_storage_bits():
    def forbidden(*a,**kw):raise AssertionError('candidate prep entered native prefix proof')
    view=module_function_view(array_bounds,bindings={'guards_for_operation':forbidden})
    def importer(name,globals=None,locals=None,fromlist=(),level=0):
        if name=='array_bounds' and level==1:return view
        return builtins.__import__(name,globals,locals,fromlist,level)
    producer=module_function_view(arithmetic_seeds,import_hook=importer)
    for spelling,mask,expected in [('int',4,1),('unsigned',4,1),('int',3,0),('int',0,0),('signed char',256,1),('unsigned char',256,0)]:
        source=SOURCE.replace('int Index',spelling+' Index').replace('Index&4',f'Index&{mask}')
        gap=dict(file='unit.c',name='Read',line_start=1,line_end=1)
        assert producer.seed_arithmetic_hypotheses([gap],{'unit.c':source},mode='quality',integer_abi='lp64')==expected,gap
        if expected:
            assert gap['injected_hypotheses'][0]['arithmetic_site']['index_operator']=='&'
            assert gap['injected_hypotheses'][0]['arithmetic_site']['binding_status']=='candidate'

@pytest.mark.slow
def test_real_confined_mask_index_receipt():
    result=sweep.run_smt_verb_direct(file_path='unit.c',function_name='Read',verb='check-array-bounds',source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome=='confirmed',result.errors
    assert result.details['witness_index']==4
    assert result.details['source_scope']['query_contract']=='common-width-array-guards-v16'
    assert '(Index&4)' in result.details['obligation']

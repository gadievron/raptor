"""Refinement preserves the run's target layout without selecting a new one."""
from types import SimpleNamespace
import pytest
from core.audit import sweep
from core.audit.integer_abi import INTEGER_ABIS
from core.audit.refinement import dispatch_suggestion

SOURCE='int Read(unsigned char Value){Value++;return 0;}'
CLAIM='Potential unsigned increment wrap in `Value++`.'


def dispatch(config):
    return dispatch_suggestion(CLAIM,SimpleNamespace(hypothesis=CLAIM),
                                {'source':SOURCE,'file':'unit.c','function':'Read'},config)

@pytest.mark.parametrize('abi',['lp64',INTEGER_ABIS['lp64'].record(),'unknown',None])
def test_public_refinement_dispatch_preserves_configured_profile(monkeypatch,abi):
    seen=[]
    def capture(**kwargs):
        seen.append(kwargs)
        return SimpleNamespace(outcome='inconclusive',raw_output='bounded contract control')
    monkeypatch.setattr(sweep,'run_smt_verb_direct',capture)
    config=SimpleNamespace(target_path=None,integer_abi=abi)
    rows=dispatch(config)
    assert len(rows)==1 and rows[0]['tool']=='smt:check-integer-update'
    assert len(seen)==1 and seen[0]['integer_abi'] is abi
    assert seen[0]['source']==SOURCE and seen[0]['hypothesis']==CLAIM
    assert config.integer_abi is abi


def test_legacy_config_without_profile_forwards_none(monkeypatch):
    seen=[]
    def capture(**kwargs):
        seen.append(kwargs)
        return SimpleNamespace(outcome='inconclusive',raw_output='no selected ABI')
    monkeypatch.setattr(sweep,'run_smt_verb_direct',capture)
    rows=dispatch(SimpleNamespace(target_path=None))
    assert rows and seen[0]['integer_abi'] is None

@pytest.mark.parametrize('abi',[None,'unknown'])
def test_unknown_or_missing_layout_still_cannot_confirm(abi):
    rows=dispatch(SimpleNamespace(target_path=None,integer_abi=abi))
    assert len(rows)==1 and rows[0]['result'].startswith('inconclusive:'),rows

@pytest.mark.slow
def test_actual_refinement_typed_query_uses_selected_abi():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')
    rows=dispatch(SimpleNamespace(target_path=None,integer_abi='lp64'))
    assert len(rows)==1 and rows[0]['tool']=='smt:check-integer-update',rows
    assert rows[0]['result'].startswith('confirmed:'),rows

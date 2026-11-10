"""Initial language cores are local reading, not another review call."""

import json
from core.audit import orchestrator as orch, capabilities
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.wallclock import wall_deadline


def test_initial_normal_c_review_receives_conditional_foundation_without_asking(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME',str(tmp_path/'xdg'))
    target=tmp_path/'target';out=tmp_path/'out';target.mkdir();out.mkdir()
    (target/'unit.c').write_text('unsigned short f(unsigned value) { return value; }\n')
    (out/'checklist.json').write_text(json.dumps({'files':[{'path':'unit.c','items':[{'name':'f','line_start':1,'line_end':1}]}]}))
    monkeypatch.setattr(orch,'_run_mechanical_detectors',lambda *a,**k:({},set()))
    monkeypatch.setattr(orch,'_proactive_validate',lambda outcome,*a,**k:outcome)
    monkeypatch.setattr(capabilities,'probe_capabilities',lambda *a,**k:capabilities.AuditCapabilities())
    prompts=[]
    class Client:
        _call_cost_history=None
        def is_budget_exhausted(self):return False
        def generate_structured(self,prompt,schema,**kwargs):
            prompts.append((kwargs['task_type'],prompt))
            return StructuredResponse(result={'status':'clean','body':'Scripted initial assessment','reading_list':[],
                'language_reference_requests':[]},raw='',cost=0,model='scripted')
    client=Client();monkeypatch.setattr(orch,'_run_llm_client',lambda cfg:client)
    config=orch.OrchestratorConfig(target_path=target,out_dir=out,max_workers=1,resume=False,
        prefilter=False,validate=False,immediate_verify=False,sweep_validate_findings=False,
        max_refinements=0,deepen_suspicious=False,open_discovery=False,sage_recall=False,
        iris=False,joern_overrides={'enabled':False},llm_budget_client=client)
    with isolated_audit_shutdown(orch),wall_deadline(30,code_bound_s=float('inf'),what='initial C foundation control'):
        result=orch.run_orchestrator(config,make_review_fn(client,escalate_clean=False))
    assert len(prompts)==1 and prompts[0][0]=='audit' and result.outcomes[0].status=='clean'
    prompt=prompts[0][1]
    assert 'c.integer-promotion v1:' in prompt, 'initial normal C review has no typed promotion foundation'
    assert 'c.integer-conversion v1:' in prompt
    assert 'Target language edition is unknown' in prompt


import pytest


@pytest.mark.parametrize('small', [False, True])
def test_already_delivered_foundation_does_not_buy_an_identical_followup(tmp_path, monkeypatch, small):
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime
    from core.audit.reference_foundation import review_has_current_foundation
    source='unsigned short f(unsigned n) { return n; }'
    (tmp_path/'unit.c').write_text(source+'\n')
    runtime=AuditKnowledgeRuntime(tmp_path,orch.StudyQueue(),deadline=float('inf'),window=0)
    monkeypatch.setattr('core.audit.llm_review._prompt_budget',lambda *a,**k:100 if small else 100000)
    calls=[]
    class Client:
        def generate_structured(self,prompt,schema,**kwargs):
            calls.append(prompt)
            return StructuredResponse(result={'status':'clean','body':'Scripted assessment',
                'language_reference_requests':[{'topic':'integer promotion'}]},raw='',cost=0,model='scripted')
    ctx={'file':'unit.c','function':'f','line_start':1,'line_end':1,'source':source,'language':'c'}
    config=orch.OrchestratorConfig(target_path=tmp_path,out_dir=tmp_path/'out')
    outcome=runtime.wrap_review(make_review_fn(Client(),escalate_clean=False))(ctx,config)
    assert len(calls)==1
    assert review_has_current_foundation(outcome.review_result['review_claims']) is (not small)
    ready=runtime.ready_continuations(admission=lambda:True)
    if small:
        assert len(ready)==1, 'omitted reading is still useful new information'
        assert not any(e['event']=='reference_already_delivered' for e in runtime.events())
    else:
        assert not ready
        assert any(e['event']=='reference_already_delivered' for e in runtime.events())
    runtime.close()


def test_initial_panel_members_keep_their_actual_foundation_fitting(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime
    from core.audit.reference_foundation import review_has_current_foundation
    source='unsigned short f(unsigned n) { return n; }'
    (tmp_path/'unit.c').write_text(source+'\n')
    runtime=AuditKnowledgeRuntime(tmp_path,orch.StudyQueue(),deadline=float('inf'))
    ctx={'file':'unit.c','function':'f','line_start':1,'line_end':1,'source':source,'language':'c'}
    config=orch.OrchestratorConfig(target_path=tmp_path,out_dir=tmp_path/'out')
    monkeypatch.setattr('core.audit.llm_review._prompt_budget',lambda _ctx,system:100 if system=='small' else 100000)
    barrier=Barrier(2)
    class Client:
        def generate_structured(self,prompt,schema,**kwargs):
            barrier.wait(timeout=10)
            return StructuredResponse(result={'status':'clean','body':'Scripted panel'},raw='',cost=0,model='scripted')
    small=runtime.wrap_review(make_review_fn(Client(),system_prompt='small',escalate_clean=False))
    large=runtime.wrap_review(make_review_fn(Client(),system_prompt='large',escalate_clean=False))
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(small,ctx,config);b=pool.submit(large,ctx,config)
        left,right=a.result(timeout=15),b.result(timeout=15)
    left_rows=left.review_result['language_reference_delivery'];right_rows=right.review_result['language_reference_delivery']
    assert left_rows[0]['request_id']==right_rows[0]['request_id']
    assert left_rows[0]['delivered'] is False and right_rows[0]['delivered'] is True
    assert not review_has_current_foundation(left.review_result['review_claims'])
    assert review_has_current_foundation(right.review_result['review_claims'])
    runtime.close()


@pytest.mark.parametrize('file,language', [('unit.py','python'),('unit.cpp','cpp'),('unit.h','c'),('unit.C','cpp'),('binary:owned','c')])
def test_initial_foundation_does_not_invent_c_mode_for_other_subjects(tmp_path, file, language):
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime
    source='int f(void) { return 1; }'
    if not file.startswith('binary:'):
        (tmp_path/file).write_text(source+'\n')
    runtime=AuditKnowledgeRuntime(tmp_path,orch.StudyQueue(),deadline=float('inf'))
    class Client:
        def generate_structured(self,prompt,schema,**kwargs):
            assert 'Language reference (context, not proof)' not in prompt
            return StructuredResponse(result={'status':'clean','body':'Scripted subject'},raw='',cost=0,model='scripted')
    ctx={'file':file,'function':'f','line_start':1,'line_end':1,'source':source,'language':language}
    config=orch.OrchestratorConfig(target_path=tmp_path,out_dir=tmp_path/'out')
    outcome=runtime.wrap_review(make_review_fn(Client(),escalate_clean=False))(ctx,config)
    assert outcome.review_result['language_reference_delivery']==[]
    assert 'reference_inputs' not in outcome.review_result['review_claims']
    runtime.close()

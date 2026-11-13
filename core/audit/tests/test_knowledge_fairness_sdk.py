"""Actual SDK accounting joins the main graph's fair admission trace.

MockTransport and owned Python source exercise caller-context continuations;
this is not a source-study latency, provider, or global-ownership guarantee.
"""
from collections import Counter
from functools import wraps
import json

import pytest

from core.audit import capabilities,orchestrator as orch
from core.audit.journal import load_entries
from core.audit.llm_review import make_review_fn
from core.audit.record import load_verified_audit_log
from core.audit.review_claims import read_history
from core.inventory import save_checklist
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.wallclock import wall_deadline


@pytest.mark.slow
def test_actual_fair_graph_joins_sdk_attempts_and_journal_passes(tmp_path,monkeypatch,sdk_clients):
    target,out=tmp_path/'target',tmp_path/'out'
    target.mkdir()
    out.mkdir()
    (target/'units.py').write_text(''.join(f'def f{i}(n):\n    return n + 1\n' for i in range(10)))
    (target/'caller.py').write_text('def caller(n):\n    return '+ ' + '.join(f'f{i}(n)' for i in range(10))+'\n')
    items=[{'name':f'f{i}','kind':'function','line_start':2*i+1,'line_end':2*i+2} for i in range(10)]
    checklist={'files':[{'path':'units.py','items':items}]}
    save_checklist(out,checklist)
    inventory={'files':checklist['files']+[{'path':'caller.py','items':[
        {'name':'caller','kind':'function','line_start':1,'line_end':2}]}]}
    monkeypatch.setattr(orch,'_run_mechanical_detectors',lambda *a,**k:({},set()))
    monkeypatch.setattr(orch,'_proactive_validate',lambda outcome,*a,**k:outcome)
    monkeypatch.setattr(orch,'_study_consumer',lambda *a,**k:None)
    monkeypatch.setattr(capabilities,'probe_capabilities',lambda *a,**k:capabilities.AuditCapabilities())
    bundle=sdk_clients(cap=20.0,token_cap=1000000,max_calls=30,run_dir=out)
    def during_wire(request):
        admitted=[row for row in load_verified_audit_log(out) if row.get('stage')=='admitted']
        assert len(admitted)==len(bundle.state['requests'])
    bundle.state['handler']=during_wire
    def transform(row):
        message=row['choices'][0]['message']
        payload={'status':'suspicious','body':'Unresolved caller-dependent concern',
            'hypothesis':'The caller-dependent condition needs review',
            'caller_context_requests':[{'file':'caller.py','function':'caller','line_start':1,
                                         'reason':'Inspect this supplied related code'}]}
        if message.get('tool_calls'):
            message['tool_calls'][0]['function']['arguments']=json.dumps(payload)
        else:
            message['content']=json.dumps(payload)
        return row
    bundle.state['transform']=transform
    schema={'type':'object','properties':{'status':{'type':'string'},'body':{'type':'string'},
        'hypothesis':{'type':'string'},'caller_context_requests':{'type':'array','items':{
            'type':'object','properties':{'file':{'type':'string'},'function':{'type':'string'},
                'line_start':{'type':'integer'},'reason':{'type':'string'}},
            'required':['file','function','line_start','reason']}}},'required':['status','body']}
    rendered=make_review_fn(bundle.client,schema=schema,escalate_clean=False)
    admissions=[]
    @wraps(rendered)
    def review(context,config):
        admissions.append('C' if context.get('caller_context_answers') else 'I')
        return rendered(context,config)
    monkeypatch.setattr(orch,'_run_llm_client',lambda cfg:bundle.client)
    config=orch.OrchestratorConfig(target_path=target,out_dir=out,inventory=inventory,
        max_workers=1,resume=False,prefilter=False,prefilter_skip=False,triage=False,
        vendored_triage=False,batch_sloc_threshold=0,validate=False,immediate_verify=False,
        sweep_validate_findings=False,max_refinements=0,deepen_suspicious=False,
        open_discovery=False,sage_recall=False,iris=False,adversarial=False,clean_check=False,
        joern_overrides={'enabled':False},llm_budget_client=bundle.client,
        enable_session_context=False,on_demand_synthesis=False,propagate_constraints=False,
        no_binary_oracle=True,dynamic_validation=False,library_replay=False,
        cross_run_import=False,domain_model_import=False,annotations_read=False)
    with isolated_audit_shutdown(orch),wall_deadline(30,code_bound_s=float('inf'),what='joined fair SDK graph'):
        result=orch.run_orchestrator(config,review)
    assert ''.join(admissions[:12])=='IIICIIICIIIC'
    assert admissions.count('I')==admissions.count('C')==10
    assert len(result.outcomes)==10
    trace=json.loads((out/'review-admission.json').read_text())
    assert trace['scope']=='main_review_graph' and trace['global_review_ownership'] is False
    assert trace['policy']['initial_admissions']==trace['policy']['continuation_admissions']==10
    assert len(bundle.state['requests'])==bundle.client._governed_calls==20
    signed=load_verified_audit_log(out)
    admitted=[row for row in signed if row.get('stage')=='admitted']
    reported=[row for row in signed if row.get('stage')=='reported']
    assert len(admitted)==len(reported)==20
    admitted_by_id={row['attempt']['attempt_id']:row for row in admitted}
    reported_by_id={row['attempt']['attempt_id']:row for row in reported}
    assert len(admitted_by_id)==len(reported_by_id)==20
    assert admitted_by_id.keys()==reported_by_id.keys()
    for attempt_id,row in admitted_by_id.items():
        reported_attempt=reported_by_id[attempt_id]['attempt']
        assert reported_attempt['work_id']==row['attempt']['work_id']
        assert reported_attempt['beneficiaries']==row['attempt']['beneficiaries']
    assert all(row['tokens_in']==row['tokens_out']==3 for row in reported)
    history=json.loads((out/'knowledge-results.json').read_text())
    attempts=[event for event in history['events'] if event['event']=='review_attempt']
    calls=[event for event in history['events'] if event['event']=='client_call_attempt']
    assert len(attempts)==len(calls)==20
    passes={event['origin']['pass_id']:event for event in attempts}
    assert len(passes)==20
    assert Counter(row['attempt']['beneficiaries'][0] for row in admitted)==Counter({key:1 for key in passes})
    # SDK attempt IDs and renderer attempt IDs are distinct namespaces; the
    # unique work/beneficiary pass binding joins them without conflating IDs.
    for row in admitted:
        pass_id=row['attempt']['beneficiaries'][0]
        assert row['attempt']['work_id']=='review:'+pass_id and pass_id in passes
        assert row['attempt']['beneficiaries']==[pass_id]
    journals=load_entries(out,fresh=True)
    retained_passes=set()
    for row in journals:
        retained=read_history(row.review_claims)
        assert retained is not None
        reviews=([retained['review']] if isinstance(retained.get('review'),dict) else [])
        reviews.extend(intake['review'] for intake in retained['intakes'] if isinstance(intake.get('review'),dict))
        for recorded in reviews:
            pass_id=recorded['origin']['pass_id']
            assert recorded['attempt_id']==passes[pass_id]['attempt_id']
            retained_passes.add(pass_id)
    assert retained_passes==set(passes)
    assert not bundle.client.pending_usage_reservations and not bundle.client._prepared_resource_reservations
    assert bundle.client.reported_spend_usd>0
    assert result.llm_spend_usd==pytest.approx(bundle.client.reported_spend_usd)
    assert result.cost_tracker.total_spend_usd==pytest.approx(bundle.client.reported_spend_usd)
    costs=json.loads((out/'cost-breakdown.json').read_text())['attempt_accounting']
    assert costs['status']=='projected' and not costs['gaps']
    assert len(costs['attempts'])==20
    assert {row['attempt_id'] for row in costs['attempts']}=={row['attempt']['attempt_id'] for row in reported}
    assert sum(row['cost_usd'] for row in costs['attempts'])==pytest.approx(bundle.client.reported_spend_usd)

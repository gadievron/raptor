"""Owned binary advisory continuations use actual fitting and durable ACKs.

Owned bytes and an explicit in-memory view are not extraction/build evidence.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
from time import monotonic

import pytest

from core.audit import orchestrator as orch
from core.audit.binary_context import assemble_binary_context
from core.audit.collector import Collector
from core.audit.journal import load_entries
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.layer_resolution import Disagreement, DisagreementKind, LayerClaim, LayerVerdict
from core.audit.llm_review import make_review_fn
from core.inventory import save_checklist
from core.inventory.binary_builder import binary_path_key
from core.llm.providers import StructuredResponse
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction


@pytest.fixture
def binary_case(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path/'data'))
    target, out = tmp_path/'owned.bin', tmp_path/'out'
    original = b'owned module, not an executable'
    target.write_bytes(original)
    key = binary_path_key(target)
    item = {'name':'f','kind':'function','line_start':0,'line_end':None,'address':4096,'size':32}
    checklist = {'target_path':str(target),'target_kind':'binary','files':[
        {'path':key,'sha256':hashlib.sha256(original).hexdigest(),'items':[item]}]}
    save_checklist(out,checklist)
    database = REDatabase(source_tool='ghidra',binary_path=str(target),functions=[
        REFunction(name='f',address=4096,size=32,source_tool='ghidra',decompilation='return n + 1;')])
    def build(*args,**kwargs):
        return assemble_binary_context(target_path=target,file_path=key,function_name='f',
                                       checklist=checklist,db=database)
    monkeypatch.setattr(orch,'_build_context',build)
    runtime = AuditKnowledgeRuntime(target,orch.StudyQueue(),deadline=float('inf'),window=0)
    config = orch.OrchestratorConfig(target_path=target,out_dir=out,enable_session_context=False,
                                    immediate_verify=False,sweep_validate_findings=False)
    class Client:
        def __init__(self):
            self.prompts=[]
            self.next_status='suspicious'
            self.after=lambda:None
        def generate_structured(self,prompt,schema,**kwargs):
            self.prompts.append(prompt)
            if len(self.prompts)>1:
                self.after()
            payload={'status':'clean' if len(self.prompts)==1 else self.next_status,
                     'body':'Initial independent review' if len(self.prompts)==1 else 'Advisory reassessment',
                     'hypothesis':'Inspect the observed view'}
            return StructuredResponse(result=payload,raw='',cost=.1,model='captured')
    client=Client()
    review=make_review_fn(client,escalate_clean=False)
    prior=runtime.wrap_review(review)(build(),config)
    gap={**item,'file':key}
    assert prior.status=='clean' and Collector(out_dir=out,target_path=target,run_id=out.name).submit(prior,gap)
    result=orch.OrchestratorResult(outcomes=[prior],reviewed=1,clean=1,total_cost_usd=prior.cost_usd)
    disagreement=Disagreement(file=key,function='f',kind=DisagreementKind.MECHANICAL_VS_LLM,
        mechanical_claim=LayerClaim(LayerVerdict.MECHANICAL,reachable=None,has_flow=None),
        resolution='Advisory independent reassessment requested',winner=LayerVerdict.MECHANICAL)
    def run(reviewer=review):
        return orch._re_review_disagreements([disagreement],result,config,reviewer,checklist,
            None,{},monotonic(),None,knowledge_runtime=runtime)
    try:
        yield target,original,database,config,runtime,client,result,prior,run,checklist,gap
    finally:
        runtime.close('test_complete')


def test_actual_binary_advisory_continuation_publishes_only_after_ack(binary_case):
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    assert run() is result
    assert len(client.prompts)==2, 'owned binary advisory continuation was not dispatched'
    assert 'Advisory mechanical disagreement' in client.prompts[1]
    assert result.outcomes[0] is not prior and result.outcomes[0].status=='suspicious'
    assert result.clean==0 and result.suspicious==1
    assert result.total_cost_usd==pytest.approx(.2)
    rows=load_entries(cfg.out_dir,fresh=True)
    assert len(rows)==2
    row=rows[-1]
    assert row.source_hash.startswith('bin:ctx1:') and row.verdict=='suspicious'
    origin=row.review_claims['review']['origin']
    assert origin['source_identity'] is None and origin['line_start']==0
    assert origin['binary_identity']['module_sha256']==hashlib.sha256(original).hexdigest()
    events=runtime.events()
    reserved=[e for e in events if e['event']=='continuation_reserved']
    completed=[e for e in events if e['event']=='continuation_completed']
    assert len(reserved)==len(completed)==1
    assert origin['pass_id']==reserved[0]['pass_id']==completed[0]['pass_id']
    assert row.review_claims['binary_inputs']['origin']==origin
    assert not runtime._active
    from core.coverage.record import build_from_journal
    from core.audit.gaps import compute_gaps
    # The new contextual row must not turn into existence-only clean credit.
    assert not build_from_journal(cfg.out_dir)['functions_analysed']
    assert any(g['name']=='f' for g in compute_gaps(checklist,[],out_dir=cfg.out_dir))


@pytest.mark.parametrize('status',['clean','dormant'])
def test_binary_advisory_retains_prior_verdict_with_context_history(binary_case,status):
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    client.next_status=status
    run()
    assert len(client.prompts)==2 and result.outcomes[0] is not prior
    assert result.outcomes[0].status=='clean' and result.outcomes[0].body==prior.body
    row=load_entries(cfg.out_dir,fresh=True)[-1]
    assert row.source_hash.startswith('bin:ctx1:') and 'binary_inputs' in row.review_claims
    assert result.total_cost_usd==pytest.approx(.2)
    assert any(e['event']=='continuation_completed' for e in runtime.events())


@pytest.mark.parametrize('change',['changed','restored'])
def test_changed_binary_during_advisory_keeps_prior_and_charge(binary_case,change):
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    def mutate():
        target.write_bytes(b'owned changed module')
        if change=='restored':
            target.write_bytes(original)
    client.after=mutate
    run()
    assert len(client.prompts)==2 and result.outcomes[0] is prior
    # The runtime records the completed paid response before refusing it.
    paid=[e for e in runtime.events() if e['event']=='review_assessment']
    assert len(paid)==2 and paid[-1]['cost_usd']==.1
    assert len(load_entries(cfg.out_dir,fresh=True))==1
    assert not any(e['event']=='continuation_completed' for e in runtime.events())
    assert not runtime._active


@pytest.mark.parametrize('change',['view','extent','module','json-snapshot'])
def test_binary_continuation_cannot_refresh_initial_input(binary_case,change,monkeypatch):
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    if change=='view':
        db.functions[0].decompilation='return n + 2;'
    elif change=='extent':
        db.functions[0].size=64
    elif change=='module':
        target.write_bytes(b'owned replaced module')
    else:
        # Unknown ownership cannot be supplied by a serialized transient stamp.
        import core.audit.orchestrator as module
        original_build=module._build_context
        def build(*a,**k):
            ctx=original_build(*a,**k)
            from dataclasses import asdict
            ctx['_binary_module_snapshot']=asdict(ctx['_binary_module_snapshot'])
            return ctx
        # The local fixture owns this builder; restore exactly after the call.
        monkeypatch.setattr(module,'_build_context',build)
        run()
        assert len(client.prompts)==1 and result.outcomes[0] is prior
        return
    run()
    assert len(client.prompts)==1 and result.outcomes[0] is prior


@pytest.mark.parametrize('status',['suspicious','clean'])
@pytest.mark.parametrize('failure',['none','wrong-anchor','wrong-history','changed-history','changed-both-history','competing-writer'])
def test_binary_publication_requires_exact_ack_and_canonical_owner(binary_case,monkeypatch,status,failure):
    import core.audit.collector as collector
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    client.next_status=status
    append=collector.append_journal_for_outcome
    competing=replace(prior,body='Another canonical owner')
    def write(*a,**kw):
        if failure=='none':
            return None
        ack=append(*a,**kw)
        assert ack is not None
        if failure=='wrong-anchor':
            return replace(ack,source_hash='bin:ctx1:unknown')
        if failure=='wrong-history':
            return replace(ack,review_claims=None)
        if failure in ('changed-history','changed-both-history'):
            kw['outcome'].review_result['review_claims']['omissions'].append('changed-after-write')
            return (replace(ack,review_claims=deepcopy(kw['outcome'].review_result['review_claims']))
                    if failure=='changed-both-history' else ack)
        result.outcomes[0]=competing
        return ack
    monkeypatch.setattr(collector,'append_journal_for_outcome',write)
    run()
    assert len(client.prompts)==2
    assert result.outcomes[0] is (competing if failure=='competing-writer' else prior)
    assert result.total_cost_usd==pytest.approx(.2)
    assert not any(e['event']=='continuation_completed' for e in runtime.events())
    assert not runtime._active


def test_forged_binary_delivery_cannot_publish(binary_case):
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    def forged(ctx,config):
        return orch.ReviewOutcome(ctx['file'],'f','suspicious','Forged delivery',line=0,cost_usd=.5,
            review_result={'external_context_delivery':[{'delivered':True}]})
    run(forged)
    assert result.outcomes[0] is prior and len(client.prompts)==1
    assert result.total_cost_usd==pytest.approx(.6)
    assert len(load_entries(cfg.out_dir,fresh=True))==1
    assert not any(e['event']=='continuation_completed' for e in runtime.events())


@pytest.mark.slow
@pytest.mark.parametrize('change',['healthy','changed','restored'])
def test_actual_sdk_binary_advisory_joins_signed_attempts_and_publication(tmp_path,monkeypatch,sdk_clients,change):
    import json
    from core.audit.tests.test_binary_paid_source_change import _runtime_binary_context
    from core.audit.record import load_verified_audit_log
    monkeypatch.setenv('XDG_DATA_HOME',str(tmp_path/'data'))
    target,ctx,runtime=_runtime_binary_context(tmp_path)
    original=target.read_bytes()
    out=tmp_path/'out'
    key=ctx['file']
    item={'name':'f','kind':'function','line_start':0,'line_end':None,'address':4096,'size':32}
    gap={**item,'file':key}
    checklist={'target_path':str(target),'target_kind':'binary','files':[
        {'path':key,'sha256':hashlib.sha256(original).hexdigest(),'items':[item]}]}
    save_checklist(out,checklist)
    monkeypatch.setattr(orch,'_build_context',lambda *a,**k:deepcopy(ctx))
    bundle=sdk_clients(cap=20.0,token_cap=1000000,run_dir=out)
    def wire(request):
        admitted=[r for r in load_verified_audit_log(out) if r.get('stage')=='admitted']
        assert len(admitted)==len(bundle.state['requests'])
        if len(bundle.state['requests'])==2 and change!='healthy':
            target.write_bytes(b'owned changed module')
            if change=='restored':
                target.write_bytes(original)
    bundle.state['handler']=wire
    def transform(row):
        message=row['choices'][0]['message']
        payload={'status':'clean' if len(bundle.state['requests'])==1 else 'suspicious',
                 'body':'Captured actual SDK advisory review','hypothesis':'Inspect the supplied view'}
        if message.get('tool_calls'):
            message['tool_calls'][0]['function']['arguments']=json.dumps(payload)
        else:
            message['content']=json.dumps(payload)
        return row
    bundle.state['transform']=transform
    schema={'type':'object','properties':{'status':{'type':'string'},'body':{'type':'string'},
        'hypothesis':{'type':'string'}},'required':['status','body']}
    review=make_review_fn(bundle.client,schema=schema,escalate_clean=False)
    cfg=orch.OrchestratorConfig(target_path=target,out_dir=out,enable_session_context=False,
        immediate_verify=False,sweep_validate_findings=False,llm_budget_client=bundle.client)
    try:
        prior=runtime.wrap_review(review)(deepcopy(ctx),cfg)
        assert prior.status=='clean'
        assert Collector(out_dir=out,target_path=target,run_id=out.name).submit(prior,gap)
        result=orch.OrchestratorResult(outcomes=[prior],reviewed=1,clean=1,total_cost_usd=prior.cost_usd)
        disagreement=Disagreement(file=key,function='f',kind=DisagreementKind.MECHANICAL_VS_LLM,
            mechanical_claim=LayerClaim(LayerVerdict.MECHANICAL,reachable=None,has_flow=None),
            resolution='Advisory independent reassessment requested',winner=LayerVerdict.MECHANICAL)
        orch._re_review_disagreements([disagreement],result,cfg,review,checklist,
                                     None,{},monotonic(),None,knowledge_runtime=runtime)
        assert len(bundle.state['requests'])==bundle.client._governed_calls==2
        assert 'Advisory mechanical disagreement' in bundle.state['requests'][1].content.decode()
        signed=load_verified_audit_log(out)
        admitted=[r for r in signed if r.get('stage')=='admitted']
        reported=[r for r in signed if r.get('stage')=='reported']
        assert len(admitted)==len(reported)==2
        assert {r['attempt']['attempt_id'] for r in admitted}=={r['attempt']['attempt_id'] for r in reported}
        events=runtime.events()
        attempts=[e for e in events if e['event']=='review_attempt']
        assert len(attempts)==2
        assert len([e for e in events if e['event']=='client_call_attempt'])==2
        assert sum(runtime._calls.values())==2
        passes={e['origin']['pass_id']:e for e in attempts}
        for row in admitted:
            pass_id=row['attempt']['beneficiaries'][0]
            assert row['attempt']['work_id']=='review:'+pass_id and pass_id in passes
            assert row['attempt']['beneficiaries']==[pass_id]
        assert all(r['tokens_in']==r['tokens_out']==3 for r in reported)
        assert bundle.client.reported_spend_usd>0 and not bundle.client.pending_usage_reservations
        assert not bundle.client._prepared_resource_reservations
        assessments=[e for e in events if e['event']=='review_assessment']
        assert len(assessments)==2
        assert sum(e['cost_usd'] for e in assessments)==pytest.approx(bundle.client.reported_spend_usd)
        if change=='healthy':
            row=load_entries(out,fresh=True)[-1]
            assert result.outcomes[0] is not prior and row.verdict=='suspicious'
            assert row.source_hash.startswith('bin:ctx1:')
            pass_id=row.review_claims['review']['origin']['pass_id']
            assert row.review_claims['review']['attempt_id']==passes[pass_id]['attempt_id']
            assert any(e['event']=='continuation_completed' and e['pass_id']==pass_id for e in events)
            assert result.total_cost_usd==pytest.approx(bundle.client.reported_spend_usd)
        else:
            assert result.outcomes[0] is prior and len(load_entries(out,fresh=True))==1
            assert not any(e['event']=='continuation_completed' for e in events)
            assert assessments[-1]['binary_module_unchanged_after_call'] is False
        assert not runtime._active
    finally:
        runtime.close('test_complete')


@pytest.mark.parametrize('change',['view','representation','extent'])
def test_view_change_during_paid_advisory_is_historical_only(binary_case,monkeypatch,change):
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    original_build=orch._build_context
    contexts=[]
    def build(*a,**k):
        ctx=original_build(*a,**k)
        contexts.append(ctx)
        return ctx
    monkeypatch.setattr(orch,'_build_context',build)
    def mutate():
        ctx=contexts[-1]
        if change=='view':
            ctx['source']='another supplied view'
        elif change=='representation':
            ctx['representation']='disassembly'
        else:
            ctx['metadata']['size']=64
    client.after=mutate
    run()
    assert len(client.prompts)==2 and result.outcomes[0] is prior
    paid=[e for e in runtime.events() if e['event']=='review_assessment']
    assert paid[-1]['binary_module_unchanged_after_call'] is True
    assert paid[-1]['binary_view_unchanged_after_call'] is False
    assert paid[-1]['cost_usd']==.1 and len(load_entries(cfg.out_dir,fresh=True))==1
    assert not runtime._active


def test_publication_cannot_borrow_another_binary_occurrences_context(binary_case):
    from core.audit.context import _defend_identifier
    from core.audit.continuation_context import context_spec,context_version
    from core.audit.disagreement_review_context import render_disagreement_context
    from core.audit.review_claims import merge_history
    from core.audit.tests.test_binary_review_availability import _reviewer
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    other_db=REDatabase(source_tool='ghidra',binary_path=str(target),functions=[
        REFunction(name='g',address=8192,size=32,source_tool='ghidra',decompilation='return another;')])
    other=assemble_binary_context(target_path=target,file_path=checklist['files'][0]['path'],function_name='g',db=other_db)
    other_review,_calls=_reviewer()
    runtime.wrap_review(other_review)(other,cfg)
    other['disagreement_override']={'resolution':'another occurrence advisory'}
    version=context_version(render_disagreement_context(other['disagreement_override'],defend_identifier=_defend_identifier))
    spec=context_spec(other,kind='disagreement',version=version)
    assert runtime.offer_context_delta(other,kind='disagreement',version=version)
    reservation=runtime.reserve_context_continuation(other,admission=lambda:True,required_context_id=spec['context_id'])
    assert reservation is not None and runtime.enrich_context(other,reservation)
    candidate=runtime.wrap_review(other_review)(other,cfg)
    assert runtime.publication_binary_scope(reservation,candidate) is not None
    run()
    assert result.outcomes[0] is not prior
    borrowed=replace(candidate,review_result={**candidate.review_result,'review_claims':merge_history(
        candidate.review_result['review_claims'],result.outcomes[0].review_result['review_claims'])})
    assert runtime.publication_binary_scope(reservation,borrowed) is None
    runtime.fail(reservation,'test_complete',ctx=other)



def test_initial_refused_view_does_not_become_owner_after_restore(tmp_path):
    from core.audit.tests.test_binary_paid_source_change import _runtime_binary_context
    from core.audit.knowledge_calls import KnowledgeCallRefused
    from core.audit.context import _defend_identifier
    from core.audit.continuation_context import context_version
    from core.audit.disagreement_review_context import render_disagreement_context
    target,ctx,runtime=_runtime_binary_context(tmp_path)
    original=ctx['source']
    state={'change':True}
    class Client:
        def generate_structured(self,*a,**k):
            if state['change']:
                ctx['source']='different supplied view'
            return StructuredResponse(result={'status':'clean','body':'Captured judgment'},raw='',cost=.1,model='captured')
    review=make_review_fn(Client(),escalate_clean=False)
    cfg=orch.OrchestratorConfig(target_path=target,out_dir=tmp_path/'out')
    try:
        with pytest.raises(KnowledgeCallRefused,match='binary_view_changed_or_unavailable'):
            runtime.wrap_review(review)(ctx,cfg)
        ctx['source']=original
        advisory={'resolution':'advisory independent reassessment'}
        ctx['disagreement_override']=advisory
        version=context_version(render_disagreement_context(advisory,defend_identifier=_defend_identifier))
        assert runtime.offer_context_delta(ctx,kind='disagreement',version=version) is False
        assert sum(runtime._calls.values())==1
        paid=[e for e in runtime.events() if e['event']=='review_assessment']
        assert len(paid)==1 and paid[0]['cost_usd']==.1
        state['change']=False
        ctx.pop('disagreement_override')
        runtime.wrap_review(review)(ctx,cfg)
        ctx['disagreement_override']=advisory
        assert runtime.offer_context_delta(ctx,kind='disagreement',version=version) is True
        assert sum(runtime._calls.values())==2
    finally:
        runtime.close('test_complete')


def test_omitted_actual_advisory_section_does_not_publish(binary_case,monkeypatch):
    from core.audit import llm_review
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    monkeypatch.setattr(llm_review,'_prompt_budget',lambda *a:1)
    run()
    assert len(client.prompts)==2 and result.outcomes[0] is prior
    assert 'Advisory mechanical disagreement' not in client.prompts[-1]
    assert len(load_entries(cfg.out_dir,fresh=True))==1
    assert result.total_cost_usd==pytest.approx(.2)
    assert not any(e['event']=='continuation_completed' for e in runtime.events())


def test_context_bound_binary_publication_requires_bounded_history(binary_case):
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    run()
    published=result.outcomes[0]
    assert published is not prior and published.binary_publication_scope is not None
    damaged=deepcopy(published.review_result)
    damaged['review_claims']['intakes']='not an intake list'
    candidate=replace(published,review_result=damaged)
    assert candidate.binary_publication_scope.matches(candidate,gap) is False
    assert Collector(out_dir=cfg.out_dir,target_path=target,run_id=cfg.out_dir.name).submit(candidate,gap) is None
    assert len(load_entries(cfg.out_dir,fresh=True))==2


def test_context_scope_losing_both_live_view_fields_cannot_publish(binary_case):
    target,original,db,cfg,runtime,client,result,prior,run,checklist,gap=binary_case
    run()
    published=result.outcomes[0]
    scope=replace(published.binary_publication_scope,view_context=None,view_identity=None)
    # The module and persisted binding still match: neither recreates the
    # original live implementation-view capability after a lossy copy.
    assert scope.module.current() and scope.record()==published.binary_publication_scope.record()
    candidate=replace(published,binary_publication_scope=scope)
    assert scope.current(target) is False
    assert Collector(out_dir=cfg.out_dir,target_path=target,run_id=cfg.out_dir.name).submit(candidate,gap) is None
    assert len(load_entries(cfg.out_dir,fresh=True))==2

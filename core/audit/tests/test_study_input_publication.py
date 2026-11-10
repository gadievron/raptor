"""Fresh input admission remains separate from portable historical reuse."""

from core.audit.collector import append_journal_for_outcome
from core.audit.orchestrator import ReviewOutcome
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.refutation_source import capture_source_identity
from core.audit.review_input_scope import CapturedReviewInput, ReviewInputScope
from core.audit.review_context_inputs import context_inputs_from_sources, context_inputs_record_digest
from core.audit.source_anchor import parse_context_source_anchor
from core.audit.gaps import _verify_entries_fold


def test_fresh_concern_with_conflicting_historical_input_is_recorded_without_reuse(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path/'xdg'))
    target=tmp_path/'target'; target.mkdir()
    (target/'a.c').write_text('int f(void) { return 0; }\n')
    (target/'types.h').write_text('typedef unsigned foo_t;\n')
    primary=capture_source_identity(target,'a.c')
    header=capture_source_identity(target,'types.h')
    manifest=context_inputs_from_sources([('target','a.c',primary.sha256),
        ('target','types.h',header.sha256),('target','types.h','a'*64)])
    assert manifest['complete'] is False
    history={'version':1,'role':'review-history-only','review':None,'intakes':[],
             'complete':False,'omissions':[],'source_inputs':manifest}
    origin=KnowledgeOrigin('pass','a.c','f',1,1,primary)
    scope=ReviewInputScope(origin,context_inputs_record_digest(manifest),
        (CapturedReviewInput('target',target,'a.c',primary),CapturedReviewInput('target',target,'types.h',header)))
    outcome=ReviewOutcome(file='a.c',function='f',status='suspicious',body='owned scripted concern',hypothesis='unresolved current concern',
        review_result={'review_claims':history},review_input_scope=scope)
    gap={'file':'a.c','function':'f','line_start':1,'line_end':1}
    entry=append_journal_for_outcome(out_dir=tmp_path/'out',target_path=target,run_id='control',outcome=outcome,gap=gap)
    assert entry is not None, 'portable history conflict must not discard a fresh concern'
    assert entry.verdict == 'suspicious'
    assert parse_context_source_anchor(entry.source_hash)[2] is None
    covered=set()
    _verify_entries_fold(covered,[entry],target_path=target,current_spans={'a.c:f':(1,1)},
        reuse_sink=None,current_strategies_fn=lambda *_:set(),current_model=None,source_label='control')
    assert not covered
    outcome.review_input_scope=None
    assert append_journal_for_outcome(out_dir=tmp_path/'without',target_path=target,run_id='control',outcome=outcome,gap=gap) is None


import pytest


@pytest.mark.parametrize('multi_model', [False, True])
def test_nonselected_study_delivery_contributes_inputs_without_selected_delivery_credit(tmp_path, monkeypatch, multi_model):
    from threading import Lock
    from core.audit.tests.test_knowledge_runtime import _source_study_case, _consume_source_case
    from core.audit.llm_review import make_review_fn
    from core.llm.providers import StructuredResponse

    case = _source_study_case(tmp_path)
    _consume_source_case(case)
    orch, config, _, runtime, _, _, _, _ = case
    reservation, = runtime.ready_continuations(admission=lambda: True, required_calls=2)
    ctx = {'file': 'owned.c', 'function': 'f', 'line_start': 2,
           'source': (tmp_path/'owned.c').read_text().splitlines()[1], 'language': 'c'}
    assert runtime.enrich_context(ctx, reservation)
    monkeypatch.setattr('core.audit.llm_review._prompt_budget',
                        lambda _ctx, system: 100 if system == 'small' else 100000)
    config.review_passes = 2
    config.multi_model = multi_model
    config.models = ['small', 'large']
    config.adversarial = False

    class Client:
        def __init__(self, large): self.large = large
        def generate_structured(self, prompt, schema, **kwargs):
            assert ('ownership is not established' in prompt) is self.large
            payload = {'status': 'clean' if self.large else 'suspicious', 'body': 'Scripted assessment'}
            if not self.large:
                payload['hypothesis'] = 'independent primary concern'
            return StructuredResponse(result=payload, raw='', cost=0, model='scripted')

    small = make_review_fn(Client(False), system_prompt='small', escalate_clean=False)
    large = make_review_fn(Client(True), system_prompt='large', escalate_clean=False)
    config.review_fns_by_model = {'small': small, 'large': large}
    lock, remaining = Lock(), [small, large]
    def sample(context, cfg):
        with lock: fn = remaining.pop(0)
        return fn(context, cfg)
    sample._knowledge_observed_client_contract = True
    outcome = orch._multi_pass_review(runtime.wrap_review(sample), ctx, config, 2, knowledge_runtime=runtime)
    assert outcome.review_result['source_study_delivery'][0]['delivered'] is False
    manifest = outcome.review_result['review_claims']['source_inputs']
    assert {row['file'] for row in manifest['sources']} == {'owned.c', 'types.h'}
    # All study dispatch inputs, including material not cited by the answer,
    # remain live publication obligations of the combined assessment.
    scope = outcome.review_input_scope
    assert scope is not None and scope.current(tmp_path)
    assert {source.file for source in scope.inputs} == {'owned.c', 'types.h'}
    (tmp_path/'types.h').write_text('typedef struct { unsigned changed; } foo_t;\n')
    assert not scope.current(tmp_path)
    runtime.close()


from dataclasses import replace
from core.audit.tests.test_study_input_bindings import _job, _response, DECLARATION
from core.concepts.model import StudyItem


def test_exported_study_inputs_keep_original_uncited_stamps_without_recapture(tmp_path, monkeypatch):
    (tmp_path/'types.h').write_text(DECLARATION+'\n')
    context_source='struct related { unsigned flags; };'
    (tmp_path/'context.h').write_text(context_source+'\n')
    bindings, subjects, item = _job(tmp_path)
    context=StudyItem('related','struct','related','context.h',line=1,definition=context_source)
    packet=subjects.prepare([item],[context])
    subjects.record(packet,_response())
    answer=subjects.snapshot()[0]
    assert len(answer.materials)==1 and len(answer.inputs)==2
    before=bindings.snapshot_inputs(answer.inputs)
    assert {source.file for source in before}=={'types.h','context.h'}
    (tmp_path/'context.h').write_text(context_source+'\n/* later physical version */\n')
    def forbidden_capture(*a, **k): raise AssertionError('snapshot export refreshed an original input')
    monkeypatch.setattr('core.audit.study_inputs.capture_source_identity', forbidden_capture)
    assert bindings.snapshot_inputs(answer.inputs)==before
    substituted=replace(answer.inputs[0], text='unbound replacement')
    assert bindings.snapshot_inputs((substituted,)) is None
    assert bindings.snapshot_inputs((replace(answer.inputs[0],binding_id='unknown'),)) is None

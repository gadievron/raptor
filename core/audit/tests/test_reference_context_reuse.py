"""Delivered reference contents constrain durable coverage and reuse."""

import pytest
from dataclasses import replace

from core.audit.tests.test_knowledge_runtime_coordinator import _runtime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig
from core.audit.collector import append_journal_for_outcome
from core.audit.gaps import _verify_entries_fold
from core.llm.providers import StructuredResponse


@pytest.mark.parametrize("change", ["version", "rule", "conditions", "unrelated"])
@pytest.mark.parametrize("reuse", [False, True])
def test_changed_delivered_reference_requires_fresh_review(tmp_path, monkeypatch, change, reuse):
    monkeypatch.setenv('XDG_DATA_HOME',str(tmp_path/'xdg'))
    runtime,ctx=_runtime(tmp_path)
    reservation,=runtime.ready_continuations(admission=lambda:True)
    assert runtime.enrich_context(ctx,reservation)
    answers=ctx['language_reference_answers']
    supplied={entry.entry_id for answer in answers for entry in answer.entries}
    assert supplied
    class Client:
        def generate_structured(self,prompt,schema,**kwargs):
            assert 'Language reference (context, not proof)' in prompt
            return StructuredResponse(result={'status':'clean','body':'Owned scripted assessment'},raw='',cost=0,model='scripted')
    config=OrchestratorConfig(target_path=tmp_path,out_dir=tmp_path/'out')
    outcome=runtime.wrap_review(make_review_fn(Client(),escalate_clean=False))(ctx,config)
    assert all(row['delivered'] for row in outcome.review_result['language_reference_delivery'])
    entry=append_journal_for_outcome(out_dir=config.out_dir,target_path=tmp_path,run_id='owned',outcome=outcome,
        gap={'file':'unit.c','function':'f','line_start':1,'line_end':1})
    assert entry is not None
    def covered_now():
        covered=set(); sink={} if reuse else None
        _verify_entries_fold(covered,[entry],target_path=tmp_path,current_spans={'unit.c:f':(1,1)},reuse_sink=sink,
            current_strategies_fn=lambda *_:set(),current_model=None,source_label='reference-control')
        if reuse:
            assert bool(sink) == bool(covered)
        return covered
    assert covered_now()=={'unit.c:f'}
    from core.language_reference import c_integer
    from core.audit.source_anchor import context_source_anchor_version
    assert context_source_anchor_version(entry.source_hash) == 3
    assert entry.review_claims['reference_inputs']['complete'] is True
    def update(item):
        if change == 'unrelated':
            return replace(item, rule=item.rule+' Unrelated clarification.') if item.entry_id not in supplied else item
        if item.entry_id not in supplied:
            return item
        if change == 'version': return replace(item, version=item.version+1)
        if change == 'conditions': return replace(item, conditions=(*item.conditions,'Reviewed additional condition.'))
        return replace(item, rule=item.rule+' Updated reviewed clarification.')
    monkeypatch.setattr(c_integer,'ENTRIES',tuple(update(item) for item in c_integer.ENTRIES))
    if change == 'unrelated':
        assert covered_now()=={'unit.c:f'}, 'unrelated reference entries must not force a new review'
    else:
        assert not covered_now(),'changed delivered reference content still credits the old assessment'
    runtime.close()


def test_reference_change_during_source_admission_rechecks_the_full_set(tmp_path, monkeypatch):
    from core.audit import review_context_inputs
    from core.audit.gaps import _review_context_current
    from core.audit.reference_inputs import reference_inputs_from_delivery
    from core.audit.knowledge_context import reference_delivery, reference_sections
    from core.audit.review_context_inputs import context_inputs_from_sources
    from core.audit.refutation_source import capture_source_identity
    from core.audit.reference_inputs import review_context_digest
    from core.audit.source_anchor import make_context_source_anchor
    from core.coverage.journal import ReviewJournalEntry
    from core.language_reference import c_integer, lookup, ReferenceContext
    from core.staleness import hash_span

    path=tmp_path/'unit.c';path.write_text('int f(void) { return 0; }\n')
    answer=lookup('r','',ReferenceContext('c'),entry_id='c.integer-promotion')
    reference=reference_inputs_from_delivery(reference_delivery((answer,),reference_sections((answer,))),(answer,))
    identity=capture_source_identity(tmp_path,'unit.c')
    sources=context_inputs_from_sources([('target','unit.c',identity.sha256)])
    history={'source_inputs':sources,'reference_inputs':reference}
    anchor=make_context_source_anchor(identity.sha256,hash_span(path,1,1),review_context_digest(sources,reference),context_version=3)
    entry=ReviewJournalEntry(ts='2026-11-10T00:00:00Z',run_id='owned',file='unit.c',function='f',
        verdict='clean',source_hash=anchor,line_start=1,line_end=1,review_claims=history)
    assert _review_context_current(entry,tmp_path)
    capture=review_context_inputs.capture_source_identity
    changed=[]
    def mutate_from_source_reader(*args,**kwargs):
        if not changed:
            changed.append(True)
            monkeypatch.setattr(c_integer,'ENTRIES',tuple(replace(item,rule=item.rule+' Updated.')
                if item.entry_id=='c.integer-promotion' else item for item in c_integer.ENTRIES))
        return capture(*args,**kwargs)
    monkeypatch.setattr(review_context_inputs,'capture_source_identity',mutate_from_source_reader)
    assert not _review_context_current(entry,tmp_path)
    assert changed


def _journaled_reference(root, monkeypatch, *, status='clean'):
    monkeypatch.setenv('XDG_DATA_HOME', str(root/'xdg'))
    runtime, ctx = _runtime(root)
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert runtime.enrich_context(ctx, reservation)
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            assert 'Language reference (context, not proof)' in prompt
            payload = {'status': status, 'body': 'Owned scripted reference assessment'}
            if status == 'suspicious': payload['hypothesis'] = 'Unresolved current source concern'
            return StructuredResponse(result=payload, raw='', cost=0, model='scripted')
    config = OrchestratorConfig(target_path=root, out_dir=root/'out')
    outcome = runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))(ctx, config)
    gap = {'file': 'unit.c', 'function': 'f', 'line_start': 1, 'line_end': 1}
    return runtime, outcome, gap


def test_fresh_concern_with_older_reference_is_recorded_without_reuse(tmp_path, monkeypatch):
    from core.audit.source_anchor import parse_context_source_anchor
    from core.audit.verdict_reuse import outcome_from_entry
    from core.language_reference import c_integer
    runtime, outcome, gap = _journaled_reference(tmp_path, monkeypatch, status='suspicious')
    used = {row['id'] for row in outcome.review_result['review_claims']['reference_inputs']['entries']}
    monkeypatch.setattr(c_integer, 'ENTRIES', tuple(replace(item, rule=item.rule+' Revised condition.')
        if item.entry_id in used else item for item in c_integer.ENTRIES))
    entry = append_journal_for_outcome(out_dir=tmp_path/'out', target_path=tmp_path,
                                      run_id='fresh', outcome=outcome, gap=gap)
    assert entry is not None and entry.verdict == 'suspicious'
    assert parse_context_source_anchor(entry.source_hash)[2] is None
    covered = set()
    _verify_entries_fold(covered, [entry], target_path=tmp_path, current_spans={'unit.c:f': (1, 1)},
        reuse_sink=None, current_strategies_fn=lambda *_: set(), current_model=None, source_label='owned')
    assert not covered
    reconstructed = outcome_from_entry(entry)
    assert reconstructed.review_input_scope is None
    assert append_journal_for_outcome(out_dir=tmp_path/'cold', target_path=tmp_path,
                                     run_id='cold', outcome=reconstructed, gap=gap) is None
    runtime.close()


def test_reference_dependencies_survive_history_transforms_and_require_their_tag(tmp_path, monkeypatch):
    from copy import deepcopy
    from core.audit.review_claims import merge_history, panel_context_history, record_intake
    from core.audit.gaps import _review_context_current
    from core.audit.review_context_inputs import context_inputs_digest
    from core.audit.source_anchor import make_context_source_anchor, parse_context_source_anchor
    runtime, outcome, gap = _journaled_reference(tmp_path, monkeypatch)
    entry = append_journal_for_outcome(out_dir=tmp_path/'out', target_path=tmp_path,
                                      run_id='fresh', outcome=outcome, gap=gap)
    assert entry is not None and _review_context_current(entry, tmp_path)
    history = entry.review_claims
    references = history['reference_inputs']
    assert record_intake(history, [])['reference_inputs'] == references
    assert merge_history(history, None)['reference_inputs'] == references
    assert panel_context_history(None, [{'review_claims': history}])['reference_inputs'] == references
    for field in ('source_inputs', 'reference_inputs'):
        changed = deepcopy(history); changed.pop(field)
        assert not _review_context_current(replace(entry, review_claims=changed), tmp_path)
    primary, span, _ = parse_context_source_anchor(entry.source_hash)
    old = make_context_source_anchor(primary, span, context_inputs_digest(history['source_inputs']), context_version=2)
    assert not _review_context_current(replace(entry, source_hash=old), tmp_path)
    runtime.close()


@pytest.mark.parametrize('multi_model', [False, True])
def test_nonselected_reference_delivery_contributes_only_its_dependencies(tmp_path, monkeypatch, multi_model):
    from threading import Lock
    from core.audit import orchestrator as orch
    runtime, ctx = _runtime(tmp_path)
    reservation, = runtime.ready_continuations(admission=lambda: True, required_calls=2)
    assert runtime.enrich_context(ctx, reservation)
    monkeypatch.setattr('core.audit.llm_review._prompt_budget',
                        lambda _ctx, system: 100 if system == 'small' else 100000)
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path/'out', review_passes=2,
                                multi_model=multi_model, models=['small', 'large'], adversarial=False)
    class Client:
        def __init__(self, large): self.large = large
        def generate_structured(self, prompt, schema, **kwargs):
            assert ('Language reference (context, not proof)' in prompt) is self.large
            payload = {'status': 'clean' if self.large else 'suspicious', 'body': 'Scripted panel assessment'}
            if not self.large: payload['hypothesis'] = 'Independent primary concern'
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
    assert outcome.review_result['language_reference_delivery'][0]['delivered'] is False
    history = outcome.review_result['review_claims']
    assert history['reference_inputs']['complete'] and history['reference_inputs']['entries']
    assert history['source_inputs']['version'] == 2
    assert outcome.review_input_scope is not None and outcome.review_input_scope.current(tmp_path)
    entry = append_journal_for_outcome(out_dir=config.out_dir, target_path=tmp_path, run_id='panel',
                                      outcome=outcome, gap={'line_start': 1, 'line_end': 1})
    assert entry is not None and entry.source_hash.startswith('src:ctx3:')
    runtime.close()


def test_known_reference_tag_is_rechecked_before_append(tmp_path, monkeypatch):
    from core.audit import collector
    from core.language_reference import c_integer
    runtime, outcome, gap = _journaled_reference(tmp_path, monkeypatch)
    used = {row['id'] for row in outcome.review_result['review_claims']['reference_inputs']['entries']}
    constructor = collector.ReviewJournalEntry
    changed = []
    def change_after_tag_creation(*args, **kwargs):
        assert kwargs['source_hash'].startswith('src:ctx3:')
        assert not kwargs['source_hash'].endswith(':unknown')
        entry = constructor(*args, **kwargs)
        monkeypatch.setattr(c_integer, 'ENTRIES', tuple(replace(item, rule=item.rule+' New rule revision.')
            if item.entry_id in used else item for item in c_integer.ENTRIES))
        changed.append(True)
        return entry
    monkeypatch.setattr(collector, 'ReviewJournalEntry', change_after_tag_creation)
    assert append_journal_for_outcome(out_dir=tmp_path/'out', target_path=tmp_path,
                                     run_id='barrier', outcome=outcome, gap=gap) is None
    assert changed
    runtime.close()

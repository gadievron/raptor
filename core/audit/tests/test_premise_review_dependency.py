"""Caller-premise review dependencies are never source-study subjects."""
import json

import pytest

from core.audit import orchestrator as orch
from core.audit.collector import append_journal_for_outcome
from core.concepts.reading_list import ReadingList, ReadingListItem
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.fixture(autouse=True)
def owned_shutdown():
    with isolated_audit_shutdown(orch):
        yield


def case(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'a.c').write_text('int f(int n) { return n + 1; }\n')
    out = tmp_path / 'out'
    out.mkdir()
    h = {'mechanism': 'selected concern', 'confidence': 'refuted',
         'counter': 'the caller validates the bound', 'counter_scope': 'cross_function'}
    outcome = orch.ReviewOutcome(file='a.c', function='f', line=1, status='suspicious',
                                body='[gate violation: original] review body',
                                hypothesis=h['mechanism'], hypotheses=[h],
                                review_result={'hypothesis': h['mechanism']})
    return orch.OrchestratorConfig(target_path=target, out_dir=out), outcome, h


def test_premise_requires_review_without_queueing_source_study(tmp_path):
    config, outcome, h = case(tmp_path)
    original_prefix = outcome.body
    orch._record_unresolved_review_premise(config, outcome, h)
    assert not (config.out_dir / 'reading-list.json').exists()
    assert outcome.body.startswith(original_prefix)
    assert 'needs review' in outcome.body
    assert h['counter'] in outcome.body
    assert outcome.status == 'suspicious' and not outcome.evidence_tool
    events = [json.loads(line) for line in
              (config.out_dir / '.audit-log.jsonl').read_text().splitlines()]
    event = next(e for e in events if e.get('action') == 'review_premise_unresolved')
    assert event['adjudication'] == 'unverified'
    assert event['hypothesis'] == h['mechanism'] and event['reason'] == h['counter']
    entry = append_journal_for_outcome(out_dir=config.out_dir, target_path=config.target_path,
        run_id=config.out_dir.name, outcome=outcome,
        gap={'name': 'f', 'file': 'a.c', 'line_start': 1, 'line_end': 1})
    assert entry is not None and 'needs review' in entry.body
    assert entry.hypotheses[0]['counter'] == h['counter']


def test_resume_retires_generated_premise_but_keeps_real_subject(tmp_path):
    config, _outcome, _h = case(tmp_path)
    path = config.out_dir / 'reading-list.json'
    legacy = ReadingListItem(id='premise-old', source_command='/audit', source_file='a.c',
                             source_function='f', question='Does this hold: the caller validates the bound (refutation premise for f)?')
    legitimate = ReadingListItem(id='subject-owned', source_command='/audit', source_file='a.c',
                                source_function='f', question='foo_t')
    ReadingList(items=[legacy, legitimate]).save(path)
    queue = orch.StudyQueue()
    assert orch._requeue_pending_study(config, queue) == 1
    batch = queue.dequeue_batch(max_items=10, timeout=0)
    assert [request.question for request in batch] == ['foo_t']
    saved = ReadingList.load(path)
    archived = next(item for item in saved.items if item.id == 'premise-old')
    assert archived.unresolvable and not archived.resolved
    assert 'review' in archived.unresolvable_reason
    assert archived.question == legacy.question
    assert not next(item for item in saved.items if item.id == 'subject-owned').unresolvable


@pytest.mark.parametrize('later_finding', [False, True])
def test_review_need_survives_held_and_later_selected_outcomes(tmp_path, monkeypatch, later_finding):
    from core.audit.smt_promotion_gate import CallerGateDecision

    config, outcome, blocked = case(tmp_path)
    first = {'mechanism': 'first local concern', 'confidence': 'refuted', 'counter_scope': 'local'}
    last = {'mechanism': 'later local concern', 'confidence': 'refuted', 'counter_scope': 'local'}
    outcome.status = 'clean'
    outcome.hypotheses = [first, blocked] + ([last] if later_finding else [])
    result = orch.OrchestratorResult(outcomes=[outcome], clean=1)
    monkeypatch.setattr(orch, '_mechanism_specificity', lambda _: 0)
    monkeypatch.setattr('core.audit.cwe_dispatch.smt_verb_for_cwe', lambda _: None)
    monkeypatch.setattr(orch, '_hypothesis_to_smt_verb', lambda _: 'check-overflow')
    monkeypatch.setattr(orch, '_guard_blocks_promotion', lambda *args, **kwargs: None)
    monkeypatch.setattr(orch, '_run_tool_chain', lambda *args, **kwargs: ['smt:check-overflow'])
    hold = CallerGateDecision('hold', 'first caller condition unresolved', channel_outcome='inconclusive')
    monkeypatch.setattr(orch, '_smt_caller_gate_decision',
                        lambda config, candidate, verb, mechanism, *args, **kwargs:
                        hold if mechanism == first['mechanism'] else None)
    orch._promote_clean_refuted(result, config)
    published = result.outcomes[0]
    assert published.status == ('finding' if later_finding else 'suspicious')
    assert published.hypothesis == (last['mechanism'] if later_finding else first['mechanism'])
    assert '[needs review]' in published.body and blocked['counter'] in published.body
    assert published.evidence_tool == 'clean-refuted:smt:check-overflow'
    assert not (config.out_dir / 'reading-list.json').exists()
    entry = append_journal_for_outcome(out_dir=config.out_dir, target_path=config.target_path,
        run_id=config.out_dir.name, outcome=published,
        gap={'name': 'f', 'file': 'a.c', 'line_start': 1, 'line_end': 1})
    assert entry is not None and blocked['counter'] in entry.body

"""Self-refutation rescue keeps receipts on their selected claim."""

import json
from copy import deepcopy

import pytest

from core.audit import orchestrator as orch
from core.audit.collector import append_journal_for_outcome
from core.audit.findings_export import build_graded_finding, export_graded_from_journal
from core.audit.smt_promotion_gate import CallerGateDecision
from core.testing.audit_shutdown import isolated_audit_shutdown

SELECTED = 'selected arithmetic concern'
OLD = 'unrelated earlier concern'


@pytest.fixture(autouse=True)
def owned_shutdown():
    with isolated_audit_shutdown(orch):
        yield


def case(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'source.c').write_text('int f(int n) {\n    return n + 1;\n}\n')
    out = tmp_path / 'out'
    out.mkdir()
    hypotheses = [
        {'mechanism': OLD, 'confidence': 'high', 'cwe': 'CWE-252'},
        {'mechanism': SELECTED, 'confidence': 'refuted', 'cwe': 'CWE-190'},
    ]
    outcome = orch.ReviewOutcome(file='source.c', function='f', line=1, status='clean', body='Original review',
        hypothesis=OLD, hypotheses=hypotheses, review_result={
            'hypothesis': OLD, 'hypotheses': deepcopy(hypotheses), 'cwe': 'CWE-252', 'cwe_class': 'CWE-252',
        })
    result = orch.OrchestratorResult(outcomes=[outcome], clean=1)
    config = orch.OrchestratorConfig(target_path=target, out_dir=out)
    checklist = {'files': [{'path': 'source.c', 'items': [
        {'name': 'f', 'line_start': 1, 'line_end': 3},
    ]}]}
    return outcome, result, config, checklist


def patch_channel(monkeypatch, lane):
    calls = []
    monkeypatch.setattr('core.audit.cwe_dispatch.smt_verb_for_cwe', lambda _: None if lane == 'cheap' else 'check-overflow')
    monkeypatch.setattr(orch, '_hypothesis_to_smt_verb', lambda _: None if lane == 'cheap' else 'check-overflow')
    monkeypatch.setattr(orch, '_hypothesis_to_tool_chain', lambda *a, **kw: [{'type': 'semgrep'}])
    monkeypatch.setattr(orch, '_guard_blocks_promotion', lambda *a, **kw: None)
    gate = CallerGateDecision('hold', 'fixture caller condition unresolved', channel_outcome='inconclusive')
    monkeypatch.setattr(orch, '_smt_caller_gate_decision', lambda *a, **kw: gate if lane == 'hold' else None)

    def check(chain, **kwargs):
        calls.append(kwargs)
        # Injected channel result; tests bind its claim, not native correctness.
        return ['semgrep:explicit-error-discard'] if lane == 'cheap' else ['smt:check-overflow']

    monkeypatch.setattr(orch, '_run_tool_chain', check)
    return calls


@pytest.mark.parametrize('lane', ['finding', 'hold', 'cheap'])
def test_rescued_claim_survives_live_and_journal_export(tmp_path, monkeypatch, lane):
    original, result, config, checklist = case(tmp_path)
    before = deepcopy(original.review_result)
    hypotheses_before = deepcopy(original.hypotheses)
    calls = patch_channel(monkeypatch, lane)
    orch._promote_clean_refuted(result, config, checklist=checklist)
    selected = result.outcomes[0]
    assert calls and calls[0]['hypothesis'] == SELECTED
    assert calls[0]['cwe'] == 'CWE-190'
    assert selected.hypothesis == selected.review_result['hypothesis'] == SELECTED
    assert selected.review_result['cwe'] == selected.review_result['cwe_class'] == 'CWE-190'
    assert selected.hypotheses[0]['mechanism'] == SELECTED
    assert sorted(h['mechanism'] for h in selected.hypotheses) == sorted(h['mechanism'] for h in hypotheses_before)
    assert original.hypothesis == OLD and original.review_result == before
    assert original.hypotheses == hypotheses_before
    assert build_graded_finding(selected)['hypothesis'] == SELECTED
    entry = append_journal_for_outcome(out_dir=config.out_dir, target_path=config.target_path,
        run_id=config.out_dir.name, outcome=selected, gap={'name': 'f', 'file': 'source.c', 'line_start': 1, 'line_end': 3})
    assert entry is not None
    assert entry.cwe == 'CWE-190' and entry.hypotheses[0]['mechanism'] == SELECTED
    exported = export_graded_from_journal(config.out_dir)
    assert exported is not None
    assert exported['findings'][0]['hypothesis'] == SELECTED


def test_same_label_later_discovery_keeps_held_claim_receipt(tmp_path, monkeypatch):
    original, result, config, checklist = case(tmp_path)
    original.hypotheses = [
        {'mechanism': SELECTED, 'confidence': 'refuted', 'cwe': 'CWE-252'},
        {'mechanism': SELECTED, 'confidence': 'refuted', 'cwe': 'CWE-190'},
    ]
    original.review_result['hypotheses'] = deepcopy(original.hypotheses)
    patch_channel(monkeypatch, 'hold')
    monkeypatch.setattr('core.audit.cwe_dispatch.smt_verb_for_cwe',
                        lambda cwe: 'check-overflow' if cwe == 'CWE-252' else None)
    monkeypatch.setattr(orch, '_hypothesis_to_smt_verb', lambda _: None)
    monkeypatch.setattr(orch, '_run_tool_chain', lambda chain, **kwargs:
                        ['smt:check-overflow'] if chain[0]['type'] == 'smt'
                        else ['semgrep:explicit-error-discard'])
    orch._promote_clean_refuted(result, config, checklist=checklist)
    held = result.outcomes[0]
    assert held.status == 'suspicious'
    assert held.evidence_tool == 'clean-refuted:smt:check-overflow'
    assert held.review_result['cwe'] == 'CWE-252'
    assert held.hypotheses[0]['cwe'] == 'CWE-252'
    events = [json.loads(line) for line in
              (config.out_dir / '.audit-log.jsonl').read_text().splitlines()]
    discovery = next(e for e in events if e.get('action') == 'refuted_hypothesis_confirmed')
    assert discovery['hypothesis'] == SELECTED
    assert discovery['cwe'] == 'CWE-190'
    assert discovery['evidence_tool'] == 'semgrep:explicit-error-discard'
    assert result.clean == 0 and result.suspicious == 1 and result.refuted_rescued == 1

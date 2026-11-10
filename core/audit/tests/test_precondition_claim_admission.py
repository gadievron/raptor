"""Precondition checks must retain their admitted claim and request."""
from copy import deepcopy

import pytest

from core.audit import orchestrator as orch
from core.audit.precondition_check import CheckResult, PreconditionVerdict
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
    hypothesis = {'mechanism': 'selected concern', 'cwe': 'CWE-190',
                  'counter': 'the local check bounds the value', 'counter_scope': 'local'}
    checks = [{'check_type': 'function_reaches_sink', 'assumption': 'sink is reachable',
               'location': {'file': 'a.c', 'function': 'f'}}]
    outcome = orch.ReviewOutcome(
        file='a.c', function='f', line=1, status='suspicious', body='review',
        hypothesis=hypothesis['mechanism'], hypotheses=[hypothesis],
        review_result={'hypothesis': hypothesis['mechanism'], 'hypotheses': [deepcopy(hypothesis)],
                       'cwe': 'CWE-190', 'preconditions': checks},
    )
    return outcome, orch.OrchestratorResult(outcomes=[outcome], suspicious=1), orch.OrchestratorConfig(
        target_path=target, out_dir=out,
    )


def supported():
    return PreconditionVerdict(checks=[CheckResult(
        check_type='function_reaches_sink', assumption='sink is reachable',
        verdict='supported', evidence='injected structural observation', grade='structural',
    )])


def test_ambiguous_material_never_dispatches_preconditions(tmp_path, monkeypatch):
    outcome, result, config = case(tmp_path)
    other = deepcopy(outcome.hypotheses[0])
    other['counter'] = 'a different local check bounds the value'
    outcome.hypotheses.append(other)
    calls = []
    monkeypatch.setattr('core.audit.precondition_check.verify_preconditions',
                        lambda *args, **kwargs: calls.append(args) or supported())
    orch._promote_suspicious_preconditions(result, config)
    assert calls == []
    assert result.outcomes[0].status == 'suspicious'
    assert result.precondition_promoted == 0


@pytest.mark.parametrize('revision', ['erase', 'material', 'primary', 'request', 'default-cwe', 'simultaneous', 'review-copy', 'stable'])
def test_precondition_receipt_stays_on_admitted_input(tmp_path, monkeypatch, revision):
    outcome, result, config = case(tmp_path)
    if revision == 'default-cwe':
        for row in (outcome.hypotheses[0], outcome.review_result['hypotheses'][0]):
            row.pop('cwe')
    calls = []

    def verify(*args, **kwargs):
        calls.append(args)
        if revision == 'erase':
            outcome.hypotheses.clear()
            outcome.review_result['hypotheses'].clear()
        elif revision == 'material':
            for row in (outcome.hypotheses[0], outcome.review_result['hypotheses'][0]):
                row['counter'] = 'a revised local check bounds the value'
        elif revision == 'primary':
            outcome.hypothesis = outcome.review_result['hypothesis'] = 'replacement concern'
        elif revision == 'default-cwe':
            outcome.review_result['cwe'] = 'CWE-252'
        elif revision == 'review-copy':
            outcome.review_result = deepcopy(outcome.review_result)
        elif revision == 'simultaneous':
            args[0][0]['location']['function'] = 'other'
            outcome.review_result['preconditions'][0]['location']['function'] = 'other'
        elif revision == 'request':
            outcome.review_result['preconditions'][0]['location']['function'] = 'other'
        return supported()

    monkeypatch.setattr('core.audit.precondition_check.verify_preconditions', verify)
    orch._promote_suspicious_preconditions(result, config)
    assert len(calls) == 1
    admitted = revision in ('stable', 'review-copy')
    assert result.outcomes[0].status == ('finding' if admitted else 'suspicious')
    assert result.precondition_promoted == (1 if admitted else 0)
    assert 'precondition_verification' in result.outcomes[0].review_result


@pytest.mark.parametrize('loss', ['truncated', 'malformed', 'missing-result'])
def test_supported_subset_cannot_stand_for_all_obligations(tmp_path, monkeypatch, loss):
    outcome, result, config = case(tmp_path)
    first = outcome.review_result['preconditions'][0]
    if loss == 'truncated':
        outcome.review_result['preconditions'] = [deepcopy(first) for _ in
                                                  range(orch._MAX_PRECONDITION_CHECKS_PER_FN + 1)]
    elif loss == 'malformed':
        outcome.review_result['preconditions'].append('not a check record')
    else:
        outcome.review_result['preconditions'].append(deepcopy(first))
    calls = []

    def verify(preconditions, **kwargs):
        calls.append(deepcopy(preconditions))
        count = 1 if loss == 'missing-result' else len(preconditions)
        return PreconditionVerdict(checks=[supported().checks[0] for _ in range(count)])

    monkeypatch.setattr('core.audit.precondition_check.verify_preconditions', verify)
    orch._promote_suspicious_preconditions(result, config)
    assert calls and len(calls[0]) <= orch._MAX_PRECONDITION_CHECKS_PER_FN
    assert result.outcomes[0].status == 'suspicious'
    assert result.precondition_promoted == 0
    assert outcome.review_result['precondition_verification']['all_supported'] is True
    assert outcome.review_result['claim_material_deferred']['reason'] == 'incomplete-precondition-verification'


@pytest.mark.parametrize('field', ['scalar', 'review'])
def test_disagreeing_primary_fields_never_dispatch(tmp_path, monkeypatch, field):
    outcome, result, config = case(tmp_path)
    if field == 'scalar':
        outcome.hypothesis = 'different concern'
    else:
        outcome.review_result['hypothesis'] = 'different concern'
    calls = []
    monkeypatch.setattr('core.audit.precondition_check.verify_preconditions',
                        lambda *args, **kwargs: calls.append(args) or supported())
    orch._promote_suspicious_preconditions(result, config)
    assert calls == []
    assert result.outcomes[0].status == 'suspicious'

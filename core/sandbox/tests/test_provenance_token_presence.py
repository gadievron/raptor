"""A malformed present provenance token is distinct from an old unstamped artifact."""
import copy
import json

import pytest

from core.sandbox import telemetry_mac as mac, triage, triage_deep as deep
from core.testing.state_isolation import pin_user_state_dirs


BAD_TOKENS = [None, '', False, 0, 0.0, [], {}]
BAD_IDS = ['null', 'empty', 'false', 'integer-zero', 'float-zero', 'array', 'object']
KINDS = ['summary', 'degraded', 'triage', 'deep']


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))


def artifact(kind):
    if kind == 'summary':
        return {'total_denials': 0, 'by_type': {}, 'denials': []}
    if kind == 'degraded':
        return {'audit_requested': True, 'audit_engaged': False, 'degraded': True,
                'reason': 'owned prerequisite unavailable', 'instructions': 'owned remedy'}
    if kind == 'triage':
        return {'verdict': 'clean', 'signals': [], 'inputs': {}, 'caveats': []}
    return {'rules_verdict': 'clean', 'assessments': [], 'overall_note': 'owned note',
            'model': 'owned model', 'rules_verdict_immutable': True}


def verify(kind, value, run, *, allow_legacy=True):
    binding = mac.run_binding(run)
    if kind == 'summary':
        return triage._verify_summary(value, binding, allow_legacy=allow_legacy)[1]
    if kind == 'degraded':
        return triage._verify_audit_degraded(value, binding, allow_legacy=allow_legacy)[1]
    if kind == 'triage':
        return triage.verify_triage_report(value, run)
    return deep.verify_deep_report(value, run)


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('token', BAD_TOKENS, ids=BAD_IDS)
def test_present_invalid_tokens_are_not_legacy(tmp_path, kind, token):
    path = tmp_path / 'owned.json'
    path.write_text(json.dumps({**artifact(kind), 'mac': token}))
    original = path.read_bytes()
    value = json.loads(original)
    before = copy.deepcopy(value)
    assert verify(kind, value, tmp_path) == 'tampered'
    assert value == before
    assert path.read_bytes() == original


@pytest.mark.parametrize('kind', ['summary', 'degraded'])
@pytest.mark.parametrize('token', BAD_TOKENS, ids=BAD_IDS)
def test_current_run_rejection_is_preserved(tmp_path, kind, token):
    value = {**artifact(kind), 'mac': token}
    assert verify(kind, value, tmp_path, allow_legacy=False) == 'tampered'


@pytest.mark.parametrize('kind', KINDS)
def test_genuinely_unstamped_artifacts_remain_legacy(tmp_path, kind):
    assert verify(kind, artifact(kind), tmp_path) == 'legacy'


@pytest.mark.parametrize('kind', KINDS)
def test_nonempty_invalid_tokens_remain_tampered(tmp_path, kind):
    assert verify(kind, {**artifact(kind), 'mac': 'invalid'}, tmp_path) == 'tampered'


@pytest.mark.parametrize('token', BAD_TOKENS, ids=BAD_IDS)
def test_deep_legacy_opt_in_does_not_accept_malformed_present_tokens(tmp_path, monkeypatch, token):
    from core.llm import factory

    def unexpected_client():
        pytest.fail('malformed provenance must be refused before client acquisition')
    monkeypatch.setattr(factory, 'get_client', unexpected_client)
    # A future signal type is still usable for advisory grounding; this test
    # concerns report provenance, without constructing target activity.
    value = {**artifact('triage'), 'signals': [{'type': 'owned-signal'}], 'mac': token}
    path = tmp_path / triage.TRIAGE_FILE
    path.write_text(json.dumps(value))
    original = path.read_bytes()
    assert deep.deep_analyse(tmp_path, allow_legacy=True) is None
    assert path.read_bytes() == original
    assert not (tmp_path / deep.DEEP_FILE).exists()

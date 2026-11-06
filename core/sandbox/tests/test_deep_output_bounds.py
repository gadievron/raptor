"""Advisory output keeps probability types honest and escapes bounded prefixes."""
import json

import pytest

from core.sandbox import triage, triage_deep as deep
from core.sandbox.tests.test_triage_deep import _FakeClient
from core.testing.state_isolation import pin_user_state_dirs


REPORT = {'signals': [{'type': 'volume_anomaly'}]}


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))


def reply(confidence=0.75, rationale='owned', overall_note='owned'):
    return json.dumps({'assessments': [{
        'signal_type': 'volume_anomaly', 'judgement': 'unclear',
        'confidence': confidence, 'rationale': rationale,
    }], 'overall_note': overall_note})


@pytest.mark.parametrize('value,expected', [
    pytest.param(True, 0.0, id='boolean-true'),
    pytest.param(False, 0.0, id='boolean-false'),
    pytest.param(0, 0.0, id='integer-zero'),
    pytest.param(1, 1.0, id='integer-one'),
    pytest.param(0.75, 0.75, id='fraction'),
    pytest.param('0.75', 0.75, id='numeric-string'),
    pytest.param(None, 0.0, id='null'),
    pytest.param([], 0.0, id='array'),
    pytest.param({}, 0.0, id='object'),
    pytest.param(float('nan'), 0.0, id='nan'),
    pytest.param(float('inf'), 0.0, id='infinity'),
    pytest.param(-2, 0.0, id='below-range'),
    pytest.param(2, 1.0, id='above-range'),
    pytest.param(10 ** 400, 0.0, id='float-overflow'),
])
def test_confidence_coercion_does_not_treat_booleans_as_probabilities(value, expected):
    assessments, _, dropped = deep._parse_assessments(reply(confidence=value), REPORT)
    assert dropped == 0
    assert assessments[0]['confidence'] == expected


@pytest.mark.parametrize('field', ['rationale', 'overall_note'])
@pytest.mark.parametrize('pattern', ['x', '\x1b', '\u2603', 'x\0\u2603\t', '\udcff'],
                         ids=['plain', 'escape', 'unicode', 'mixed', 'surrogate'])
@pytest.mark.parametrize('length', [499, 500, 2000], ids=['under', 'exact', 'over'])
def test_escaping_work_is_bounded_and_keeps_the_existing_output_prefix(
        monkeypatch, field, pattern, length):
    text = (pattern * ((length + len(pattern) - 1) // len(pattern)))[:length]
    original = deep.escape_nonprintable
    expected = original(text)[:deep._MAX_RATIONALE_CHARS]
    lengths = []

    def escape(value):
        lengths.append(len(value))
        return original(value)

    monkeypatch.setattr(deep, 'escape_nonprintable', escape)
    assessments, note, dropped = deep._parse_assessments(reply(**{field: text}), REPORT)
    assert dropped == 0
    actual = assessments[0]['rationale'] if field == 'rationale' else note
    assert actual == expected
    assert max(lengths) <= deep._MAX_RATIONALE_CHARS


@pytest.mark.parametrize('confidence,expected', [(True, 0.0), (0.75, 0.75)],
                         ids=['malformed-confidence', 'numeric-confidence'])
def test_signed_advisory_report_preserves_rules_and_bounded_text(
        tmp_path, monkeypatch, confidence, expected):
    rules = {'run_dir': str(tmp_path), 'verdict': 'notable',
             'signals': [{'type': 'volume_anomaly', 'severity': 'medium',
                          'count': 1, 'evidence': ['owned signal']}],
             'inputs': {}, 'caveats': []}
    path = tmp_path / triage.TRIAGE_FILE
    triage._write(path, rules)
    original_bytes = path.read_bytes()
    original_escape = deep.escape_nonprintable
    lengths = []

    def escape(value):
        lengths.append(len(value))
        return original_escape(value)

    monkeypatch.setattr(deep, 'escape_nonprintable', escape)
    text = 'owned\x1b\u2603' * 300
    client = _FakeClient(reply(confidence, text, text))
    result = deep.deep_analyse(tmp_path, client=client)
    assert result['assessments'][0]['confidence'] == expected
    assert result['assessments'][0]['rationale'] == original_escape(text)[:500]
    assert result['overall_note'] == original_escape(text)[:500]
    assert max(lengths) <= deep._MAX_RATIONALE_CHARS
    assert len(client.calls) == 1
    assert result['rules_verdict'] == 'notable'
    assert result['rules_verdict_immutable'] is True
    assert path.read_bytes() == original_bytes
    saved = json.loads((tmp_path / deep.DEEP_FILE).read_text())
    assert saved == result
    assert deep.verify_deep_report(saved, tmp_path) == 'verified'

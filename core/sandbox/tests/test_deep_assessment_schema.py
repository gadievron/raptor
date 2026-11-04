"""Untrusted assessment shapes cannot interrupt deep-triage parsing."""
import json

import pytest

from core.sandbox import triage_deep as deep


REPORT = {'signals': [{'type': 'known'}]}


def parse(items):
    return deep._parse_assessments(json.dumps({'assessments': items}), REPORT)


@pytest.mark.parametrize('signal_type', [[], {}, ['known'], 1, None])
def test_invalid_signal_type_is_dropped_without_hiding_later_item(signal_type):
    assessments, _, dropped = parse([
        {'signal_type': signal_type},
        {'signal_type': 'known', 'judgement': 'tool_noise', 'confidence': 0.7}])
    assert dropped == 1
    assert len(assessments) == 1
    assert assessments[0]['judgement'] == 'tool_noise'


@pytest.mark.parametrize('judgement', [[], {}, ['tool_noise'], 1, None])
def test_invalid_judgement_becomes_unclear(judgement):
    assessments, _, dropped = parse([{'signal_type': 'known', 'judgement': judgement}])
    assert dropped == 0
    assert assessments[0]['judgement'] == 'unclear'


def test_integer_confidence_overflow_becomes_zero():
    assessments, _, dropped = parse([{'signal_type': 'known', 'confidence': 10 ** 400}])
    assert dropped == 0
    assert assessments[0]['confidence'] == 0.0


@pytest.mark.parametrize('error_type', [ValueError, RecursionError])
@pytest.mark.parametrize('wrapped', [False, True])
def test_decode_failures_return_empty(monkeypatch, error_type, wrapped):
    real_loads = json.loads

    def fail(text):
        if wrapped and text.startswith('prefix'):
            return real_loads(text)
        raise error_type('invalid model response')

    monkeypatch.setattr(deep.json, 'loads', fail)
    text = 'prefix {} suffix' if wrapped else '{}'
    assert deep._parse_assessments(text, REPORT) == ([], '', 0)


def test_prose_wrapped_valid_response_still_parses():
    text = 'prefix ' + json.dumps({'assessments': [
        {'signal_type': 'known', 'judgement': 'attack_attempt', 'confidence': 0.9}]}) + ' suffix'
    assessments, _, dropped = deep._parse_assessments(text, REPORT)
    assert dropped == 0
    assert assessments[0]['judgement'] == 'attack_attempt'

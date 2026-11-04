"""Deep-triage model responses have finite confidence and textual content."""
import json
from types import SimpleNamespace

import pytest

from core.sandbox import triage_deep as deep


@pytest.mark.parametrize('value', [float('inf'), float('-inf'), float('nan'),
                                  'Infinity', '-Infinity', 'NaN'])
def test_nonfinite_confidence_is_zero(value):
    text = json.dumps({'assessments': [{'signal_type': 'known', 'confidence': value}]})
    assessments, _, dropped = deep._parse_assessments(text, {'signals': [{'type': 'known'}]})
    assert dropped == 0
    assert assessments[0]['confidence'] == 0.0


@pytest.mark.parametrize('value,expected', [(-2, 0.0), (0.5, 0.5), (2, 1.0), ('0.7', 0.7)])
def test_finite_confidence_clamping_is_preserved(value, expected):
    text = json.dumps({'assessments': [{'signal_type': 'known', 'confidence': value}]})
    assessments, _, _ = deep._parse_assessments(text, {'signals': [{'type': 'known'}]})
    assert assessments[0]['confidence'] == expected


@pytest.mark.parametrize('content', [None, [], ['text'], {}, {'text': '{}'}, 42, b'{}'])
def test_nontext_response_content_becomes_empty(content):
    assert deep._response_text(SimpleNamespace(content=content)) == ''


@pytest.mark.parametrize('text', ['', '{}', '```json\n{}\n```'])
def test_text_response_forms_remain_supported(text):
    assert deep._response_text(text) == text
    assert deep._response_text(SimpleNamespace(content=text)) == text


def test_missing_content_becomes_empty():
    assert deep._response_text(object()) == ''

"""Denial text fields are validated before classification or MAC work."""
import json

import pytest

from core.sandbox import telemetry_mac, triage


@pytest.mark.parametrize('field', ['type', 'syscall', 'profile', 'path'])
@pytest.mark.parametrize('value', [[], {}, 7, True])
@pytest.mark.parametrize('stamped', [False, True])
def test_invalid_denial_text_is_rejected(tmp_path, monkeypatch, field, value, stamped):
    summary = {'total_denials': 1, 'denials': [{field: value}]}
    if stamped:
        summary['mac'] = 'invalid'

    def unexpected(*args, **kwargs):
        pytest.fail('malformed row reached MAC construction')

    monkeypatch.setattr(telemetry_mac, 'summary_fields', unexpected)
    assert triage._verify_summary(summary, 'run') == (None, triage._INTEGRITY_TAMPERED)
    (tmp_path / triage.SUMMARY_FILE).write_text(json.dumps(summary))
    report = triage.triage_run(tmp_path, allow_legacy=True)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('value', [None, '', 'text'])
def test_optional_string_fields_preserve_legacy_acceptance(value):
    row = dict.fromkeys(['type', 'syscall', 'profile', 'path'], value)
    summary = {'total_denials': 1, 'denials': [row]}
    assert triage._verify_summary(summary, 'run') == (summary, triage._INTEGRITY_LEGACY)

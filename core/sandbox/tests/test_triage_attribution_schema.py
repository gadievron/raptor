"""Recognized attribution fields are typed before provenance or display use."""

import copy
import json

import pytest

from core.sandbox import summary, telemetry_mac as mac, triage
from core.testing.sandbox_state_scope import isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


BAD_FLAGS = [None, 0, 1, 0.0, 1.0, '', 'true', [], {}, ['owned'], {'owned': True}]
BAD_TEXT = [None, 0, 1, False, True, 0.5, [], {}, ['owned'], {'owned': 'text'}]
SUMMARY_BAD = [('cli_sandbox_disabled', value) for value in BAD_FLAGS] + [('disable_consent', value) for value in BAD_TEXT]
MARKER_BAD = [(field, value) for field in ['reason', 'instructions'] for value in BAD_TEXT]
SUMMARY_GOOD = [
    {}, {'cli_sandbox_disabled': False}, {'cli_sandbox_disabled': True},
    {'disable_consent': ''}, {'disable_consent': 'owned-future-label'},
    {'cli_sandbox_disabled': False, 'disable_consent': ''},
    {'cli_sandbox_disabled': True, 'disable_consent': 'nonce'},
    {'cli_sandbox_disabled': True, 'disable_consent': 'owned-\x1b[31m\n' + 'x' * 1000},
]
MARKER_GOOD = [{}, {'reason': ''}, {'reason': 'owned'}, {'instructions': ''},
               {'reason': 'owned', 'instructions': 'owned instructions'},
               {'reason': 'owned-\x1b[31m\n', 'instructions': 'native text'}]


@pytest.fixture
def owned(tmp_path):
    with isolated_sandbox_state(()), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / 'state')
        home = tmp_path / 'home'
        home.mkdir()
        patch.setenv('HOME', str(home))
        patch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        patch.setattr(mac, '_warned_paths', set())
        run = tmp_path / 'run'
        run.mkdir()
        yield run


@pytest.fixture
def monkeypatch(owned):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def decoded(value):
    return json.loads(json.dumps(value))


@pytest.mark.parametrize('field,value', SUMMARY_BAD)
@pytest.mark.parametrize('mode', ['legacy', 'stamped'])
def test_bad_summary_headers_rejected_before_mac(owned, monkeypatch, field, value, mode):
    record = decoded({'total_denials': 0, 'denials': [], field: value})
    if mode == 'stamped':
        record['mac'] = 'owned-placeholder'
    before = copy.deepcopy(record)

    def unexpected(*args, **kwargs):
        pytest.fail('malformed header reached MAC construction')

    monkeypatch.setattr(mac, 'summary_fields', unexpected)
    accepted, integrity = triage._verify_summary(record, 'owned-run', allow_legacy=True)
    assert record == before
    assert accepted is None
    assert integrity == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('field,value', MARKER_BAD)
@pytest.mark.parametrize('mode', ['legacy', 'stamped'])
def test_bad_marker_text_rejected_before_mac(owned, monkeypatch, field, value, mode):
    record = decoded({'reason': 'owned reason', 'instructions': 'owned instructions', field: value})
    if mode == 'stamped':
        record['mac'] = 'owned-placeholder'
    before = copy.deepcopy(record)

    def unexpected(*args, **kwargs):
        pytest.fail('malformed marker text reached MAC construction')

    monkeypatch.setattr(mac, 'audit_degraded_fields', unexpected)
    accepted, integrity = triage._verify_audit_degraded(record, 'owned-run', allow_legacy=True)
    assert record == before
    assert accepted is None
    assert integrity == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('headers', SUMMARY_GOOD)
@pytest.mark.parametrize('mode', ['legacy', 'stamped'])
def test_valid_summary_headers_preserve_fields_and_bytes(owned, headers, mode):
    record = decoded({'total_denials': 0, 'denials': [], 'extra': {'future': True}, **headers})
    run = mac.run_binding(owned)
    if mode == 'stamped':
        fields = mac.summary_fields(0, triage._denials_sha256([]), run,
                                   cli_sandbox_disabled=record.get('cli_sandbox_disabled', False),
                                   disable_consent=record.get('disable_consent', ''))
        record['mac'] = mac.mint(fields)
        assert record['mac']
    before = json.dumps(record, ensure_ascii=True)
    accepted, integrity = triage._verify_summary(record, run, allow_legacy=mode == 'legacy')
    assert accepted is record
    assert integrity == (triage._INTEGRITY_LEGACY if mode == 'legacy' else triage._INTEGRITY_VERIFIED)
    assert json.dumps(record, ensure_ascii=True) == before


@pytest.mark.parametrize('text', MARKER_GOOD)
@pytest.mark.parametrize('mode', ['legacy', 'stamped'])
def test_valid_marker_text_preserves_fields_and_bytes(owned, text, mode):
    record = decoded({'extra': {'future': True}, **text})
    run = mac.run_binding(owned)
    if mode == 'stamped':
        record['mac'] = mac.mint(mac.audit_degraded_fields(record, run))
        assert record['mac']
    before = json.dumps(record, ensure_ascii=True)
    accepted, integrity = triage._verify_audit_degraded(record, run, allow_legacy=mode == 'legacy')
    assert accepted is record
    assert integrity == (triage._INTEGRITY_LEGACY if mode == 'legacy' else triage._INTEGRITY_VERIFIED)
    assert json.dumps(record, ensure_ascii=True) == before


@pytest.mark.parametrize('source,field,value', [
    ('summary', 'cli_sandbox_disabled', None), ('summary', 'cli_sandbox_disabled', 0),
    ('summary', 'disable_consent', True), ('summary', 'disable_consent', {}),
    ('marker', 'reason', None), ('marker', 'reason', []),
    ('marker', 'instructions', False), ('marker', 'instructions', {}),
])
@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_cli_reports_malformed_legacy_metadata_without_rewriting_input(owned, capsys, source, field, value, json_output):
    if source == 'summary':
        path = owned / summary.SUMMARY_FILE
        record = {'total_denials': 0, 'denials': [], field: value}
        key = 'sandbox_summary'
    else:
        path = owned / summary.AUDIT_DEGRADED_FILE
        record = {'reason': 'owned reason', 'instructions': 'owned instructions', field: value}
        key = 'audit_degraded'
    before = (json.dumps(record) + '\n').encode()
    path.write_bytes(before)
    code = triage._cli_main([str(owned), '--legacy'] + (['--json'] if json_output else []))
    captured = capsys.readouterr()
    report = json.loads((owned / triage.TRIAGE_FILE).read_text())
    assert path.read_bytes() == before
    assert report['inputs']['integrity'][key] == triage._INTEGRITY_TAMPERED
    assert any(s['type'] == 'telemetry_tampering' for s in report['signals'])
    assert code == 4
    assert captured.err == ''
    if json_output:
        assert json.loads(captured.out) == report
    else:
        assert 'Verdict: Suspicious' in captured.out
    assert triage.verify_triage_report(report, owned) == triage._INTEGRITY_VERIFIED


def test_absent_artifacts_keep_existing_integrity():
    assert triage._verify_summary(None, 'owned-run', allow_legacy=False) == (None, triage._INTEGRITY_VERIFIED)
    assert triage._verify_audit_degraded(None, 'owned-run', allow_legacy=False) == (None, triage._INTEGRITY_VERIFIED)

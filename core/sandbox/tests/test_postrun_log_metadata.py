"""Post-run diagnostic metadata cannot rewrite human log records."""
import json
import logging

import pytest

from core.sandbox import calibrate as cal, egress_summary as egress, evidence
from core.sandbox import observe_profile as observe
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr(observe, '_connect_gap_last_warn', float('-inf'))
    monkeypatch.setattr(cal, '_CACHE_DIR', tmp_path / CONTROL / 'cache')


def safe_records(caplog, module, prefix):
    records = [r for r in caplog.records if r.name == module.__name__]
    assert records
    formatter = logging.Formatter('%(message)s')
    for record in records:
        text = formatter.format(record)
        assert prefix in text
        assert 'owned-' in text
        assert all(c not in text for c in ('\x1b', '\r', '\x85', '\u202e'))
        assert '\n' not in text
    return records


def write_observation(run, rows):
    path = evidence.evidence_write_path(run, observe.OBSERVE_FILENAME)
    path.parent.mkdir(parents=True)
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    return path


@pytest.mark.parametrize('kind', ['unprotected', 'missing-nonce', 'ambiguous', 'connect-gap',
                                 'not-regular', 'oversized'])
def test_observe_diagnostics_escape_run_metadata(tmp_path, monkeypatch, caplog, kind):
    run = tmp_path / CONTROL
    options = dict(expected_nonce='owned', current_run=True,
                   sandbox_info={'nonce_delivery': 'in_process'})
    rows = [{'type': 'audit_summary', 'nonce': 'owned'}]
    if kind == 'unprotected':
        options['sandbox_info'] = {'nonce_delivery': CONTROL}
    elif kind == 'missing-nonce':
        options['expected_nonce'] = None
    elif kind == 'ambiguous':
        rows.insert(0, {'nonce': 'owned', 'parse_ambiguous': True})
    elif kind == 'connect-gap':
        rows.insert(0, {'nonce': 'owned', 'syscall': 'network-outbound', 'path': 'unparsed'})
    path = write_observation(run, rows)
    if kind == 'not-regular':
        path.unlink()
        path.mkdir()
    elif kind == 'oversized':
        monkeypatch.setattr(observe, '_MAX_OBSERVE_BYTES', 1)
    result = observe.parse_observe_log(run, **options)
    safe_records(caplog, observe, 'parse' if kind not in ('not-regular', 'oversized') else 'observe log')
    assert result.nonce_trusted is (kind not in ('unprotected', 'missing-nonce'))
    if kind in ('ambiguous', 'connect-gap', 'not-regular', 'oversized'):
        assert result.capture_incomplete is True
    if kind not in ('not-regular', 'oversized'):
        assert path.read_text() == ''.join(json.dumps(row) + '\n' for row in rows)


def calibration_profile():
    return cal.SandboxProfile(binary_path='/owned/tool', binary_sha256='owned',
                              env_signature='owned', captured_at='2026-01-01T00:00:00Z',
                              probe_args=['--version'])


@pytest.mark.parametrize('kind', ['setup', 'write', 'load'])
def test_calibration_cache_failure_logs_escape_metadata(tmp_path, caplog, kind):
    cache = cal.cache_dir()
    if kind == 'setup':
        cache.parent.write_bytes(b'owned obstruction')
    else:
        cache.mkdir(parents=True)
        if kind == 'write':
            (cache / 'owned.json').mkdir()
        else:
            (cache / 'owned.json').write_text('{')
    if kind == 'load':
        assert cal._load_from_cache('owned') is None
    else:
        assert cal._save_to_cache('owned', calibration_profile()) is None
    safe_records(caplog, cal, 'calibrate: cache')
    if kind == 'setup':
        assert cache.parent.read_bytes() == b'owned obstruction'
    elif kind == 'write':
        assert (cache / 'owned.json').is_dir()
    else:
        assert (cache / 'owned.json').read_text() == '{'


@pytest.mark.parametrize('kind', ['allowed', 'denied', 'write-failure'])
def test_egress_finalize_logs_escape_path_and_errors(tmp_path, caplog, kind):
    caplog.set_level(logging.DEBUG, logger=egress.__name__)
    run = tmp_path / CONTROL
    run.mkdir()
    event = {'host': 'owned.invalid', 'port': 443,
             'result': 'denied_policy' if kind == 'denied' else 'allowed'}
    source = run / egress.PROXY_EVENTS_FILENAME
    source.write_text(json.dumps(event) + '\n')
    output = run / egress.EGRESS_SUMMARY_FILE
    if kind == 'write-failure':
        output.mkdir()
    result = egress.finalize_egress_summary(run)
    if kind == 'write-failure':
        assert result is None
        assert output.is_dir()
    else:
        assert result['total_connections'] == 1
        assert json.loads(output.read_text()) == result
    safe_records(caplog, egress, 'finalize_egress_summary failed' if kind == 'write-failure' else 'egress:')
    assert source.read_text() == json.dumps(event) + '\n'

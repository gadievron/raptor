"""Activity provenance, truthful outcomes, bounded output and loss controls."""
import json
from subprocess import CompletedProcess

import pytest

from core.sandbox import activity, summary, telemetry_mac
from core.testing.module_state import isolated_module_state


@pytest.fixture(autouse=True)
def owned_receipts(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
    with isolated_module_state(activity, {'_runs': {}}, lock=activity._lock):
        with isolated_module_state(summary, {'_run_postures': {}}, lock=summary._lock):
            yield


def receipt(run, *, hidden=True, returncode=0):
    result = CompletedProcess(['/owned/not-executed'], returncode)
    result.sandbox_info = {'mount_ns_active': hidden, 'restrict_reads': hidden,
                           'containment_tier': 'mount-ns' if hidden else 'none'}
    summary.record_run_posture(run, mount_ns_active=hidden, restrict_reads=hidden)
    activity.record_execution(run, result=result, job_budget={'status': 'not_requested'})
    return result


def test_parent_receipt_signed_files_and_incomplete_empty_observation(tmp_path):
    receipt(tmp_path)
    report = activity.finalize(tmp_path)
    assert report['execution_count'] == 1
    assert report['event_count'] == 1
    assert report['integrity'] == 'verified'
    assert not report['coverage']['complete']
    assert 'observe_disabled_or_unavailable' in report['coverage']['issues']
    assert activity.verify_report(tmp_path, report, key_hidden=True)
    assert not activity.verify_report(tmp_path, report)  # no assumed key-hiding posture
    row = json.loads((tmp_path / activity.EVENTS_FILE).read_text())
    assert row['action'] == 'process_exit' and row['outcome'] == 'succeeded'
    assert row['pid'] is None  # CompletedProcess supplies no observed PID
    assert (tmp_path / activity.TEXT_FILE).stat().st_mode & 0o777 == 0o600
    assert 'Attempts do not establish success' in (tmp_path / activity.TEXT_FILE).read_text()


def test_edited_events_and_cross_run_replay_rejected(tmp_path):
    receipt(tmp_path)
    report = activity.finalize(tmp_path)
    path = tmp_path / activity.EVENTS_FILE
    original = path.read_bytes()
    path.write_text('{"outcome":"succeeded"}\n')
    assert not activity.verify_report(tmp_path, report, key_hidden=True)
    path.write_bytes(original)
    other = tmp_path / 'another-run'
    other.mkdir()
    (other / activity.EVENTS_FILE).write_bytes(original)
    assert not activity.verify_report(other, report, key_hidden=True)


def test_target_forged_unsigned_policy_not_promoted(tmp_path):
    receipt(tmp_path)
    (tmp_path / summary.SUMMARY_FILE).write_text(json.dumps({
        'total_denials': 1, 'denials': [{'type': 'fake', 'path': '/invented'}]}))
    report = activity.finalize(tmp_path)
    assert report['event_count'] == 1
    assert any('denial_' in issue for issue in report['coverage']['issues'])
    assert '/invented' not in (tmp_path / activity.EVENTS_FILE).read_text()


def test_known_key_exposed_receipt_never_claims_verified(tmp_path):
    receipt(tmp_path, hidden=False)
    report = activity.finalize(tmp_path)
    assert report['integrity'] == 'unavailable'
    assert not activity.verify_report(tmp_path, report, key_hidden=True)
    assert 'telemetry_key_exposed' in report['coverage']['issues']


def test_valid_proxy_event_retains_tunnel_semantics(tmp_path):
    from core.sandbox import context
    receipt(tmp_path)
    event = {'t': 1.0, 'host': 'example.org', 'port': 443, 'result': 'allowed',
             'resolved_ip': '93.184.216.34', 'bytes_c2u': 12, 'bytes_u2c': 24, 'duration': .2}
    context._persist_proxy_events([event], output=str(tmp_path), target=None)
    report = activity.finalize(tmp_path)
    rows = [json.loads(line) for line in (tmp_path / activity.EVENTS_FILE).read_text().splitlines()]
    tunnels = [row for row in rows if row['source'] == 'proxy']
    assert len(tunnels) == 1
    assert tunnels[0]['outcome'] == 'allowed'
    assert tunnels[0]['details']['http_method'] == 'not_visible'
    assert tunnels[0]['details']['url_path'] == 'not_visible'
    assert 'query names/types not comprehensively observed' in report['coverage']['dns']


def test_observe_paths_are_attempts_not_reads_succeeded(tmp_path, monkeypatch):
    from core.sandbox import observe_profile
    profile = observe_profile.ObserveProfile(paths_read=['/some/path'], paths_stat=['/checked'],
                                              budget_truncated=True)
    monkeypatch.setattr(observe_profile, 'parse_observe_log', lambda *a, **kw: profile)
    records = [
        {'syscall': 'openat', 'args': [-100, 1234, 0], 'path': '/some/path',
         'ts': 'owned-time', 'pid': 123, 'nonce': 'owned'},
        {'syscall': 'stat', 'path': '/checked', 'ts': 'later', 'pid': 124, 'nonce': 'owned'},
    ]
    monkeypatch.setattr(observe_profile, '_iter_records', lambda *a, **kw: iter(records))
    result = CompletedProcess(['/owned'], 0)
    result.sandbox_info = {'observe_nonce': 'owned', 'mount_ns_active': True}
    activity.record_execution(tmp_path, result=result)
    report = activity.finalize(tmp_path)
    rows = [json.loads(line) for line in (tmp_path / activity.EVENTS_FILE).read_text().splitlines()]
    observed = [row for row in rows if row['source'] == 'observe']
    assert {row['action'] for row in observed} == {'open_read', 'stat'}
    assert {row['pid'] for row in observed} == {123, 124}
    assert {row['timestamp'] for row in observed} == {'owned-time', 'later'}
    assert all(row['outcome'] == 'attempted' for row in observed)
    assert all(row['details']['operation_success'] == 'unknown' for row in observed)
    assert 'observe_budget_truncated' in report['coverage']['issues']


def test_activity_cap_is_visible_and_output_is_sanitised(tmp_path, monkeypatch):
    monkeypatch.setattr(activity, 'MAX_EVENTS', 1)
    receipt(tmp_path)
    receipt(tmp_path, returncode=1)
    report = activity.finalize(tmp_path)
    assert report['event_count'] == 1
    assert report['execution_count'] == 2
    assert 'activity_budget_exhausted' in report['coverage']['issues']
    assert '\x1b' not in activity._text('path\x1b]0;injected\x07')


def test_duplicate_source_identity_not_resource_deduplication():
    state = activity._state()
    activity._append(state, 'proxy', 'connect', 'same', identity=1)
    activity._append(state, 'proxy', 'connect', 'same', identity=1)
    activity._append(state, 'proxy', 'connect', 'same', identity=2)
    assert len(state['events']) == 2


def test_prefork_signer_uses_existing_canonical_format_without_key_reopen(monkeypatch):
    fields = {'kind': 'sandbox-job-budget', 'run': 'owned', 'sha256': 'owned-data'}
    expected = telemetry_mac.mint(fields)
    signer = telemetry_mac.prepare_signer()
    def unexpected():
        raise AssertionError('post-fork signer reopened key')
    monkeypatch.setattr(telemetry_mac, '_load_or_create_key', unexpected)
    assert signer(fields) == expected
    with pytest.raises(ValueError):
        signer({'run': 'missing-kind'})


def test_watcher_receipt_is_joined_without_duplicate_parent_job(tmp_path):
    from core.sandbox import evidence, job_budget
    job_id = 'a' * 32
    receipt(tmp_path)
    row = {'run': tmp_path.name, 'job_id': job_id,
           'requested': {'pids.max': '16'}, 'result': {'cleanup': 'complete'},
           'policy': 'full_mount_pid_namespace_required'}
    row['mac'] = telemetry_mac.mint(job_budget.receipt_fields(row))
    with_handle = evidence.EvidenceFile.open(tmp_path, job_budget.RECEIPTS_FILE)
    try:
        assert with_handle.write_record(row)
        assert with_handle.write_record(row)
    finally:
        with_handle.close()
    report = activity.finalize(tmp_path)
    assert len(report['job_budgets']) == 1
    assert report['job_budgets'][0]['cleanup'] == 'complete'
    assert activity.verify_report(tmp_path, report, key_hidden=True)
    # Finalisation of already-written, verified artifacts is idempotent.
    assert activity.finalize(tmp_path) == report


def test_orphan_receipt_without_known_key_hiding_posture_is_not_attested(tmp_path):
    from core.sandbox import evidence, job_budget
    row = {'run': tmp_path.name, 'job_id': 'b' * 32, 'requested': {'pids.max': '16'},
           'result': {'cleanup': 'complete'}}
    row['mac'] = telemetry_mac.mint(job_budget.receipt_fields(row))
    handle = evidence.EvidenceFile.open(tmp_path, job_budget.RECEIPTS_FILE)
    try:
        assert handle.write_record(row)
    finally:
        handle.close()
    report = activity.finalize(tmp_path)
    assert report['integrity'] == 'unavailable'
    assert not report['job_budgets']
    assert 'job_budget_receipt_unverified' in report['coverage']['issues']


def test_proxy_timing_and_bytes_cannot_be_changed_under_legacy_mac(tmp_path):
    from core.sandbox import context
    from core.sandbox.proxy import PROXY_EVENTS_FILENAME
    receipt(tmp_path)
    context._persist_proxy_events([{'t': 1., 'host': 'example.org', 'port': 443,
        'result': 'allowed', 'resolved_ip': '93.184.216.34', 'bytes_c2u': 12,
        'bytes_u2c': 24, 'duration': .5}], output=str(tmp_path), target=None)
    path = tmp_path / PROXY_EVENTS_FILENAME
    row = json.loads(path.read_text())
    row.update(port=12345, bytes_c2u=999999, duration=999999)
    path.write_text(json.dumps(row)+'\n')
    report = activity.finalize(tmp_path)
    rows = [json.loads(line) for line in (tmp_path / activity.EVENTS_FILE).read_text().splitlines()]
    tunnel = next(row for row in rows if row['source'] == 'proxy')
    assert tunnel['resource'] == 'example.org' and tunnel['outcome'] == 'allowed'
    assert tunnel['details']['port'] is None and tunnel['details']['bytes_c2u'] is None
    assert not tunnel['details']['metadata_verified']
    assert 'proxy_activity_fields_unverified' in report['coverage']['issues']


@pytest.mark.parametrize('tamper', [False, True])
def test_allowed_policy_activity_has_its_own_provenance(tmp_path, tamper):
    receipt(tmp_path)
    report = summary._assemble_and_write_summary(tmp_path,
        records=[{'type': 'read', 'path': '/owned/allowed', 'verdict': 'allow', 'ts': 'owned'}],
        refusals=[], corrupt_lines=0, inode_mismatch=False, planted_object='')
    assert report['allowed_activity_mac']
    if tamper:
        report['allowed_reports'][0]['path'] = '/not-observed'
        (tmp_path / summary.SUMMARY_FILE).write_text(json.dumps(report))
    merged = activity.finalize(tmp_path)
    rows = [json.loads(line) for line in (tmp_path / activity.EVENTS_FILE).read_text().splitlines()]
    allowed = [row for row in rows if row['source'] == 'policy_allowed']
    assert bool(allowed) is (not tamper)
    if not tamper:
        assert allowed[0]['outcome'] == 'allowed'
        assert allowed[0]['details']['operation_success'] == 'unknown'
    else:
        assert 'allowed_policy_records_unverified' in merged['coverage']['issues']


def test_observe_reader_failure_does_not_drop_execution_receipt(tmp_path, monkeypatch):
    calls = []
    def broken(*args):
        calls.append('observe')
        raise OSError('owned reader failure')
    monkeypatch.setattr(activity, '_capture_observe', broken)
    result = CompletedProcess(['/owned'], 0)
    result.sandbox_info = {'mount_ns_active': True, 'observe_nonce': 'owned'}
    activity.record_execution(tmp_path, result=result)
    report = activity.finalize(tmp_path)
    assert calls == ['observe']
    assert report['execution_count'] == 1
    assert report['counts'] == [{'action': 'process_exit', 'outcome': 'succeeded', 'count': 1}]
    assert 'observe_receipt_failed:OSError' in report['coverage']['issues']

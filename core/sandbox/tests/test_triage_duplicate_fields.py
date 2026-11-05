"""Ambiguous objects cannot pass triage's evidence readers."""
import json

import pytest

from core.sandbox import telemetry_mac as mac, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


@pytest.mark.parametrize('text', [
    '{"detail":1,"detail":2}',
    r'{"detail":1,"de\u0074ail":2}',
    '{"metadata":{"detail":1,"detail":2}}',
    '{"metadata":[{"detail":1,"detail":1}]}',
])
def test_whole_json_refuses_duplicates(tmp_path, text):
    path = tmp_path / 'input.json'
    path.write_text(text)
    assert triage._load_json(path) is None


def duplicate(record, field, earlier):
    return '{' + json.dumps(field) + ':' + json.dumps(earlier) + ',' + json.dumps(record)[1:]


@pytest.mark.parametrize('artifact', ['summary', 'degraded', 'count'])
def test_ambiguous_signed_artifact_cannot_verify(tmp_path, artifact):
    run = tmp_path / 'run'
    run.mkdir()
    binding = mac.run_binding(run)
    if artifact == 'summary':
        record = {'total_denials': 0, 'denials': []}
        record['mac'] = mac.mint(mac.summary_fields(0, triage._denials_sha256([]), binding))
        name, field, earlier, integrity = triage.SUMMARY_FILE, 'total_denials', 1, 'sandbox_summary'
    elif artifact == 'degraded':
        record = {'reason': 'owned fixture', 'instructions': ''}
        record['mac'] = mac.mint(mac.audit_degraded_fields(record, binding))
        name, field, earlier, integrity = triage.AUDIT_DEGRADED_FILE, 'reason', 'earlier', 'audit_degraded'
    else:
        record = {'count': 0, 'flags': []}
        record['mac'] = mac.mint(mac.proxy_events_count_fields(0, [], binding))
        name, field, earlier, integrity = triage.PROXY_EVENTS_COUNT_FILENAME, 'count', 1, 'proxy_events'
    assert record['mac']
    (run / name).write_text(duplicate(record, field, earlier))
    report = triage.triage_run(run, allow_legacy=False)
    assert report is not None
    assert report['inputs']['integrity'][integrity] == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('chunk_size', [1, 1024])
@pytest.mark.parametrize('nested', [False, True], ids=['event-field', 'nested-field'])
def test_stream_discards_ambiguity_and_retains_verified_peers(tmp_path, monkeypatch, chunk_size, nested):
    run = tmp_path / 'run'
    run.mkdir()
    records = []
    for seq in range(3):
        rec = {'host': 'example.test', 'result': 'allowed', 'seq': seq}
        rec['mac'] = mac.mint(mac.proxy_event_fields(rec, mac.run_binding(run)))
        assert rec['mac']
        records.append(rec)
    if nested:
        ambiguous = json.dumps(records[1])[:-1] + ',"metadata":{"detail":1,"detail":2}}'
    else:
        ambiguous = duplicate(records[1], 'host', 'earlier.test')
    path = run / triage.PROXY_EVENTS_FILENAME
    path.write_text(json.dumps(records[0]) + '\n' + ambiguous + '\n' + json.dumps(records[2]) + '\n')
    # Copy the consumer OS binding; chunk injection must not affect others.
    from types import ModuleType
    import os
    private = ModuleType('duplicate_stream_os')
    vars(private).update(vars(os))
    private.read = lambda fd, size: os.read(fd, min(size, chunk_size))
    monkeypatch.setattr(triage, 'os', private)
    issues = set()
    assert triage._load_jsonl_stream(path, issues=issues) == ([records[0], records[2]], False)
    assert issues == {'malformed_record'}
    report = triage.triage_run(run, allow_legacy=True)
    assert report['inputs']['total_proxy_events'] == 2
    assert report['inputs']['integrity']['proxy_events'] == triage._INTEGRITY_TAMPERED
    assert 'malformed_record' in json.dumps(report)


@pytest.mark.parametrize('record', [
    {'left': {'detail': 1}, 'right': {'detail': 2}},
    {'items': [{'detail': 1}, {'detail': 2}]},
    {'\u00e9': 1, 'e\u0301': 2},
])
def test_unique_objects_remain_compatible(tmp_path, record):
    path = tmp_path / 'input.json'
    path.write_text(json.dumps(record))
    assert triage._load_json(path) == record
    events, issues = [], set()
    triage._parse_jsonl_line(path.read_bytes(), events, issues=issues)
    assert events == [record]
    assert not issues

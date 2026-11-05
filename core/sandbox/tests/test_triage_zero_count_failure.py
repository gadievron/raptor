"""Parent-memory persistence failures remain reportable at count zero."""
import errno
import json
import os

import pytest

from core.sandbox import context, proxy, summary, telemetry_mac, triage


@pytest.fixture(autouse=True)
def isolate_state(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
    monkeypatch.setattr(summary, '_proxy_persist_state', {})
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})


@pytest.mark.parametrize('flag', ['persist_open_failure', 'persist_write_failure'])
def test_zero_count_failure_still_produces_report(tmp_path, flag):
    summary.record_proxy_persist_state(tmp_path, expected_count=0, flags=[flag])
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report is not None
    assert report['inputs']['integrity']['proxy_events'] == triage._INTEGRITY_TAMPERED
    assert flag in json.dumps(report)
    assert (tmp_path / triage.TRIAGE_FILE).exists()


def test_healthy_zero_count_still_has_no_report(tmp_path):
    summary.record_proxy_persist_state(tmp_path, expected_count=0, flags=[])
    assert triage.triage_run(tmp_path, allow_legacy=False) is None


def test_legacy_no_artifact_behavior_is_preserved(tmp_path):
    summary.record_proxy_persist_state(tmp_path, expected_count=0, flags=['persist_open_failure'])
    assert triage.triage_run(tmp_path, allow_legacy=True) is None


def test_failed_first_append_and_sidecar_still_produce_report(tmp_path, monkeypatch):
    log = tmp_path / proxy.PROXY_EVENTS_FILENAME
    original_open = os.open

    def refuse_log(path, *args, **kwargs):
        if os.fspath(path) == str(log):
            raise OSError(errno.EACCES, 'first append unavailable')
        return original_open(path, *args, **kwargs)

    def fail_key(fields):
        raise OSError(errno.ENOSPC, 'key creation unavailable')

    with monkeypatch.context() as scoped:
        scoped.setattr(os, 'open', refuse_log)
        scoped.setattr(telemetry_mac, 'mint', fail_key)
        context._persist_proxy_events([{'host': 'example.test'}], output=tmp_path)
    assert not log.exists()
    assert not (tmp_path / proxy.PROXY_EVENTS_COUNT_FILENAME).exists()
    assert summary.get_proxy_persist_state(tmp_path)['expected_count'] == 0
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report is not None
    assert 'persist_open_failure' in json.dumps(report)
    assert report['inputs']['integrity']['proxy_events'] == triage._INTEGRITY_TAMPERED

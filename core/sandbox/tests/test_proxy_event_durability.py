"""Durable sidecar counts follow event durability and retain write failures."""
import json
import os
import stat
import threading

import pytest

from core.sandbox import context, proxy, summary, telemetry_mac


import core.sandbox.context as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(autouse=True)
def _isolate_delegated_os_faults(monkeypatch):
    """Forward delegated syscalls while preserving each borrowed OS view."""
    import core.sandbox.context as primary0
    import core.atomic_fs as delegated0
    patch_module_attribute(monkeypatch, delegated0, "os", "fsync",
                           lambda *args, **kwargs: primary0.os.fsync(*args, **kwargs))
    import core.sandbox.context as primary1
    import core.atomic_fs as delegated1
    patch_module_attribute(monkeypatch, delegated1, "os", "fstat",
                           lambda *args, **kwargs: primary1.os.fstat(*args, **kwargs))
    import core.sandbox.context as primary2
    import core.atomic_fs as delegated2
    patch_module_attribute(monkeypatch, delegated2, "os", "close",
                           lambda *args, **kwargs: primary2.os.close(*args, **kwargs))


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch):
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})
    monkeypatch.setattr(context, '_PROXY_PERSIST_LOCK', threading.Lock())
    monkeypatch.setattr(summary, '_proxy_persist_state', {})
    monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: 'test-token')
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'test-token')


def event(host='example.test'):
    return {'host': host, 'port': 443, 'result': 'allowed'}


def paths(tmp_path):
    return tmp_path / proxy.PROXY_EVENTS_FILENAME, tmp_path / proxy.PROXY_EVENTS_COUNT_FILENAME


def test_events_are_fsynced_before_count_sidecar(tmp_path, monkeypatch):
    log, sidecar = paths(tmp_path)
    original = os.fsync
    order = []

    def fsync(fd):
        current = os.fstat(fd)
        source = log.stat()
        if stat.S_ISREG(current.st_mode):
            order.append('events' if (current.st_dev, current.st_ino) == (source.st_dev, source.st_ino) else 'sidecar')
        return original(fd)

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'fsync', fsync)
    context._persist_proxy_events([event()], output=tmp_path)
    assert order.index('events') < order.index('sidecar')
    assert json.loads(sidecar.read_text())['count'] == 1
    assert json.loads(sidecar.read_text())['flags'] == []


def test_event_fsync_failure_is_recorded_and_stays_sticky(tmp_path, monkeypatch, caplog):
    log, sidecar = paths(tmp_path)
    original = os.fsync

    def fail_event_sync(fd):
        current, source = os.fstat(fd), log.stat()
        if (current.st_dev, current.st_ino) == (source.st_dev, source.st_ino):
            raise OSError('event durability unavailable')
        return original(fd)

    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, _os_fault_consumer, "os", 'fsync', fail_event_sync)
        context._persist_proxy_events([event()], output=tmp_path)
    failed = json.loads(sidecar.read_text())
    assert failed['count'] == 1
    assert 'persist_write_failure' in failed['flags']
    assert 'persist_write_failure' in summary.get_proxy_persist_state(tmp_path)['flags']
    context._persist_proxy_events([event('later.test')], output=tmp_path)
    later = json.loads(sidecar.read_text())
    assert later['count'] == 2
    assert 'persist_write_failure' in later['flags']
    assert [json.loads(line)['seq'] for line in log.read_text().splitlines()] == [0, 1]
    assert 'could not write proxy events' in caplog.text


def test_late_serialization_failure_preserves_count_of_written_prefix(tmp_path):
    log, sidecar = paths(tmp_path)
    context._persist_proxy_events([event(), {**event(), 'bad': object()}], output=tmp_path)
    count = json.loads(sidecar.read_text())
    assert count['count'] == 1
    assert 'persist_write_failure' in count['flags']
    assert len(log.read_text().splitlines()) == 1
    context._persist_proxy_events([event('later.test')], output=tmp_path)
    assert [json.loads(line)['seq'] for line in log.read_text().splitlines()] == [0, 1]


def test_metadata_failure_preserves_existing_sidecar_anchor(tmp_path, monkeypatch):
    _, sidecar = paths(tmp_path)
    sidecar.write_text(json.dumps({'count': 7, 'flags': ['old_flag'], 'mac': 'test-token'}))
    original = os.fstat
    calls = []

    def fail_once(fd):
        calls.append(fd)
        if len(calls) == 1:
            raise OSError('metadata failed')
        return original(fd)

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'fstat', fail_once)
    context._persist_proxy_events([event()], output=tmp_path)
    payload = json.loads(sidecar.read_text())
    assert payload['count'] == 7
    assert set(payload['flags']) == {'old_flag', 'persist_write_failure'}
    assert context._PROXY_PERSIST_LOCK.acquire(blocking=False)
    context._PROXY_PERSIST_LOCK.release()


def test_secondary_failure_reporting_cannot_leak_persist_lock(tmp_path, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError('sidecar unavailable')

    monkeypatch.setattr(context, '_write_proxy_count_sidecar', fail)
    context._persist_proxy_events([event()], output=tmp_path)
    assert context._PROXY_PERSIST_LOCK.acquire(blocking=False)
    context._PROXY_PERSIST_LOCK.release()
    assert 'could not persist proxy write-failure state' in caplog.text


def test_nonregular_close_error_does_not_retry_a_released_fd(tmp_path, monkeypatch):
    from types import SimpleNamespace

    log, sidecar = paths(tmp_path)
    original_fstat, original_close = os.fstat, os.close
    first_stat = True
    failed_close = False
    invalid_closes = []

    def fake_stat(fd):
        nonlocal first_stat
        if first_stat:
            first_stat = False
            return SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
        return original_fstat(fd)

    def close(fd):
        nonlocal failed_close
        try:
            original_fstat(fd)
        except OSError:
            invalid_closes.append(fd)
            raise
        original_close(fd)
        if not failed_close:
            failed_close = True
            raise OSError('close failed after descriptor release')

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'fstat', fake_stat)
    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'close', close)
    context._persist_proxy_events([event()], output=tmp_path)
    assert invalid_closes == []
    assert log.read_bytes() == b''
    assert 'persist_write_failure' in json.loads(sidecar.read_text())['flags']

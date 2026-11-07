"""Count sidecars publish complete JSON without losing old data on failure."""
import json
import os
import stat
from unittest.mock import Mock

import pytest

from core.sandbox import context
from core.sandbox import proxy
from core.sandbox import summary
from core.sandbox import telemetry_mac


import core.atomic_fs as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def sidecar(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: 'test-token')
    mirror = Mock()
    monkeypatch.setattr(summary, 'record_proxy_persist_state', mirror)
    return tmp_path / proxy.PROXY_EVENTS_COUNT_FILENAME, mirror


@pytest.mark.parametrize('size', [1, 7])
def test_partial_writes_publish_full_sidecar(tmp_path, monkeypatch, sidecar, size):
    path, mirror = sidecar
    original = os.write
    calls = []

    def write(fd, data):
        calls.append(len(data))
        return original(fd, data[:size])

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'write', write)
    context._write_proxy_count_sidecar(tmp_path, 12, {'flag'}, 'run-binding')
    assert json.loads(path.read_text()) == {'count': 12, 'flags': ['flag'], 'mac': 'test-token'}
    assert len(calls) > 1
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    mirror.assert_called_once()
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]


def test_no_progress_preserves_previous_sidecar(tmp_path, monkeypatch, sidecar, caplog):
    path, mirror = sidecar
    path.write_bytes(b'previous')
    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'write', lambda fd, data: 0)
    context._write_proxy_count_sidecar(tmp_path, 12, set(), 'run-binding')
    assert path.read_bytes() == b'previous'
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]
    assert 'could not write' in caplog.text
    mirror.assert_called_once()


def test_stale_legacy_temp_file_does_not_block_or_get_deleted(tmp_path, sidecar):
    path, _ = sidecar
    stale = path.with_name(f'{path.name}.tmp.{os.getpid()}')
    stale.write_bytes(b'not owned by this call')
    context._write_proxy_count_sidecar(tmp_path, 12, set(), 'run-binding')
    assert json.loads(path.read_text())['count'] == 12
    assert stale.read_bytes() == b'not owned by this call'


def test_cancellation_cleans_owned_temp_and_preserves_old_file(tmp_path, monkeypatch, sidecar):
    path, _ = sidecar
    path.write_bytes(b'previous')

    original = os.write
    calls = []

    def cancel(fd, data):
        calls.append(fd)
        if len(calls) == 1:
            return original(fd, data[:5])
        raise KeyboardInterrupt()

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'write', cancel)
    with pytest.raises(KeyboardInterrupt):
        context._write_proxy_count_sidecar(tmp_path, 12, set(), 'run-binding')
    assert path.read_bytes() == b'previous'
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]


def test_unavailable_mac_keeps_memory_mirror_without_file(tmp_path, monkeypatch, sidecar):
    path, mirror = sidecar
    monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: None)
    context._write_proxy_count_sidecar(tmp_path, 12, set(), 'run-binding')
    assert not path.exists()
    mirror.assert_called_once()


@pytest.mark.parametrize('operation', ['fsync', 'replace'])
def test_commit_failure_preserves_old_sidecar(tmp_path, monkeypatch, sidecar, operation):
    path, mirror = sidecar
    path.write_bytes(b'previous')

    def fail(*args, **kwargs):
        raise OSError('commit failed')

    patch_module_attribute(monkeypatch, _os_fault_consumer, 'os', operation, fail)
    context._write_proxy_count_sidecar(tmp_path, 12, set(), 'run-binding')
    assert path.read_bytes() == b'previous'
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]
    mirror.assert_called_once()


def test_one_flag_snapshot_feeds_mac_payload_and_parent_mirror(tmp_path, monkeypatch, sidecar):
    path, mirror = sidecar
    original = telemetry_mac.proxy_events_count_fields
    seen = []

    def fields(count, flags, run):
        seen.append(list(flags))
        return original(count, flags, run)

    monkeypatch.setattr(telemetry_mac, 'proxy_events_count_fields', fields)
    context._write_proxy_count_sidecar(tmp_path, 12, iter(['z', 'a']), 'run-binding')
    assert seen == [['a', 'z']]
    assert json.loads(path.read_text())['flags'] == ['a', 'z']
    assert mirror.call_args.kwargs['flags'] == ['a', 'z']

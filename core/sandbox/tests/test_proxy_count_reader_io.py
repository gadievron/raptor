"""Bounded sidecar reads tolerate short I/O and reject malformed fields."""
import json
import os

import pytest

from core.sandbox import context, proxy, telemetry_mac


import core.sandbox.context as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def sidecar(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: token == 'test-token')
    path = tmp_path / proxy.PROXY_EVENTS_COUNT_FILENAME
    path.write_text(json.dumps({'count': 4, 'flags': ['old'], 'mac': 'test-token'}))
    return path


def read(path):
    return context._read_proxy_count_sidecar(path.parent, 'test-run')


def test_short_reads_reach_eof(sidecar, monkeypatch):
    original = os.read
    calls = []

    def short(fd, size):
        calls.append(size)
        return original(fd, min(size, 3))

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'read', short)
    assert read(sidecar) == (4, {'old'}, False)
    assert len(calls) > 2


def test_read_stops_at_cap_plus_one(sidecar, monkeypatch):
    monkeypatch.setattr(context, '_COUNT_SIDECAR_MAX_BYTES', 16)
    sidecar.write_bytes(b'x' * 100)
    original = os.read
    consumed = []

    def short(fd, size):
        chunk = original(fd, min(size, 3))
        consumed.append(len(chunk))
        return chunk

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'read', short)
    assert read(sidecar) == (None, set(), True)
    assert sum(consumed) == 17


@pytest.mark.parametrize('payload', [
    {'count': True, 'flags': []}, {'count': -1, 'flags': []},
    {'count': '4', 'flags': []}, {'count': 4, 'flags': 7},
    {'count': 4, 'flags': 'old'}, {'count': 4, 'flags': {'old': 1}},
    {'count': 4, 'flags': [7]}, {'count': 4, 'flags': None},
])
def test_malformed_fields_rejected_before_mac(sidecar, monkeypatch, payload):
    sidecar.write_text(json.dumps({**payload, 'mac': 'test-token'}))

    def unexpected(*args):
        pytest.fail('malformed fields reached MAC processing')

    monkeypatch.setattr(telemetry_mac, 'proxy_events_count_fields', unexpected)
    assert read(sidecar) == (None, set(), True)


def test_recursion_error_is_invalid_sidecar(sidecar, monkeypatch):
    def too_deep(*args, **kwargs):
        raise RecursionError('decoder nesting limit')

    monkeypatch.setattr(json, 'loads', too_deep)
    assert read(sidecar) == (None, set(), True)


@pytest.mark.parametrize('read_fails', [False, True])
def test_close_error_does_not_mask_result(sidecar, monkeypatch, read_fails):
    original = os.close
    closed = []

    def close(fd):
        original(fd)
        closed.append(fd)
        raise OSError('close failed after release')

    if read_fails:
        def failed_read(*args):
            raise OSError('read failed')
        patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'read', failed_read)
    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'close', close)
    assert read(sidecar) == ((None, set(), True) if read_fails else (4, {'old'}, False))
    assert len(closed) == 1

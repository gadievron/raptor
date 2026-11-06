"""Later tamper events remain parseable after an interrupted predecessor."""
import json
import os
from unittest.mock import Mock

import pytest

from core.sandbox import telemetry_mac as mac


import core.sandbox.telemetry_mac as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def marker(tmp_path, monkeypatch):
    path = tmp_path / 'tamper.jsonl'
    monkeypatch.setattr(mac, 'tamper_marker_path', lambda: path)
    monkeypatch.setattr(mac.logger, 'warning', Mock())
    return path


@pytest.mark.parametrize('prefix', [1, 5, 20])
def test_valid_append_survives_partial_predecessor(marker, monkeypatch, prefix):
    original = os.write
    calls = []

    def short(fd, data):
        calls.append(bytes(data))
        return original(fd, data[:prefix])

    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, _os_fault_consumer, "os", 'write', short)
        mac._record_tamper_event('incomplete', 'first')
    assert len(calls) == 1
    mac._record_tamper_event('preserved', 'second')
    assert [event['reason'] for event in mac.tamper_events()] == ['preserved']
    assert json.loads(marker.read_bytes().splitlines()[-1])['quarantined_to'] == 'second'


def test_append_resynchronizes_preexisting_fragment(marker):
    # Models an earlier process that failed during its append.
    marker.write_bytes(b'{"reason":"unfinished')
    mac._record_tamper_event('later process', 'second')
    assert [event['reason'] for event in mac.tamper_events()] == ['later process']


def test_healthy_records_still_roundtrip(marker, monkeypatch):
    original = os.write
    writes = []

    def write(fd, data):
        writes.append(bytes(data))
        return original(fd, data)

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'write', write)
    mac._record_tamper_event('first', 'one')
    mac._record_tamper_event('second', 'two')
    assert [event['reason'] for event in mac.tamper_events()] == ['first', 'second']
    assert len(writes) == 2
    assert all(data.startswith(b'\n') and data.endswith(b'\n') for data in writes)

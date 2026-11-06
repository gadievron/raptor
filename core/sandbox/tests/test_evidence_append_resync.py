"""A failed append cannot consume the next successful JSONL record."""
import json
import os
import threading

import pytest

from core.sandbox import evidence


import core.sandbox.evidence as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


class Cancelled(BaseException):
    pass


@pytest.mark.parametrize('failure', ['short', 'error', 'cancel'])
def test_next_record_is_separate_after_partial_failure(tmp_path, monkeypatch, failure):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    original = os.write
    first = True
    calls = []

    def write(fd, data):
        nonlocal first
        calls.append(bytes(data))
        if first:
            first = False
            n = original(fd, data[:5])
            if failure == 'error':
                raise OSError('failure after progress')
            if failure == 'cancel':
                raise Cancelled('cancel after progress')
            return n
        return original(fd, data)

    try:
        patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'write', write)
        if failure == 'cancel':
            with pytest.raises(Cancelled):
                handle.write_record({'first': 'incomplete'})
        else:
            assert not handle.write_record({'first': 'incomplete'})
        assert handle.write_record({'second': 'preserved'})
        assert handle.write_record({'third': 'normal'})
        lines = handle.path.read_bytes().splitlines()
        assert json.loads(lines[-2]) == {'second': 'preserved'}
        assert json.loads(lines[-1]) == {'third': 'normal'}
        assert calls[1].startswith(b'\n')
        assert not calls[2].startswith(b'\n')
        assert len(calls) == 3  # no fragment retries
    finally:
        handle.close()


def test_resync_remains_pending_after_zero_progress(tmp_path, monkeypatch):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    original = os.write
    calls = []

    def write(fd, data):
        calls.append(bytes(data))
        if len(calls) == 1:
            return original(fd, data[:3])
        if len(calls) == 2:
            return 0
        return original(fd, data)

    try:
        patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'write', write)
        assert not handle.write_record({'first': 1})
        assert not handle.write_record({'second': 2})
        assert handle.write_record({'third': 3})
        assert calls[1].startswith(b'\n')
        assert calls[2].startswith(b'\n')
        assert json.loads(handle.path.read_bytes().splitlines()[-1]) == {'third': 3}
    finally:
        handle.close()


def test_recovery_state_is_set_before_another_writer_can_enter(tmp_path, monkeypatch):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    original = os.write
    failed = threading.Event()
    result = []

    def write(fd, data):
        if not failed.is_set():
            n = original(fd, data[:4])
            failed.set()
            return n
        return original(fd, data)

    def second_writer():
        assert failed.wait(2)
        result.append(handle.write_record({'second': 'preserved'}))

    thread = threading.Thread(target=second_writer)
    try:
        patch_module_attribute(monkeypatch, _os_fault_consumer, "os", 'write', write)
        thread.start()
        assert not handle.write_record({'first': 'incomplete'})
        thread.join(2)
        assert not thread.is_alive()
        assert result == [True]
        assert json.loads(handle.path.read_bytes().splitlines()[-1]) == {'second': 'preserved'}
    finally:
        thread.join(2)
        handle.close()

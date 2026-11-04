"""Malformed event PIDs cannot invoke special PID semantics or stop capture."""
import io
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox import seatbelt_audit as audit


@pytest.fixture
def owner(tmp_path):
    def lookup(pid):
        if pid > 0x7fffffff:
            raise OverflowError("PID does not fit pid_t")
        raise ProcessLookupError()

    getpgid = Mock(side_effect=lookup)
    streamer = audit.LogStreamer(tmp_path, require_scope=True, getpgid=getpgid,
                                 get_ppid=lambda pid: None)
    streamer._scope_pids.add(123)
    return streamer, getpgid


@pytest.mark.parametrize('pid', [0, -1, -123, True, False, 1 << 31, 10 ** 100])
def test_invalid_pid_is_rejected_before_process_lookup(owner, pid):
    streamer, getpgid = owner
    assert streamer._pid_in_scope_locked(pid) is False
    getpgid.assert_not_called()


def test_registered_pid_remains_in_scope(owner):
    streamer, getpgid = owner
    assert streamer._record_in_scope({'target_pid': 123}) is True
    getpgid.assert_not_called()


def test_maximum_pid_is_safe_to_query(owner):
    streamer, getpgid = owner
    assert streamer._record_in_scope({'target_pid': 0x7fffffff}) is False
    getpgid.assert_called_once_with(0x7fffffff)


def test_ambiguous_record_keeps_existing_suspect_admission(owner):
    streamer, getpgid = owner
    assert streamer._record_in_scope({'target_pid': 10 ** 100,
                                      'parse_ambiguous': True}) is True
    getpgid.assert_not_called()


def test_reader_continues_after_out_of_range_pid(owner, monkeypatch, caplog):
    streamer, _ = owner

    def line(pid):
        return json.dumps({'senderImagePath': audit.SANDBOX_KEXT_SENDER,
                           'eventMessage': f'Sandbox: tool({pid}) deny file-read-data /tmp/file'}) + '\n'

    streamer._proc = SimpleNamespace(stdout=io.StringIO(line(10 ** 100) + line(123)))
    captured = []

    def accept(record):
        if streamer._record_in_scope(record):
            captured.append(record)

    monkeypatch.setattr(streamer, '_filter_and_append', accept)
    streamer._read_loop()
    assert [record['target_pid'] for record in captured] == [123]
    assert 'reader thread crashed' not in caplog.text

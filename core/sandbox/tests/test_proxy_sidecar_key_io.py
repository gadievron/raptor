"""Key-creation I/O failures obey count-sidecar best-effort semantics."""
import errno
import os
import threading

import pytest

from core.sandbox import context, proxy, summary, telemetry_mac


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch):
    monkeypatch.setattr(summary, '_proxy_persist_state', {})
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})
    monkeypatch.setattr(context, '_PROXY_PERSIST_LOCK', threading.Lock())


@pytest.mark.parametrize('error', [errno.ENOSPC, errno.EACCES, errno.EIO])
def test_key_io_error_keeps_parent_mirror_and_old_sidecar(tmp_path, monkeypatch, caplog, error):
    path = tmp_path / proxy.PROXY_EVENTS_COUNT_FILENAME
    path.write_bytes(b'previous')

    def fail(fields):
        raise OSError(error, 'key creation unavailable')

    monkeypatch.setattr(telemetry_mac, 'mint', fail)
    context._write_proxy_count_sidecar(tmp_path, 7, {'earlier_failure'}, 'run')
    assert path.read_bytes() == b'previous'
    state = summary.get_proxy_persist_state(tmp_path)
    assert state['expected_count'] == 7
    assert state['flags'] == ['earlier_failure']
    assert 'could not write' in caplog.text


def test_append_refusal_and_key_failure_do_not_break_caller(tmp_path, monkeypatch):
    original = os.open
    log = tmp_path / proxy.PROXY_EVENTS_FILENAME

    def refused(path, *args, **kwargs):
        if os.fspath(path) == str(log):
            raise OSError(errno.EACCES, 'events unavailable')
        return original(path, *args, **kwargs)

    def key_failure(fields):
        raise OSError(errno.ENOSPC, 'key unavailable')

    monkeypatch.setattr(os, 'open', refused)
    monkeypatch.setattr(telemetry_mac, 'mint', key_failure)
    context._persist_proxy_events([{'host': 'example.test'}], output=tmp_path)
    state = summary.get_proxy_persist_state(tmp_path)
    assert 'persist_open_failure' in state['flags']
    lock = context._PROXY_PERSIST_LOCK
    assert lock.acquire(blocking=False)
    lock.release()


def test_key_cancellation_still_propagates(tmp_path, monkeypatch):
    cancellation = KeyboardInterrupt('cancel key creation')

    def cancel(fields):
        raise cancellation

    monkeypatch.setattr(telemetry_mac, 'mint', cancel)
    with pytest.raises(KeyboardInterrupt) as raised:
        context._write_proxy_count_sidecar(tmp_path, 7, set(), 'run')
    assert raised.value is cancellation
    assert summary.get_proxy_persist_state(tmp_path)['expected_count'] == 7

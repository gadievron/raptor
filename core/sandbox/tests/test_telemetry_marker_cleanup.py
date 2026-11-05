"""Marker descriptor cleanup cannot swallow primary errors or cancellation."""
from contextlib import contextmanager
import errno
import json
import os
from types import ModuleType

import pytest

from core.sandbox import telemetry_mac as tmac
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def marker(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    path = tmp_path / 'tamper.jsonl'
    path.write_text('{"reason":"first"}\n{"reason":"second"}\n')
    monkeypatch.setattr(tmac, 'tamper_marker_path', lambda: path)
    return path


def local_os(monkeypatch, **changes):
    private = ModuleType('marker_cleanup_os')
    vars(private).update(vars(os))
    vars(private).update(changes)
    monkeypatch.setattr(tmac, 'os', private)


@pytest.mark.parametrize('operation', ['read', 'write', 'read-stat', 'write-stat'])
@pytest.mark.parametrize('failure', ['error', 'cancel', 'io'])
def test_primary_failure_survives_secondary_close_error(marker, monkeypatch, caplog, operation, failure):
    error = (RuntimeError('primary marker failure') if failure == 'error' else
             KeyboardInterrupt('primary marker cancellation') if failure == 'cancel' else
             OSError(errno.EIO, 'primary marker I/O failure'))
    opened, closed = [], []

    def open_fd(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def close_fd(fd):
        closed.append(fd)
        os.close(fd)
        # Check before warning handlers can reuse the released number.
        with pytest.raises(OSError) as released:
            os.fstat(fd)
        assert released.value.errno == errno.EBADF
        raise OSError(errno.EIO, 'secondary marker close failure')

    def fstat(fd):
        if operation.endswith('-stat'):
            raise error
        return os.fstat(fd)

    def write(fd, data):
        os.write(fd, data[:5])
        raise error

    @contextmanager
    def fdopen(fd, *args, **kwargs):
        with os.fdopen(fd, *args, **kwargs) as stream:
            def records():
                yield next(stream)
                raise error
            yield records()

    local_os(monkeypatch, open=open_fd, close=close_fd, fstat=fstat,
             write=write, fdopen=fdopen)

    def invoke():
        if operation.startswith('read'):
            return tmac.tamper_events()
        return tmac._record_tamper_event('reason', 'quarantined')

    if failure == 'io':
        result = invoke()
        if operation.startswith('read'):
            assert result == ([{'reason': 'first'}] if operation == 'read' else [])
        else:
            assert 'could not append the key tamper marker' in caplog.text
    else:
        with pytest.raises(type(error)) as raised:
            invoke()
        assert raised.value is error
    assert len(opened) == 1
    assert closed == opened


@pytest.mark.parametrize('operation', ['read', 'write'])
@pytest.mark.parametrize('close_error', [False, True], ids=['clean-close', 'failed-close'])
def test_successful_io_retains_close_behavior(marker, monkeypatch, caplog, operation, close_error):
    closed = []

    def close(fd):
        closed.append(fd)
        os.close(fd)
        with pytest.raises(OSError) as released:
            os.fstat(fd)
        assert released.value.errno == errno.EBADF
        if close_error:
            raise OSError(errno.EIO, 'marker close failed')

    local_os(monkeypatch, close=close)
    if operation == 'read':
        assert tmac.tamper_events() == [{'reason': 'first'}, {'reason': 'second'}]
    else:
        tmac._record_tamper_event('new event', 'quarantined')
        assert json.loads(marker.read_text().splitlines()[-1])['reason'] == 'new event'
        assert ('could not append the key tamper marker' in caplog.text) is close_error
    assert len(closed) == 1

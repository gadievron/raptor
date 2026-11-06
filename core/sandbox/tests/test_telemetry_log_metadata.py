"""Key diagnostics retain outcomes without rendering native metadata controls."""

import errno
import logging
import os
from pathlib import Path
from types import ModuleType

import pytest

from core.sandbox import telemetry_mac as mac
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='native POSIX control paths')


class Cancelled(BaseException):
    pass


@pytest.fixture(params=['control', 'long'])
def owned(tmp_path, monkeypatch, request, caplog):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    data = tmp_path / CONTROL
    if request.param == 'long':
        data = data / ('a' * 100) / ('b' * 100)
    monkeypatch.setenv('XDG_DATA_HOME', str(data))
    monkeypatch.setattr(mac, '_warned_paths', set())
    private = ModuleType('telemetry_log_os')
    vars(private).update(vars(os))
    monkeypatch.setattr(mac, 'os', private)
    caplog.set_level(logging.DEBUG, logger=mac.logger.name)
    key = mac._key_path()
    key.parent.mkdir(parents=True)
    return key, private, request.param


def assert_safe(caplog, layout, label):
    records = [r for r in caplog.records if r.name == mac.logger.name]
    assert records
    assert any(label in r.getMessage() for r in records)
    for record in records:
        rendered = logging.Formatter('%(message)s').format(record)
        assert all(c.isprintable() for c in rendered)
        assert len(rendered) < 1200
        assert record.exc_info is None
        if layout == 'long':
            assert '...[+' in rendered


@pytest.mark.parametrize('scenario', [
    'open-refused', 'stable-short', 'quarantine-refused', 'quarantine',
    'marker-failed', 'publication', 'unlink-error', 'unlink-cancel',
    'close-error', 'close-cancel',
])
def test_key_failure_diagnostics(owned, monkeypatch, caplog, scenario):
    key, private, layout = owned
    detail = CONTROL + ('x' * 800 if layout == 'long' else '')
    if scenario == 'open-refused':
        key.write_bytes(b'k' * mac._KEY_LEN)
        key.chmod(0o600)

        def refuse(path, flags, *args):
            if Path(path) == key:
                raise PermissionError(errno.EACCES, detail, str(path))
            return os.open(path, flags, *args)

        private.open = refuse
        assert mac._load_or_create_key() is None
        assert mac._load_or_create_key() is None
        assert key.read_bytes() == b'k' * mac._KEY_LEN
        assert not list(key.parent.glob('*.tampered-*'))
        records = [r for r in caplog.records if r.name == mac.logger.name]
        assert [r.levelno for r in records] == [logging.WARNING, logging.DEBUG]
        assert_safe(caplog, layout, 'refusing key')
    elif scenario == 'stable-short':
        key.write_bytes(b'k')
        key.chmod(0o600)
        clock = ModuleType('telemetry_log_time')
        vars(clock).update(vars(mac.time))
        clock.sleep = lambda seconds: None
        monkeypatch.setattr(mac, 'time', clock)
        assert mac._load_or_create_key() is None
        assert key.read_bytes() == b'k'
        assert not list(key.parent.glob('*.tampered-*'))
        assert_safe(caplog, layout, 'creation-race retry budget')
    elif scenario in {'quarantine-refused', 'quarantine', 'marker-failed'}:
        original = b'k' * mac._KEY_LEN
        key.write_bytes(original)
        key.chmod(0o644)
        if scenario == 'quarantine-refused':
            def refuse_rename(source, dest):
                raise OSError(errno.EIO, detail, source)
            private.rename = refuse_rename
            assert mac._load_or_create_key() is None
            assert key.read_bytes() == original
            assert not list(key.parent.glob('*.tampered-*'))
            assert_safe(caplog, layout, 'quarantine failed')
            return
        if scenario == 'marker-failed':
            def refuse_marker(path, flags, *args):
                if Path(path) == mac.tamper_marker_path():
                    raise OSError(errno.EIO, detail, str(path))
                return os.open(path, flags, *args)
            private.open = refuse_marker
        fields = {'kind': 'test', 'detail': CONTROL}
        token = mac.mint(fields)
        assert token is not None
        assert mac.verify(fields, token)
        preserved = list(key.parent.glob('*.tampered-*'))
        assert len(preserved) == 1
        assert preserved[0].read_bytes() == original
        assert key.read_bytes() != original
        assert key.stat().st_mode & 0o077 == 0
        if scenario == 'quarantine':
            events = mac.tamper_events()
            assert len(events) == 1
            assert events[0]['quarantined_to'] == preserved[0].name
            assert 'mode 0644' in events[0]['reason']
        else:
            assert not mac.tamper_marker_path().exists()
        assert_safe(caplog, layout, 'KEY TAMPER')
    elif scenario == 'publication':
        def disappear(fd, data):
            count = os.write(fd, data)
            key.unlink()
            return count
        private.write = disappear
        assert mac._load_or_create_key() is None
        assert not key.exists()
        assert_safe(caplog, layout, 'publication verification')
        private.write = os.write
        token = mac.mint({'kind': 'test'})
        assert token is not None
        assert mac.verify({'kind': 'test'}, token)
    else:
        original = Cancelled(detail) if scenario.endswith('cancel') else OSError(errno.EIO, detail)
        opened, closed = [], []
        calls = 0

        def open_fd(*args, **kwargs):
            fd = os.open(*args, **kwargs)
            opened.append(fd)
            return fd

        def write(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return os.write(fd, data[:3])
            raise original

        def close(fd):
            os.close(fd)
            closed.append(fd)
            if scenario.startswith('close'):
                raise OSError(errno.EIO, detail, str(key))

        if scenario.startswith('unlink'):
            class CleanupPath(type(key)):
                def unlink(self, missing_ok=False):
                    raise OSError(errno.EIO, detail, str(self))
            monkeypatch.setattr(mac, '_key_path', lambda: CleanupPath(key))
        private.open, private.write, private.close = open_fd, write, close
        with pytest.raises(type(original)) as raised:
            mac._load_or_create_key()
        assert raised.value is original
        assert len(opened) == 1
        assert closed == opened
        with pytest.raises(OSError) as released:
            os.fstat(opened[0])
        assert released.value.errno == errno.EBADF
        if scenario.startswith('unlink'):
            assert key.read_bytes() and key.stat().st_size == 3
            label = 'incomplete key cleanup failed'
        else:
            assert not key.exists()
            label = 'key descriptor cleanup failed'
        assert_safe(caplog, layout, label)


def test_healthy_key_preserves_native_identity_and_metadata(owned, caplog):
    key, _private, _layout = owned
    fields = {'kind': 'test', 'detail': CONTROL}
    token = mac.mint(fields)
    assert token is not None
    assert mac.verify(fields, token)
    assert not mac.verify({**fields, 'detail': 'different'}, token)
    assert CONTROL in key.parts
    assert len(key.read_bytes()) == mac._KEY_LEN
    assert not list(key.parent.glob('*.tampered-*'))
    assert mac.tamper_events() == []
    assert not [r for r in caplog.records if r.name == mac.logger.name]

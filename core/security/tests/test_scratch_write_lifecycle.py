"""Private record writes retire their own descriptor and incomplete temporary."""
import errno
import os
from contextlib import suppress

import pytest

from core.security import scratch_lifecycle as lifecycle
from core.testing.module_bindings import patch_module_attribute


def test_failed_adoption_retires_descriptor_and_temporary(tmp_path, monkeypatch):
    original_open, original_close = os.open, os.close
    owners = []
    node = original_open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        primary = KeyboardInterrupt('owned adoption failure')

        def opened(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            owners.append(fd)
            return fd

        def adopt(*args, **kwargs):
            raise primary

        patch_module_attribute(monkeypatch, lifecycle, 'os', 'open', opened)
        patch_module_attribute(monkeypatch, lifecycle, 'os', 'fdopen', adopt)
        with pytest.raises(KeyboardInterrupt) as caught:
            lifecycle._write(node, 'record.json', {'owned': True})
        assert caught.value is primary
        assert len(owners) == 1
        with pytest.raises(OSError) as closed:
            os.fstat(owners[0])
        assert closed.value.errno == errno.EBADF
        assert list(tmp_path.iterdir()) == []
    finally:
        for fd in owners:
            with suppress(OSError):
                original_close(fd)
        original_close(node)


@pytest.mark.parametrize('phase', ['write', 'flush', 'sync', 'close', 'replace'])
@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt])
def test_primary_failure_keeps_previous_record_and_retires_owned_state(
    tmp_path, monkeypatch, phase, error_type,
):

    path = tmp_path / 'record.json'
    path.write_text('{"previous":true}')
    original_open, original_close, original_adopt = os.open, os.close, os.fdopen
    original_unlink, original_sync = os.unlink, os.fsync
    owners, closed, streams, unlinked = [], [], [], []
    node = original_open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        primary = error_type('owned record failure')

        class Stream:
            def __init__(self, raw):
                self.raw = raw
                self.closes = 0
            def write(self, data):
                if phase == 'write':
                    raise primary
                return self.raw.write(data)
            def flush(self):
                if phase == 'flush':
                    raise primary
                self.raw.flush()
            def fileno(self):
                return self.raw.fileno()
            def close(self):
                self.closes += 1
                self.raw.close()
                if phase == 'close':
                    raise primary
                if phase in ('write', 'flush', 'sync'):
                    raise RuntimeError('secondary stream close')

        def opened(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            info = os.fstat(fd)
            owners.append((fd, (info.st_dev, info.st_ino)))
            return fd

        def adopt(fd, *args, **kwargs):
            assert kwargs['closefd'] is False
            stream = Stream(original_adopt(fd, *args, **kwargs))
            streams.append(stream)
            return stream

        def close(fd):
            original_close(fd)
            closed.append(fd)
            if phase != 'replace':
                raise RuntimeError('secondary raw close')

        def sync(fd):
            if phase == 'sync':
                raise primary
            original_sync(fd)

        def replace(*args, **kwargs):
            raise primary

        def unlink(name, **kwargs):
            original_unlink(name, **kwargs)
            unlinked.append(name)
            raise RuntimeError('secondary unlink')

        for name, value in [('open', opened), ('fdopen', adopt), ('close', close),
                            ('fsync', sync), ('replace', replace), ('unlink', unlink)]:
            patch_module_attribute(monkeypatch, lifecycle, 'os', name, value)
        with pytest.raises(error_type) as caught:
            lifecycle._write(node, 'record.json', {'next': True})
        assert caught.value is primary
        assert path.read_text() == '{"previous":true}'
        assert sorted(p.name for p in tmp_path.iterdir()) == ['record.json']
        assert len(owners) == len(streams) == len(closed) == len(unlinked) == 1
        assert streams[0].closes == 1 and streams[0].raw.closed
        with pytest.raises(OSError) as retired:
            os.fstat(owners[0][0])
        assert retired.value.errno == errno.EBADF
    finally:
        for stream in streams:
            stream.raw.close()
        for fd, identity in owners:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                original_close(fd)
        original_close(node)


def test_success_syncs_file_then_published_directory(tmp_path, monkeypatch):
    import json

    node = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        real_sync = os.fsync
        seen = []

        def sync(fd):
            seen.append((fd == node, (tmp_path / 'record.json').exists()))
            real_sync(fd)

        patch_module_attribute(monkeypatch, lifecycle, 'os', 'fsync', sync)
        lifecycle._write(node, 'record.json', {'owned': True})
    finally:
        os.close(node)
    assert seen == [(False, False), (True, True)]
    assert json.loads((tmp_path / 'record.json').read_text()) == {'owned': True}
    assert sorted(p.name for p in tmp_path.iterdir()) == ['record.json']


def test_exclusive_open_failure_keeps_existing_temporary(tmp_path, monkeypatch):
    token = 'a' * 32
    collision = tmp_path / ('.write-' + token)
    collision.write_bytes(b'previous owned temporary')
    patch_module_attribute(monkeypatch, lifecycle, 'secrets', 'token_hex', lambda size: token)
    node = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FileExistsError):
            lifecycle._write(node, 'record.json', {'owned': True})
    finally:
        os.close(node)
    assert collision.read_bytes() == b'previous owned temporary'
    assert not (tmp_path / 'record.json').exists()


def test_directory_sync_failure_does_not_remove_published_record(tmp_path, monkeypatch):
    import json

    node = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        original_sync = os.fsync
        primary = OSError('directory sync failed')

        def sync(fd):
            if fd == node:
                raise primary
            original_sync(fd)

        patch_module_attribute(monkeypatch, lifecycle, 'os', 'fsync', sync)
        with pytest.raises(OSError) as caught:
            lifecycle._write(node, 'record.json', {'owned': True})
        assert caught.value is primary
    finally:
        os.close(node)
    assert json.loads((tmp_path / 'record.json').read_text()) == {'owned': True}
    assert sorted(p.name for p in tmp_path.iterdir()) == ['record.json']

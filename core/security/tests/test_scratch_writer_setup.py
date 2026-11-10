"""Standalone scratch writers own descriptors before native stream adoption."""
import errno
import os
from types import SimpleNamespace

import pytest

from core.security import launch_scratch, scratch_lifecycle
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state


@pytest.fixture
def writer(tmp_path, monkeypatch):
    registry = tmp_path / 'registry'
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(registry))
    root = (tmp_path / f'raptor-{os.geteuid()}' / f'session-{os.getpid()}-123').resolve()
    root.parent.mkdir(mode=0o700)
    root.mkdir(mode=0o700)
    authority = tmp_path / 'authority'

    def prepare(operation):
        if operation == 'create':
            owner, invoke = launch_scratch, lambda: launch_scratch.create(root)
        else:
            metadata = launch_scratch.create(root)
            if operation == 'issue':
                owner, invoke = launch_scratch, lambda: launch_scratch.issue(authority, metadata, os.getpid())
            else:
                owner, invoke = scratch_lifecycle, lambda: scratch_lifecycle.register(metadata, os.getpid())
        return SimpleNamespace(owner=owner, invoke=invoke, root=root, authority=authority, registry=registry)

    with isolated_module_state(scratch_lifecycle, {'_scratch_module': None}):
        yield prepare


@pytest.mark.parametrize('operation', ['create', 'issue', 'register'])
@pytest.mark.parametrize('error_type', [RuntimeError, OSError, KeyboardInterrupt, SystemExit])
def test_failed_writer_adoption_retires_raw_descriptor(writer, monkeypatch, operation, error_type):
    state = writer(operation)
    primary = error_type('owned writer adoption failed')
    owners = []
    real_close = os.close

    def fail(fd, *args, **kwargs):
        info = os.fstat(fd)
        owners.append((fd, (info.st_dev, info.st_ino)))
        raise primary

    patch_module_attribute(monkeypatch, state.owner, 'os', 'fdopen', fail)
    try:
        with pytest.raises(error_type) as caught:
            state.invoke()
        assert caught.value is primary
        assert len(owners) == 1
        with pytest.raises(OSError) as retired:
            os.fstat(owners[0][0])
        assert retired.value.errno == errno.EBADF
        if operation == 'create':
            assert (state.root / 'metadata/launch.json').is_file()
        elif operation == 'register':
            assert (state.root / 'metadata/session-id').is_file()
            assert not state.registry.exists()
        else:
            assert len(list(state.authority.rglob(str(os.getpid())))) == 1
    finally:
        for fd, identity in owners:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                real_close(fd)


@pytest.mark.parametrize('operation', ['create', 'issue', 'register'])
@pytest.mark.parametrize('phase', ['write', 'close'])
@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt])
def test_write_error_keeps_priority_across_independent_cleanup(
    writer, monkeypatch, operation, phase, error_type,
):
    state = writer(operation)
    real_adopt, real_close = os.fdopen, os.close
    primary = error_type('owned writer failure')
    owners, wrappers, closes = {}, [], []

    class Writer:
        def __init__(self, raw):
            self.raw = raw
            self.closes = 0
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.close()
        def write(self, data):
            if phase == 'write':
                raise primary
            return self.raw.write(data)
        def flush(self):
            return self.raw.flush()
        def fileno(self):
            return self.raw.fileno()
        def close(self):
            self.closes += 1
            self.raw.close()
            if phase == 'close':
                raise primary
            raise RuntimeError('secondary stream close')

    def adopt(fd, *args, **kwargs):
        assert kwargs['closefd'] is False
        info = os.fstat(fd)
        owners[fd] = (info.st_dev, info.st_ino)
        wrapper = Writer(real_adopt(fd, *args, **kwargs))
        wrappers.append(wrapper)
        return wrapper

    def close(fd):
        real_close(fd)
        if fd in owners:
            closes.append(fd)
            raise RuntimeError('secondary descriptor close')

    patch_module_attribute(monkeypatch, state.owner, 'os', 'fdopen', adopt)
    patch_module_attribute(monkeypatch, state.owner, 'os', 'close', close)
    try:
        with pytest.raises(error_type) as caught:
            state.invoke()
        assert caught.value is primary
        assert len(owners) == len(wrappers) == len(closes) == 1
        assert wrappers[0].closes == 1 and wrappers[0].raw.closed
        for fd in owners:
            with pytest.raises(OSError) as retired:
                os.fstat(fd)
            assert retired.value.errno == errno.EBADF
    finally:
        for wrapper in wrappers:
            wrapper.raw.close()
        for fd, identity in owners.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                real_close(fd)


@pytest.mark.parametrize('operation', ['create', 'issue', 'register'])
def test_success_keeps_private_native_records_and_reservation_contract(writer, operation):
    import json
    import stat
    from pathlib import Path

    state = writer(operation)
    result = state.invoke()
    if operation == 'create':
        path = result
        data = json.loads(path.read_text())
        assert data == {'v': 1, 'tmpdir': str(state.root / 'tmp'), 'protected': False}
    elif operation == 'issue':
        packet = json.loads(result)
        path = Path(packet['entry'])
        data = json.loads(path.read_text())
        assert data['v'] == 1 and data['metadata'] == str(state.root / 'metadata/launch.json')
        assert len(data['token']) == 64 and data['identity']
    else:
        path = state.root / 'metadata/session-id'
        assert path.read_text() == result
        records = list(scratch_lifecycle.records())
        assert len(records) == 1
        assert records[0]['id'] == result and records[0]['state'] == 'retained'
        assert records[0]['root'] == str(state.root)
    info = path.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.geteuid() and info.st_nlink == 1


def test_record_writer_helper_failure_allocates_no_file(tmp_path, monkeypatch):
    real_open, real_close = os.open, os.close
    owners = {}
    node = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        primary = RuntimeError('adjacent helper unavailable')

        def unavailable():
            raise primary

        def opened(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            info = os.fstat(fd)
            owners[fd] = (info.st_dev, info.st_ino)
            return fd

        monkeypatch.setattr(scratch_lifecycle, 'scratch', unavailable)
        patch_module_attribute(monkeypatch, scratch_lifecycle, 'os', 'open', opened)
        with pytest.raises(RuntimeError) as caught:
            scratch_lifecycle._write(node, 'record.json', {'owned': True})
        assert caught.value is primary
        assert owners == {} and list(tmp_path.iterdir()) == []
    finally:
        for fd, identity in owners.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                real_close(fd)
        real_close(node)

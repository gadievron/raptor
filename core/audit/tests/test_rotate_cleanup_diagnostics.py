"""Secondary cleanup diagnostics cannot replace a rotation failure."""

import io
import os
from types import FunctionType, SimpleNamespace

import pytest

from core.audit import audit_log_rotate as rotation
from core.audit import record
from core.source import streams


@pytest.mark.parametrize('stage', ['close', 'unlink'])
@pytest.mark.parametrize('primary_type,diagnostic_type', [
    pytest.param(OSError, OSError, id='ordinary'),
    pytest.param(OSError, MemoryError, id='diagnostic-memory'),
    pytest.param(OSError, KeyboardInterrupt, id='diagnostic-interrupt'),
    pytest.param(OSError, SystemExit, id='diagnostic-exit'),
    pytest.param(KeyboardInterrupt, OSError, id='primary-interrupt'),
    pytest.param(SystemExit, KeyboardInterrupt, id='primary-exit'),
])
def test_native_cleanup_keeps_primary_and_attempts_remaining_temps(
    tmp_path, monkeypatch, stage, primary_type, diagnostic_type,
):
    # The same small fixture budgets as existing remedy tests: exercise
    # multiple native owners without copying a production-size log.
    for module in (rotation, record):
        monkeypatch.setattr(module, '_AUDIT_LOG_MAX_BYTES', 2048)
        monkeypatch.setattr(module, '_AUDIT_LOG_SHARD_ROLL_BYTES', 1536)
    payload = b'owned log row\n' * 400
    source = tmp_path / record.AUDIT_LOG_FILENAME
    source.write_bytes(payload)
    primary = primary_type('primary native sync failure')
    diagnostic = diagnostic_type('secondary cleanup diagnostic failure')
    state = {'syncs': 0, 'failed': False, 'warnings': 0, 'unlinks': [], 'writers': []}

    def fsync(fd):
        os.fsync(fd)
        state['syncs'] += 1
        if state['syncs'] == 3:
            state['failed'] = True
            raise primary

    def writer(raw):
        class Writer(io.BufferedWriter):
            def close(self):
                if self.closed:
                    return
                super().close()
                if state['failed'] and stage == 'close':
                    raise OSError('native close consumed')

        stream = Writer(raw)
        state['writers'].append(stream)
        return stream

    def fdopen(fd, mode, **kwargs):
        if mode != 'wb':
            return os.fdopen(fd, mode, **kwargs)
        return writer(io.FileIO(fd, mode, closefd=kwargs.get('closefd', True)))

    def native_open(path, mode, **kwargs):
        stream = io.open(path, mode, **kwargs)
        return writer(stream.detach()) if mode == 'wb' else stream

    # The predecessor's adoption helper now owns native setup. Keep its
    # real implementation, isolating only this consumer's native writer.
    bindings = dict(streams.adopt_fd.__globals__)
    bindings['io'] = SimpleNamespace(**{**vars(io), 'open': native_open})
    adopt = FunctionType(streams.adopt_fd.__code__, bindings,
                         streams.adopt_fd.__name__, streams.adopt_fd.__defaults__)
    adopt.__kwdefaults__ = streams.adopt_fd.__kwdefaults__
    monkeypatch.setattr(rotation, 'adopt_fd', adopt)

    class OwnedPath(type(tmp_path)):
        def unlink(self, *args, **kwargs):
            if self.name.startswith(rotation._TMP_PREFIX):
                state['unlinks'].append(self.name)
                if stage == 'unlink' and self.name.endswith('001'):
                    raise PermissionError('owned temporary retained')
            return super().unlink(*args, **kwargs)

    class DiagnosticLogger:
        def warning(self, *args, **kwargs):
            state['warnings'] += 1
            raise diagnostic

    monkeypatch.setattr(rotation, 'os', SimpleNamespace(
        **{**vars(os), 'fsync': fsync, 'fdopen': fdopen},
    ))
    monkeypatch.setattr(rotation, 'Path', OwnedPath)
    monkeypatch.setattr(rotation, 'logger', DiagnosticLogger())
    try:
        with pytest.raises(primary_type) as raised:
            rotation.rotate_audit_log(tmp_path)
        assert raised.value is primary
        assert state['syncs'] == 3 and state['warnings'] == 1
        assert state['unlinks'] == [rotation._TMP_PREFIX + f'{i:03d}' for i in range(1, 4)]
        assert all(stream.closed for stream in state['writers'])
        assert source.read_bytes() == payload
        assert not list(tmp_path.glob('*.pre-rotate*'))
        remaining = sorted(p.name for p in tmp_path.glob(rotation._TMP_PREFIX + '*'))
        assert remaining == ([rotation._TMP_PREFIX + '001'] if stage == 'unlink' else [])
    finally:
        state['failed'] = False
        for stream in state['writers']:
            if not stream.closed:
                stream.close()
        # A real failed unlink is not cleanup success; the fixture owns
        # and retires any intentionally retained native temporary.
        for path in tmp_path.glob(rotation._TMP_PREFIX + '*'):
            path.unlink()


@pytest.mark.parametrize('stage', ['unlink', 'restore'])
@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
def test_rollback_diag_keeps_primary_and_restores_remaining(tmp_path, monkeypatch, stage, primary_type):
    for module in (rotation, record):
        monkeypatch.setattr(module, '_AUDIT_LOG_MAX_BYTES', 2048)
        monkeypatch.setattr(module, '_AUDIT_LOG_SHARD_ROLL_BYTES', 1536)
    first = tmp_path / record.AUDIT_LOG_FILENAME
    second = tmp_path / record._audit_log_shard_name(2)
    first_bytes, second_bytes = b'owned first row\n' * 150, b'owned second row\n' * 150
    first.write_bytes(first_bytes)
    second.write_bytes(second_bytes)
    backup_second = second.with_name(second.name + rotation._BACKUP_SUFFIX)
    primary = primary_type('primary native publish failure')
    state = {'renames': 0, 'failed': False, 'diagnostics': 0}

    def rename(src, dst):
        state['renames'] += 1
        if state['renames'] == 4:
            state['failed'] = True
            raise primary
        if stage == 'restore' and state['renames'] == 5:
            raise PermissionError('restore backup retained')
        return os.rename(src, dst)

    class OwnedPath(type(tmp_path)):
        def unlink(self, *args, **kwargs):
            if stage == 'unlink' and state['failed'] and self.name == first.name:
                raise PermissionError('published owned shard still present')
            return super().unlink(*args, **kwargs)

    class DiagnosticLogger:
        def exception(self, *args, **kwargs):
            state['diagnostics'] += 1
            raise MemoryError('secondary rollback diagnostic failure')

    monkeypatch.setattr(rotation, 'os', SimpleNamespace(**{**vars(os), 'rename': rename}))
    monkeypatch.setattr(rotation, 'Path', OwnedPath)
    monkeypatch.setattr(rotation, 'logger', DiagnosticLogger())
    try:
        with pytest.raises(primary_type) as raised:
            rotation.rotate_audit_log(tmp_path)
        assert raised.value is primary
        assert state['diagnostics'] == 1
        assert first.read_bytes() == first_bytes
        if stage == 'restore':
            assert not second.exists()
            assert backup_second.read_bytes() == second_bytes
        else:
            assert second.read_bytes() == second_bytes
            assert not backup_second.exists()
        assert not list(tmp_path.glob(rotation._TMP_PREFIX + '*'))
    finally:
        # A deliberately failed restore retains its exact native backup.
        if backup_second.exists():
            os.rename(backup_second, second)


@pytest.mark.parametrize('diagnostic_type', [OSError, KeyboardInterrupt])
def test_fresh_cleanup_diagnostic_after_success_still_propagates(tmp_path, monkeypatch, diagnostic_type):
    for module in (rotation, record):
        monkeypatch.setattr(module, '_AUDIT_LOG_MAX_BYTES', 2048)
        monkeypatch.setattr(module, '_AUDIT_LOG_SHARD_ROLL_BYTES', 1536)
    source = tmp_path / record.AUDIT_LOG_FILENAME
    payload = b'owned successful row\n' * 200
    source.write_bytes(payload)
    diagnostic = diagnostic_type('fresh post-swap diagnostic failure')

    class OwnedPath(type(tmp_path)):
        def unlink(self, *args, **kwargs):
            if self.name == rotation._TMP_PREFIX + '001':
                raise PermissionError('fresh temporary cleanup failure')
            return super().unlink(*args, **kwargs)

    class DiagnosticLogger:
        def warning(self, *args, **kwargs):
            raise diagnostic

    monkeypatch.setattr(rotation, 'Path', OwnedPath)
    monkeypatch.setattr(rotation, 'logger', DiagnosticLogger())
    with pytest.raises(diagnostic_type) as raised:
        rotation.rotate_audit_log(tmp_path)
    assert raised.value is diagnostic
    assert b''.join(path.read_bytes() for path in record.audit_log_paths(tmp_path)) == payload
    assert source.with_name(source.name + rotation._BACKUP_SUFFIX).read_bytes() == payload

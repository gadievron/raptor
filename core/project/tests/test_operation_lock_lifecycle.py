"""Operation locks must not hang on special nodes or lose ownership on failure."""
import errno
import os
from pathlib import Path
import sys

import pytest
from core.testing.standalone_cli import run_standalone_cli
from core.project import oplock
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(not oplock._HAS_FCNTL, reason='requires flock')


@pytest.mark.parametrize('kind', ['fifo', 'directory', 'symlink', 'dangling'])
@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
def test_special_lock_nodes_are_never_stamped(tmp_path, kind, required):
    target = tmp_path / 'borrowed'
    target.write_text('operator data')
    path = tmp_path / '.op.lock'
    if kind == 'fifo':
        os.mkfifo(path)
    elif kind == 'directory':
        path.mkdir()
    else:
        path.symlink_to(target if kind == 'symlink' else tmp_path / 'absent')
    identity = path.lstat().st_ino
    entered = []
    if required:
        with pytest.raises(OSError):
            with oplock.project_op_lock(tmp_path, 'probe', required=True):
                entered.append(True)
    else:
        with oplock.project_op_lock(tmp_path, 'probe') as held:
            entered.append(True)
            assert held is None
    assert entered == ([] if required else [True])
    assert path.lstat().st_ino == identity
    assert target.read_text() == 'operator data'


@pytest.mark.parametrize('kind', ['fifo', 'directory', 'symlink', 'dangling', 'oversized'])
def test_unusable_holder_stamps_are_nonblocking_unknowns(tmp_path, kind):
    path = tmp_path / 'holder'
    if kind == 'fifo':
        os.mkfifo(path)
    elif kind == 'directory':
        path.mkdir()
    elif kind in ('symlink', 'dangling'):
        target = tmp_path / 'target'
        if kind == 'symlink':
            target.write_text('{"pid":123}')
        path.symlink_to(target)
    else:
        path.write_bytes(b' ' * (oplock._HOLDER_STAMP_MAX_BYTES + 1))
    script = '''
import sys
from pathlib import Path
from core.project.oplock import read_holder
assert read_holder(Path(sys.argv[1])) == {}
'''
    result = run_standalone_cli([sys.executable, '-c', script, str(path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
def test_unavailable_backend_obeys_required_policy(tmp_path, monkeypatch, required):
    monkeypatch.setattr(oplock, '_HAS_FCNTL', False)
    if required:
        with pytest.raises(OSError) as error:
            with oplock.project_op_lock(tmp_path, 'probe', required=True):
                pytest.fail('required lock must not enter without a backend')
        assert error.value.errno == errno.ENOTSUP
    else:
        with oplock.project_op_lock(tmp_path, 'probe') as held:
            assert held is None
    assert not (tmp_path / '.op.lock').exists()


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('close_failure', [None, OSError, KeyboardInterrupt],
                         ids=['close-ok', 'close-io-error', 'close-cancel'])
def test_failed_descriptor_validation_closes_fd_and_preserves_primary(tmp_path, monkeypatch, failure, close_failure):
    opened = []
    real_open, real_close = os.open, os.close
    def opened_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd
    def closed_fd(fd):
        real_close(fd)
        if close_failure:
            raise close_failure('secondary close failure')
    def invalid(*args):
        raise failure('validation failed')
    patch_module_attribute(monkeypatch, oplock, 'os', 'open', opened_fd)
    patch_module_attribute(monkeypatch, oplock, 'os', 'close', closed_fd)
    monkeypatch.setattr(oplock, 'validate_lock_fd', invalid)
    with pytest.raises(failure, match='validation failed'):
        with oplock.project_op_lock(tmp_path, 'probe', required=True):
            pytest.fail('invalid lock must not enter')
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


@pytest.mark.parametrize('body_failure', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('stage', ['unlock', 'close'])
def test_body_failure_keeps_precedence_over_teardown(tmp_path, monkeypatch, body_failure, cleanup_failure, stage):
    real_flock, real_close = oplock.fcntl.flock, os.close
    def unlock(fd, operation):
        result = real_flock(fd, operation)
        if operation == oplock.fcntl.LOCK_UN:
            raise cleanup_failure('secondary unlock failure')
        return result
    def close(fd):
        real_close(fd)
        raise cleanup_failure('secondary close failure')
    if stage == 'unlock':
        patch_module_attribute(monkeypatch, oplock, 'fcntl', 'flock', unlock)
    else:
        patch_module_attribute(monkeypatch, oplock, 'os', 'close', close)
    held = None
    with pytest.raises(body_failure, match='body failed'):
        with oplock.project_op_lock(tmp_path, 'probe', required=True) as held:
            raise body_failure('body failed')
    with pytest.raises(OSError):
        os.fstat(held)


@pytest.mark.parametrize('cleanup_failure', [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('stage', ['unlock', 'close'])
def test_new_cancellation_during_successful_teardown_propagates(tmp_path, monkeypatch, cleanup_failure, stage):
    real_flock, real_close = oplock.fcntl.flock, os.close
    def unlock(fd, operation):
        result = real_flock(fd, operation)
        if operation == oplock.fcntl.LOCK_UN:
            raise cleanup_failure('stop teardown')
        return result
    def close(fd):
        real_close(fd)
        raise cleanup_failure('stop teardown')
    if stage == 'unlock':
        patch_module_attribute(monkeypatch, oplock, 'fcntl', 'flock', unlock)
    else:
        patch_module_attribute(monkeypatch, oplock, 'os', 'close', close)
    held = None
    with pytest.raises(cleanup_failure, match='stop teardown'):
        with oplock.project_op_lock(tmp_path, 'probe', required=True) as held:
            pass
    with pytest.raises(OSError):
        os.fstat(held)


@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
def test_persistently_replaced_lock_never_claims_stable_ownership(tmp_path, monkeypatch, required):
    original = os.lstat
    def changed(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if Path(path).name == '.op.lock':
            values = list(info)
            values[1] += 1
            return os.stat_result(values)
        return info
    patch_module_attribute(monkeypatch, oplock, 'os', 'lstat', changed)
    if required:
        with pytest.raises(OSError, match='did not stabilize'):
            with oplock.project_op_lock(tmp_path, 'probe', required=True):
                pytest.fail('unstable lock must not enter in required mode')
    else:
        with oplock.project_op_lock(tmp_path, 'probe') as held:
            assert held is None

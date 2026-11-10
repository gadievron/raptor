"""Legacy display-state reads retain parent-FD error precedence and privacy."""

import errno
import json
import os
from types import SimpleNamespace

import pytest

from core.project import session_titles as policy


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    directory = tmp_path / 'owned-legacy'
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / 'owned.json'
    value = policy._initial_state()
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    state = {'directory': directory, 'path': path, 'value': value, 'live': set(),
             'closes': 0, 'decodes': 0, 'reads': [], 'read_primary': None,
             'metadata_error': None, 'close_error': None}
    real_read = policy._read_capped_or_raise
    real_loads = policy.loads

    def open_parent(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['live'].add(fd)
        state['fd'] = fd
        return fd

    def fstat(fd):
        result = os.fstat(fd)
        if state['metadata_error'] is not None:
            raise state['metadata_error']
        return result

    def close(fd):
        os.close(fd)
        state['live'].remove(fd)
        state['closes'] += 1
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
        if state['close_error'] is not None:
            raise state['close_error']

    def read(*args, **kwargs):
        state['reads'].append((args, kwargs.copy()))
        try:
            return real_read(*args, **kwargs)
        except BaseException as primary:
            state['read_primary'] = primary
            raise

    def loads(*args, **kwargs):
        state['decodes'] += 1
        assert state['closes'] == 1
        return real_loads(*args, **kwargs)

    monkeypatch.setattr(policy, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_parent, 'fstat': fstat, 'close': close},
    ))
    monkeypatch.setattr(policy, '_read_capped_or_raise', read)
    monkeypatch.setattr(policy, 'loads', loads)
    try:
        yield state
    finally:
        for fd in tuple(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def read_legacy(state):
    return policy._legacy_state(state['directory'], state['path'].name)


def assert_retired(state):
    assert state['closes'] == 1 and not state['live']


def test_native_directory_privacy_refusal_survives_close(legacy):
    legacy['directory'].chmod(0o755)
    legacy['close_error'] = OSError('native parent close consumed')
    with pytest.raises(PermissionError, match='directory must be private'):
        read_legacy(legacy)
    assert not legacy['reads'] and legacy['decodes'] == 0
    assert_retired(legacy)


@pytest.mark.parametrize('primary_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_native_parent_metadata_primary_survives_close(legacy, primary_type):
    primary = primary_type('parent metadata failed')
    legacy['metadata_error'] = primary
    legacy['close_error'] = OSError('native parent close consumed')
    with pytest.raises(primary_type) as raised:
        read_legacy(legacy)
    assert raised.value is primary
    assert legacy['decodes'] == 0
    assert_retired(legacy)


@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'oversized'])
def test_native_child_refusal_survives_parent_close(legacy, tmp_path, kind):
    legacy['path'].unlink()
    if kind == 'symlink':
        target = tmp_path / 'owned-target'
        target.write_text('{}')
        legacy['path'].symlink_to(target)
    elif kind == 'fifo':
        os.mkfifo(legacy['path'], 0o600)
    else:
        legacy['path'].write_bytes(b'x' * 4097)
        legacy['path'].chmod(0o600)
    legacy['close_error'] = OSError('native parent close consumed')
    with pytest.raises(Exception) as raised:
        read_legacy(legacy)
    assert raised.value is legacy['read_primary']
    assert legacy['decodes'] == 0
    assert_retired(legacy)


@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_parent_close_error_refuses_before_decode(legacy, cleanup_type):
    failure = cleanup_type('native parent close consumed')
    legacy['close_error'] = failure
    with pytest.raises(cleanup_type) as raised:
        read_legacy(legacy)
    assert raised.value is failure
    assert len(legacy['reads']) == 1 and legacy['decodes'] == 0
    assert_retired(legacy)


@pytest.mark.parametrize('cleanup_type', [None, OSError, KeyboardInterrupt])
def test_missing_child_retains_fresh_parent_close_policy(legacy, cleanup_type):
    legacy['path'].unlink()
    if cleanup_type is None:
        assert read_legacy(legacy) is None
    else:
        failure = cleanup_type('native parent close consumed')
        legacy['close_error'] = failure
        with pytest.raises(cleanup_type) as raised:
            read_legacy(legacy)
        assert raised.value is failure
    assert legacy['decodes'] == 0
    assert_retired(legacy)


@pytest.mark.parametrize('close_fails', [False, True])
def test_file_privacy_check_remains_after_parent_close(legacy, close_fails):
    legacy['path'].chmod(0o644)
    if close_fails:
        failure = OSError('fresh native parent close consumed')
        legacy['close_error'] = failure
        with pytest.raises(OSError) as raised:
            read_legacy(legacy)
        assert raised.value is failure
    else:
        with pytest.raises(PermissionError, match='file must be private'):
            read_legacy(legacy)
    assert legacy['decodes'] == 0
    assert_retired(legacy)


def test_native_private_state_retains_pin_cap_and_shape(legacy):
    assert read_legacy(legacy) == legacy['value']
    assert legacy['decodes'] == 1
    args, kwargs = legacy['reads'][0]
    assert args[1] == 4096
    assert kwargs == {'follow_symlinks': False, 'dir_fd': legacy['fd']}
    assert_retired(legacy)


def test_missing_legacy_parent_remains_absent(legacy):
    legacy['directory'] = legacy['directory'] / 'absent'
    assert read_legacy(legacy) is None
    assert legacy['closes'] == legacy['decodes'] == 0 and not legacy['live']

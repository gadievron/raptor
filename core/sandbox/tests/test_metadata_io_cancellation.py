"""Metadata descriptor cleanup preserves cancellation and close-only failures."""

import errno
import json
import os
from types import ModuleType

import pytest

from core.sandbox import calibrate as cal, disable_consent as dc, host_consent as hc
from core.testing.state_isolation import pin_user_state_dirs


class Cancelled(BaseException):
    pass


OPERATIONS = ['cache-stat', 'cache-read', 'host-stat', 'host-read',
              'nonce-stat', 'nonce-read', 'nonce-write']


@pytest.fixture
def owned(tmp_path, monkeypatch, request):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    monkeypatch.setattr(cal, '_CACHE_DIR', tmp_path / 'cache')
    cal._CACHE_DIR.mkdir()
    profile = cal.SandboxProfile('/owned/tool', 'hash', 'env', 'timestamp')
    cache = cal._CACHE_DIR / 'entry.json'
    cache.write_text(profile.to_json())
    marker = tmp_path / 'marker.json'
    marker.write_text(json.dumps({'schema': 1, 'owned': 'marker'}))
    marker.chmod(0o600)
    monkeypatch.setattr(hc, 'marker_path', lambda: marker)
    nonce = 'a' * dc.NONCE_HEX_LEN
    consents = tmp_path / 'consents'
    consents.mkdir()
    consent = consents / dc._nonce_filename(nonce)
    consent.write_text(dc._nonce_digest(nonce) + '\n')
    consent.chmod(0o600)
    monkeypatch.setattr(dc, '_consents_dir', lambda: consents)
    mint_dir = tmp_path / 'mint'
    opened, closed, released = [], [], set()
    close_error = OSError(errno.EIO, 'owned close failure')
    controls = {'close_fails': False, 'primary': None, 'phase': None}

    def release_if_needed(fd):
        if fd not in released:
            os.close(fd)
            released.add(fd)

    def open_fd(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        # Register ownership before any later operation can fail.
        request.addfinalizer(lambda: release_if_needed(fd))
        released.discard(fd)
        opened.append(fd)
        return fd

    def close(fd):
        os.close(fd)
        released.add(fd)
        closed.append(fd)
        if controls['close_fails']:
            raise close_error

    def fault(phase, real):
        def invoke(*args, **kwargs):
            if controls['phase'] == phase and controls['primary'] is not None:
                raise controls['primary']
            return real(*args, **kwargs)
        return invoke

    for module in (cal, hc, dc):
        private = ModuleType('owned_metadata_os')
        vars(private).update(vars(os))
        private.open, private.close = open_fd, close
        private.fstat = fault('stat', os.fstat)
        private.read = fault('read', os.read)
        private.write = fault('write', os.write)
        monkeypatch.setattr(module, 'os', private)

    def invoke(operation):
        if operation.startswith('cache'):
            return cal._read_cache_profile(cache)
        if operation.startswith('host'):
            return hc._read_marker_record(marker)
        if operation == 'nonce-write':
            return dc._mint_nonce(mint_dir)
        return dc._nonce_file_consents(consent, nonce)

    def assert_released():
        assert len(opened) == 1
        assert closed == opened
        with pytest.raises(OSError) as error:
            os.fstat(opened[0])
        assert error.value.errno == errno.EBADF

    return invoke, controls, close_error, assert_released, nonce, profile


@pytest.mark.parametrize('operation', OPERATIONS)
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, Cancelled],
                         ids=['interrupt', 'exit', 'base-cancellation'])
@pytest.mark.parametrize('close_fails', [False, True], ids=['close-ok', 'close-error'])
def test_primary_cancellation_survives_cleanup(owned, operation, error_type, close_fails):
    invoke, controls, _close_error, assert_released, _nonce, _profile = owned
    primary = error_type('owned primary cancellation')
    controls.update(primary=primary, phase=operation.split('-')[1], close_fails=close_fails)
    with pytest.raises(error_type) as caught:
        invoke(operation)
    assert_released()
    assert caught.value is primary


@pytest.mark.parametrize('operation', ['cache-read', 'host-read', 'nonce-read', 'nonce-write'])
@pytest.mark.parametrize('close_fails', [False, True], ids=['close-ok', 'close-error'])
def test_successful_body_keeps_close_failure_authoritative(owned, operation, close_fails):
    invoke, controls, close_error, assert_released, _nonce, profile = owned
    controls['close_fails'] = close_fails
    if close_fails:
        with pytest.raises(OSError) as caught:
            invoke(operation)
        assert caught.value is close_error
    else:
        result = invoke(operation)
        if operation.startswith('cache'):
            assert result == profile
        elif operation.startswith('host'):
            assert result == ({'schema': 1, 'owned': 'marker'}, None)
        elif operation == 'nonce-write':
            assert isinstance(result, str) and len(result) == dc.NONCE_HEX_LEN
        else:
            assert result is True
    assert_released()


@pytest.mark.parametrize('close_fails', [False, True], ids=['close-ok', 'close-error'])
def test_nonce_write_error_identity_survives_cleanup(owned, close_fails):
    invoke, controls, _close_error, assert_released, _nonce, _profile = owned
    primary = OSError(errno.ENOSPC, 'owned primary write error')
    controls.update(primary=primary, phase='write', close_fails=close_fails)
    with pytest.raises(OSError) as caught:
        invoke('nonce-write')
    assert_released()
    assert caught.value is primary


@pytest.mark.parametrize('route', ['cache', 'host', 'nonce'])
@pytest.mark.parametrize('phase', ['stat', 'read'])
def test_public_readers_do_not_turn_cancellation_into_fallback(owned, monkeypatch, route, phase):
    _invoke, controls, _close_error, assert_released, nonce, _profile = owned
    primary = KeyboardInterrupt('owned cancellation')
    controls.update(primary=primary, phase=phase, close_fails=True)
    if route == 'cache':
        call = lambda: cal._load_from_cache('entry')
    elif route == 'host':
        # Reach the reader without inspecting the operator's host.
        private_sys = ModuleType('owned_host_sys')
        vars(private_sys).update(vars(hc.sys))
        private_sys.platform = 'linux'
        monkeypatch.setattr(hc, 'sys', private_sys)
        monkeypatch.setattr(hc, '_is_wsl', lambda: True)
        call = hc.applied_consent
    else:
        call = lambda: dc._presented_nonce_valid(nonce)
    with pytest.raises(KeyboardInterrupt) as caught:
        call()
    assert_released()
    assert caught.value is primary


@pytest.mark.parametrize('route', ['cache', 'host', 'nonce'])
def test_public_readers_still_fail_closed_on_close_only_error(owned, monkeypatch, route):
    _invoke, controls, _close_error, assert_released, nonce, _profile = owned
    controls['close_fails'] = True
    if route == 'cache':
        assert cal._load_from_cache('entry') is None
    elif route == 'host':
        private_sys = ModuleType('owned_host_sys')
        vars(private_sys).update(vars(hc.sys))
        private_sys.platform = 'linux'
        monkeypatch.setattr(hc, 'sys', private_sys)
        monkeypatch.setattr(hc, '_is_wsl', lambda: True)
        assert hc.applied_consent() is None
    else:
        assert dc._presented_nonce_valid(nonce) is False
    assert_released()

"""Consent diagnostics are inert while native records and decisions stay intact."""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType

import pytest

from core.sandbox import host_consent as hc
from core.testing.module_state import isolated_module_state
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'
RUNNING = '6.6.36.6-microsoft-standard-WSL2'
GRANTED = '5.15.167.4-microsoft-standard-WSL2'
MACHINE = 'owned-machine-id'
CASES = [
    ('directory', 'not-regular-file'),
    ('symlink', 'symlink'),
    ('permissive', 'permissive-mode'),
    ('invalid-json', 'invalid-json'),
    ('duplicate-json', 'invalid-json'),
    ('nonobject', 'wrong-schema'),
    ('schema', 'wrong-schema'),
    ('floor', 'wrong-floor'),
    ('timestamp', 'bad-granted-at'),
    ('future', 'future-granted-at'),
    ('machine', 'machine-id-mismatch'),
    ('missing-field', 'missing-field'),
    ('mismatch', 'kernel-family-mismatch'),
    ('oversized-families', 'kernel-family-mismatch'),
]
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='owned POSIX control paths')


@pytest.fixture(params=['control', 'long'])
def owned(tmp_path, request, caplog):
    with isolated_module_state(hc, {'_warned_reasons': set()}, lock=hc._warned_lock), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / 'state')
        data = tmp_path / CONTROL
        if request.param == 'long':
            data = data / ('a' * 100) / ('b' * 100)
        patch.setenv('XDG_DATA_HOME', str(data))
        machine, release = tmp_path / 'machine-id', tmp_path / 'osrelease'
        machine.write_text(MACHINE + '\n', encoding='ascii')
        release.write_text(RUNNING + '\n', encoding='ascii')
        patch.setattr(hc, '_MACHINE_ID_PATH', str(machine))
        patch.setattr(hc, '_OSRELEASE_PATH', str(release))
        private_sys = ModuleType('consent_log_sys')
        vars(private_sys).update(vars(sys))
        private_sys.platform = 'linux'
        patch.setattr(hc, 'sys', private_sys)
        patch.setattr(hc, '_is_wsl', lambda: True)
        patch.setattr(hc, '_landlock_available', lambda: False)
        caplog.set_level(logging.DEBUG, logger=hc.__name__)
        yield hc.marker_path(), release, request.param


@pytest.fixture
def monkeypatch(owned):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def record():
    return {'schema': 1, 'floor': 'ns-only',
            'granted_at': datetime.now(timezone.utc).isoformat(),
            'kernel_identity': GRANTED, 'machine_id': MACHINE}


def seed(path, release, scenario):
    path.parent.mkdir(parents=True, mode=0o700)
    value = record()
    if scenario == 'schema':
        value['schema'] = 2
    elif scenario == 'floor':
        value['floor'] = 'unsupported-owned-floor'
    elif scenario == 'timestamp':
        value['granted_at'] = 'not-a-timestamp'
    elif scenario == 'future':
        value['granted_at'] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    elif scenario == 'machine':
        value['machine_id'] = 'different-owned-machine'
    elif scenario == 'missing-field':
        value.pop('kernel_identity')
    elif scenario == 'mismatch':
        value['kernel_identity'] = '5.15.0-microsoft-custom-flavour'
    elif scenario == 'oversized-families':
        value['kernel_identity'] = '5.15.0-microsoft-granted-' + 'g' * 1500
        release.write_text('6.6.0-microsoft-running-' + 'r' * 1500 + '\n', encoding='ascii')
    if scenario == 'directory':
        path.mkdir()
        (path / 'owned-sentinel').write_bytes(b'preserve directory entry')
        return None
    if scenario == 'symlink':
        target = path.with_name('owned-target')
        target.write_bytes(b'preserve symlink target')
        path.symlink_to(target.name)
        return None
    raw = (b'{not JSON' if scenario == 'invalid-json' else
           b'{"schema":1,"schema":1}' if scenario == 'duplicate-json' else
           b'[]' if scenario == 'nonobject' else json.dumps(value).encode())
    path.write_bytes(raw)
    path.chmod(0o666 if scenario == 'permissive' else 0o600)
    return value if scenario not in {'invalid-json', 'duplicate-json', 'nonobject', 'permissive'} else None


def snapshot(path):
    if path.is_symlink():
        return 'symlink', os.readlink(path), path.with_name('owned-target').read_bytes()
    if path.is_dir():
        return 'directory', (path / 'owned-sentinel').read_bytes()
    if path.exists():
        return 'regular', path.read_bytes(), path.stat().st_mode
    return 'absent',


def check_result(endpoint, result, path, reason, expected_record, *, active=False):
    if endpoint == 'status':
        assert result == {'path': str(path), 'present': reason != 'absent',
                          'applies': active, 'reason': reason, 'record': expected_record}
    elif active:
        assert isinstance(result, hc.HostConsent)
        assert result.floor == 'ns-only'
        assert result.granted_at == expected_record['granted_at']
        assert result.kernel_identity == expected_record['kernel_identity']
    else:
        assert result is None


def call(endpoint):
    return hc.marker_status() if endpoint == 'status' else hc.applied_consent()


@pytest.mark.parametrize('endpoint', ['applied', 'status'])
@pytest.mark.parametrize('scenario,reason', CASES, ids=[c[0] for c in CASES])
def test_warning_and_repeat_debug_preserve_inertness(owned, caplog, endpoint, scenario, reason):
    path, release, layout = owned
    expected_record = seed(path, release, scenario)
    before = snapshot(path)
    first = call(endpoint)
    check_result(endpoint, first, path, reason, expected_record)
    assert hc._warned_reasons == {reason}
    second = call(endpoint)
    check_result(endpoint, second, path, reason, expected_record)
    assert hc._warned_reasons == {reason}
    assert snapshot(path) == before
    entries = [r for r in caplog.records if r.name == hc.__name__]
    assert [r.levelno for r in entries] == [logging.WARNING, logging.DEBUG]
    for entry in entries:
        rendered = logging.Formatter('%(message)s').format(entry)
        assert entry.exc_info is None
        assert 'wsl-host-consent:' in rendered
        assert 'fail-closed default' in rendered
        assert all(c.isprintable() for c in rendered)
        assert len(rendered) < 1500
        if layout == 'long' or scenario == 'oversized-families':
            assert '...[+' in rendered


@pytest.mark.parametrize('endpoint', ['applied', 'status'])
@pytest.mark.parametrize('scenario', ['missing', 'not-wsl', 'landlock', 'matching-minor'])
def test_silent_and_matching_controls_keep_native_status(owned, monkeypatch, caplog, endpoint, scenario):
    path, release, _layout = owned
    if scenario == 'missing':
        expected_record, reason = None, 'absent'
    else:
        expected_record = seed(path, release, 'valid')
        reason = {'not-wsl': 'not-wsl', 'landlock': 'landlock-available', 'matching-minor': 'active'}[scenario]
        if scenario == 'not-wsl':
            monkeypatch.setattr(hc, '_is_wsl', lambda: False)
        elif scenario == 'landlock':
            monkeypatch.setattr(hc, '_landlock_available', lambda: True)
    before = snapshot(path)
    for _ in range(2):
        result = call(endpoint)
        check_result(endpoint, result, path, reason, expected_record, active=scenario == 'matching-minor')
    assert hc._warned_reasons == set()
    assert snapshot(path) == before
    assert [r for r in caplog.records if r.name == hc.__name__] == []


@pytest.mark.parametrize('which', ['granted', 'running', 'both'])
def test_family_excerpts_are_bounded_on_plain_paths(owned, tmp_path, monkeypatch, caplog, which):
    _unused, release, layout = owned
    data = tmp_path / 'ascii-marker'
    if layout == 'long':
        data = data / ('a' * 100) / ('b' * 100)
    monkeypatch.setenv('XDG_DATA_HOME', str(data))
    path = hc.marker_path()
    assert str(path).isprintable()
    expected_record = seed(path, release, 'oversized-families')
    if which == 'running':
        expected_record['kernel_identity'] = GRANTED
        path.write_text(json.dumps(expected_record))
    elif which == 'granted':
        release.write_text(RUNNING + '\n', encoding='ascii')
    before = snapshot(path)
    for _ in range(2):
        result = hc.marker_status()
        check_result('status', result, path, 'kernel-family-mismatch', expected_record)
    assert hc._warned_reasons == {'kernel-family-mismatch'}
    assert snapshot(path) == before
    entries = [r for r in caplog.records if r.name == hc.__name__]
    assert [r.levelno for r in entries] == [logging.WARNING, logging.DEBUG]
    for entry in entries:
        rendered = logging.Formatter('%(message)s').format(entry)
        assert all(c.isprintable() for c in rendered)
        assert len(rendered) < 1500
        assert '...[+' in rendered

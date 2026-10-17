"""Session environment restoration must not execute shell data or cross sessions."""
import json
import os
import runpy

import pytest

from core.project import sessions
from core.startup import codex_environment as bridge

SID = '11111111-1111-1111-1111-111111111111'
OTHER = '22222222-2222-2222-2222-222222222222'


@pytest.fixture
def context(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    monkeypatch.delenv('CODEX_THREAD_ID', raising=False)
    monkeypatch.delenv('CLAUDECODE', raising=False)
    for key in ('RAPTOR_SESSION_PID', 'RAPTOR_SESSION_TOKEN', 'RAPTOR_DIR',
                'RAPTOR_CALLER_DIR', 'RAPTOR_LAUNCH_TARGET'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delitem(sessions.__dict__, 'SESSIONS_DIR', raising=False)
    identity = {'starttime': '12', 'boot_id': 'boot', 'pidns': '99'}
    monkeypatch.setattr(sessions, '_identity_for', lambda pid: dict(identity))
    monkeypatch.setattr(sessions, '_identity_matches', lambda pid, fields: all(
        fields.get(key) == value for key, value in identity.items()))
    monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: 12345)
    from core.startup import codex_broker
    monkeypatch.setattr(codex_broker, "start", lambda session_id, pid: None)
    credential = sessions.ensure_codex_session(12345)
    assert credential
    return credential


def test_restore_validates_then_restores_filtered_environment(context, monkeypatch):
    monkeypatch.setenv('RAPTOR_CALLER_DIR', '/caller with spaces')
    monkeypatch.setenv('RAPTOR_LAUNCH_TARGET', '$(touch never-run); "data"')
    bridge.publish(SID, 12345)
    path = bridge._context_directory() / bridge._name(SID, 12345)
    assert path.stat().st_mode & 0o777 == 0o600
    assert bridge._context_directory().stat().st_mode & 0o777 == 0o700
    assert context[1] not in path.read_text()  # no duplicate stored credential
    monkeypatch.delenv('RAPTOR_REGISTRY_HOME')  # Codex core policy drops this
    monkeypatch.setenv('PATH', '/usr/bin')
    monkeypatch.setenv('BASH_ENV', '/operator/value')
    restored = bridge.restore(SID)
    assert restored['RAPTOR_SESSION_TOKEN'] == context[1]
    assert restored['RAPTOR_CALLER_DIR'] == '/caller with spaces'
    assert restored['RAPTOR_LAUNCH_TARGET'] == '$(touch never-run); "data"'
    assert os.environ['BASH_ENV'] == '/operator/value'
    assert os.environ['PATH'].endswith(':/usr/bin')
    assert sessions.session_binding(pid=12345)[1] == 'none'


def test_binding_switch_and_explicit_none_survive_restore(context):
    bridge.publish(SID, 12345)
    sessions.bind_session('myproject', pid=12345)
    bridge.restore(SID)
    assert sessions.session_binding(pid=12345) == ('myproject', 'bound')
    sessions.bind_session(None, pid=12345)
    bridge.restore(SID)
    assert sessions.session_binding(pid=12345)[1] == 'none'


def test_other_session_and_installation_cannot_select_context(context, monkeypatch):
    bridge.publish(SID, 12345)
    with pytest.raises(FileNotFoundError):
        bridge.restore(OTHER)
    monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: 54321)
    with pytest.raises(FileNotFoundError):
        bridge.restore(SID)


@pytest.mark.parametrize('mutation', ['token', 'identity', 'extra', 'root'])
def test_invalid_context_never_installs_partial_environment(context, monkeypatch, mutation):
    bridge.publish(SID, 12345)
    path = bridge._context_directory() / bridge._name(SID, 12345)
    value = json.loads(path.read_text())
    if mutation == 'token':
        value['token_digest'] = '0' * 64
    elif mutation == 'identity':
        value['identity']['starttime'] = 'stale'
    elif mutation == 'extra':
        value['BASH_ENV'] = '/bad'
    else:
        value['root'] = '/other-install'
    path.write_text(json.dumps(value))
    monkeypatch.setenv('RAPTOR_DIR', '/unchanged')
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', '/original-registry')
    with pytest.raises(bridge.CodexEnvironmentError):
        bridge.restore(SID)
    assert os.environ['RAPTOR_DIR'] == '/unchanged'
    assert os.environ['RAPTOR_REGISTRY_HOME'] == '/original-registry'
    assert 'RAPTOR_SESSION_TOKEN' not in os.environ


def test_context_symlink_and_public_file_refused(context):
    bridge.publish(SID, 12345)
    path = bridge._context_directory() / bridge._name(SID, 12345)
    saved = path.with_suffix('.saved')
    path.rename(saved)
    path.symlink_to(saved)
    with pytest.raises(OSError):
        bridge.restore(SID)
    path.unlink()
    saved.rename(path)
    path.chmod(0o644)
    with pytest.raises(bridge.CodexEnvironmentError):
        bridge.restore(SID)


def test_foreign_inherited_credential_does_not_select_startup_owner(context, monkeypatch):
    monkeypatch.setenv('CODEX', '1')
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    monkeypatch.setenv('RAPTOR_SESSION_PID', '54321')
    monkeypatch.setenv('RAPTOR_SESSION_TOKEN', 'foreign-live-token')
    script = bridge.ROOT / 'libexec/raptor-session-init'
    module = runpy.run_path(str(script))
    assert module['_seed_codex_session']() == context
    assert os.environ['RAPTOR_SESSION_PID'] == '12345'


def test_physical_owner_resolver_ignores_env_first_resolver(monkeypatch):
    monkeypatch.setattr(sessions, '_env_session_pid', lambda: 54321)
    monkeypatch.setattr(os, 'getppid', lambda: 12345)
    monkeypatch.setattr(sessions, '_comm', lambda pid: 'codex' if pid == 12345 else 'bash')
    assert sessions.resolve_codex_owner_pid() == 12345


def test_unrelated_codex_process_does_not_load_raptor_environment(monkeypatch):
    monkeypatch.setenv('CODEX_THREAD_ID', SID)
    monkeypatch.delenv('RAPTOR_CODEX_ENVIRONMENT', raising=False)
    monkeypatch.setenv('BASH_ENV', '/operator/shell-setup')
    def forbidden(*args):
        pytest.fail('unrelated Codex process must not consult RAPTOR state')
    monkeypatch.setattr(bridge, 'restore', forbidden)
    bridge.restore_for_process()
    assert os.environ['BASH_ENV'] == '/operator/shell-setup'


def test_same_owner_retry_keeps_original_launch_context(context, monkeypatch):
    monkeypatch.setenv('RAPTOR_CALLER_DIR', '/original')
    bridge.publish(SID, 12345)
    prior = bridge.read_context(SID)
    monkeypatch.delenv('RAPTOR_CALLER_DIR')
    bridge.publish(SID, 12345)
    assert bridge.read_context(SID) == prior


def test_resumed_session_replaces_dead_owner_but_not_live_owner(context, monkeypatch):
    from core.startup import codex_broker
    bridge.publish(SID, 12345)
    old = bridge.read_context(SID)
    monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: 54321)
    monkeypatch.setattr(codex_broker, 'request', lambda *args: (_ for _ in ()).throw(
        bridge.CodexEnvironmentError('unavailable')))
    credential = sessions.ensure_codex_session(54321)
    assert credential
    with pytest.raises(bridge.CodexEnvironmentError, match='still live'):
        bridge.publish(SID, 54321)
    assert bridge.read_context(SID) == old
    original = sessions._identity_matches
    monkeypatch.setattr(sessions, '_identity_matches', lambda pid, fields: (
        pid != 12345 and original(pid, fields)))
    bridge.publish(SID, 54321)
    current = bridge.read_context(SID)
    assert current['pid'] == 54321
    assert current['broker_key'] != old['broker_key']

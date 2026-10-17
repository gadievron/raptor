"""Real same-user IPC with a live identity-stamped owner; no command rewrite."""
import select
import subprocess
import sys
import time
import uuid

import pytest

from core.project import sessions
from core.startup import codex_broker as broker
from core.startup import codex_environment as environment

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux peer credentials')


@pytest.fixture
def host(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    monkeypatch.delenv('CODEX_THREAD_ID', raising=False)
    monkeypatch.delitem(sessions.__dict__, 'SESSIONS_DIR', raising=False)
    for key in ('RAPTOR_SESSION_PID', 'RAPTOR_SESSION_TOKEN', 'RAPTOR_CODEX_CONTEXT_ID'):
        monkeypatch.delenv(key, raising=False)
    process = subprocess.Popen([sys.executable, '-c',
        'import ctypes,sys; ctypes.CDLL(None).prctl(15,b"codex-env-test",0,0,0); '
        'print("ready",flush=True); sys.stdin.read()'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert select.select([process.stdout], [], [], 3)[0]
    assert process.stdout.readline().strip() == 'ready'
    monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: process.pid)
    sid = str(uuid.uuid4())
    credential = sessions.ensure_codex_session(process.pid)
    assert credential
    environment.publish(sid, process.pid)
    try:
        yield sid, process, credential
    finally:
        if not process.stdin.closed:
            process.stdin.close()
        process.wait(timeout=3)
        directory, name = broker._address(sid), "ready"
        deadline = time.monotonic() + 3
        while (directory / name).exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not (directory / name).exists(), 'broker must exit with owner'


def test_hidden_parent_namespace_recovers_verified_context(host, monkeypatch):
    sid, process, credential = host
    monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: None)
    values = environment.restore(sid)
    assert values['RAPTOR_SESSION_TOKEN'] == credential[1]
    assert values['RAPTOR_SESSION_PID'] == str(process.pid)
    monkeypatch.setattr(sessions, '_foreign_entry', lambda fields: True)
    assert sessions.resolve_session_pid() == process.pid
    assert sessions.session_binding() == (None, 'none')
    forged = dict(sessions._parse_entry(sessions._sessions_dir() / str(process.pid)))
    forged['starttime'] = 'different'
    assert not sessions._identity_matches(process.pid, forged)


def test_broker_has_no_command_execution_interface(host, tmp_path):
    sid, _process, _credential = host
    marker = tmp_path / 'must-not-exist'
    with pytest.raises(environment.CodexEnvironmentError):
        broker.request(sid, {'op': 'exec', 'command': 'touch ' + str(marker)})
    assert not marker.exists()
    assert broker.request(sid, {'op': 'environment'})['ok'] is True


def test_owner_exit_revokes_attestation_and_stops_broker(host, monkeypatch):
    sid, process, credential = host
    environment.restore(sid)
    process.stdin.close()
    process.wait(timeout=3)
    monkeypatch.setattr(sessions, '_foreign_entry', lambda fields: True)
    assert not environment.attest_foreign_identity(process.pid, {
        'token': credential[1], 'starttime': 'old', 'boot_id': 'old', 'pidns': 'old'})


def test_missing_capability_cannot_obtain_environment(host):
    sid, _process, credential = host
    with environment._directory(broker._address(sid)) as directory:
        name = '0' * 32
        environment._atomic(directory, name + '.request', '{"op":"environment"}')
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                response = environment._read(directory, name + '.response')
                break
            except FileNotFoundError:
                time.sleep(0.02)
        else:
            pytest.fail('broker did not answer malformed request')
        assert credential[1] not in response
        assert response == '{"ok": false}'


def test_other_live_session_credentials_do_not_validate(host, monkeypatch):
    sid, process, _credential = host
    environment.restore(sid)
    fields = sessions._parse_entry(sessions._sessions_dir() / str(process.pid))
    monkeypatch.setenv('RAPTOR_SESSION_PID', str(process.pid + 1))
    assert not environment.attest_foreign_identity(process.pid, fields)
    monkeypatch.setenv('RAPTOR_SESSION_PID', str(process.pid))
    monkeypatch.setenv('RAPTOR_SESSION_TOKEN', 'foreign-token')
    assert not environment.attest_foreign_identity(process.pid, fields)


def test_duplicate_server_does_not_clean_live_servers_files(host):
    sid, _process, _credential = host
    ready = broker._address(sid) / 'ready'
    before = ready.read_text()
    broker.serve(sid)  # Stable lock already belongs to the active broker.
    assert ready.read_text() == before
    assert broker.request(sid, {'op': 'environment'})['ok'] is True

"""Real same-user IPC with a live identity-stamped owner; no command rewrite."""
import select
import os
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
    # restore() writes these directly; register their original values before
    # any child fixture can snapshot a restored value in monkeypatch. Empty
    # markers isolate this fixture while guaranteeing teardown restores the
    # caller's environment, including keys that were originally absent.
    for key in ('CODEX', 'RAPTOR_CODEX_ENVIRONMENT'):
        monkeypatch.setenv(key, '')
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    monkeypatch.delenv('CODEX_THREAD_ID', raising=False)
    monkeypatch.delitem(sessions.__dict__, 'SESSIONS_DIR', raising=False)
    for key in ('RAPTOR_SESSION_PID', 'RAPTOR_SESSION_TOKEN',
                'RAPTOR_CODEX_CONTEXT_ID'):
        monkeypatch.delenv(key, raising=False)
    process = subprocess.Popen([sys.executable, '-c',
        'import ctypes,sys; ctypes.CDLL(None).prctl(15,b"codex",0,0,0); '
        'print("ready",flush=True); sys.stdin.read()'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert select.select([process.stdout], [], [], 3)[0]
    assert process.stdout.readline().strip() == 'ready'
    monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: process.pid)
    sid = str(uuid.uuid4())
    monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', sid)
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


@pytest.mark.parametrize('kind', ['outcome', 'read'])
def test_owner_exit_cleans_unconsumed_receipts(host, kind):
    sid, process, _credential = host
    name = kind + '-' + 'a' * 64 + '-2.json'
    with environment._directory(broker._address(sid)) as directory:
        environment._atomic(directory, name, '{"status":7}')
    process.stdin.close()
    process.wait(timeout=3)
    deadline = time.monotonic() + 3
    receipt = broker._address(sid) / name
    while receipt.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not receipt.exists()


def test_agent_context_accessor_survives_core_env_filtering(host, monkeypatch):
    import runpy
    from pathlib import Path
    sid, _process, credential = host
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    module = runpy.run_path(str(Path(__file__).resolve().parents[3] /
                                'libexec/raptor-session-init'))
    monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: None)
    for key in ('RAPTOR_LAUNCH_TARGET', 'RAPTOR_CALLER_DIR', 'RAPTOR_SESSION_TOKEN'):
        monkeypatch.delenv(key, raising=False)
    assert module['codex_launch_context'](sid) == {
        'caller_dir': None, 'launch_target': None}
    assert credential[1] not in str(module['codex_launch_context'](sid))


def test_explicit_startup_retry_preserves_live_project_and_ledger(host, monkeypatch, capsys):
    import runpy
    from pathlib import Path
    sid, process, credential = host
    sessions.bind_session('kept-project', pid=process.pid)
    ledger = sessions._sessions_dir() / f'{process.pid}.run'
    ledger.write_text('live run\n')
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    monkeypatch.setenv('CODEX_THREAD_ID', sid)
    monkeypatch.setenv('SAGE_ENABLED', '0')
    monkeypatch.setattr(sys, 'argv', ['raptor-session-init', '--codex-bootstrap'])
    from core.startup import init
    monkeypatch.setattr(init, 'main', lambda: print('test startup banner'))
    script = Path(__file__).resolve().parents[3] / 'libexec/raptor-session-init'
    runpy.run_path(str(script), run_name='__main__')
    output = capsys.readouterr().out
    assert output.count('test startup banner') == 1
    assert output.count('Quick commands: $agentic, $scan') == 1
    assert sessions.session_binding(pid=process.pid) == ('kept-project', 'bound')
    assert sessions._parse_entry(sessions._sessions_dir() / str(process.pid))['token'] == credential[1]
    assert ledger.read_text() == 'live run\n'


def test_two_roots_share_a_live_process_without_sharing_binding_or_revocation(host, monkeypatch):
    first, process, credential = host
    second = str(uuid.uuid4())
    environment.restore(first)
    sessions.bind_session('alpha')
    monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', second)
    other = sessions.ensure_codex_session(process.pid)
    assert other and other[1] != credential[1]
    environment.publish(second, process.pid)
    environment.restore(second)
    sessions.bind_session('beta')
    environment.restore(first)
    assert sessions.session_binding() == ('alpha', 'bound')
    assert sessions.end_codex_session(process.pid, credential[1])
    with pytest.raises(environment.CodexEnvironmentError):
        environment.restore(first)
    environment.restore(second)
    assert sessions.session_binding() == ('beta', 'bound')
    assert broker.request(second, {'op': 'environment'})['ok'] is True
    assert process.poll() is None
    assert sessions.end_codex_session(process.pid, other[1])


def test_subagent_context_uses_root_binding_and_cannot_take_over_another_root(host, monkeypatch):
    root, process, _credential = host
    child = str(uuid.uuid4())
    environment.publish_alias(root, child)
    values = environment.restore(child)
    assert values['RAPTOR_CODEX_CONTEXT_ID'] == root
    sessions.bind_session('shared-root')
    environment.restore(root)
    assert sessions.session_binding() == ('shared-root', 'bound')
    other = str(uuid.uuid4())
    monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', other)
    assert sessions.ensure_codex_session(process.pid)
    environment.publish(other, process.pid)
    with pytest.raises(environment.CodexEnvironmentError, match='another owner'):
        environment.publish_alias(other, child)
    with pytest.raises(environment.CodexEnvironmentError, match='another owner'):
        environment.publish_alias(other, root)
    environment.restore(child)
    assert sessions.session_binding() == ('shared-root', 'bound')
    environment.restore(other)
    sessions.end_codex_session(process.pid, os.environ['RAPTOR_SESSION_TOKEN'])


def test_concurrent_roots_cannot_both_claim_one_subagent(host, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from core.config import RaptorConfig
    root, process, _credential = host
    other, child = str(uuid.uuid4()), str(uuid.uuid4())
    monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', other)
    assert sessions.ensure_codex_session(process.pid)
    environment.publish(other, process.pid)
    child_env = RaptorConfig.get_safe_env()
    child_env.update({'RAPTOR_DIR': str(environment.ROOT), 'RAPTOR_CODEX_HOOK': '1'})
    script = '''import os,sys
sys.path.insert(0,os.environ["RAPTOR_DIR"])
from core.project import sessions
from core.startup import codex_environment as environment
sessions.resolve_codex_owner_pid=lambda: int(sys.argv[1])
try:
    environment.publish_alias(sys.argv[2],sys.argv[3])
except ValueError:
    sys.exit(1)
'''
    def claim(parent):
        return subprocess.run([sys.executable, '-I', '-c', script, str(process.pid), parent, child],
                              env=child_env, capture_output=True, text=True, timeout=10)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim, [root, other]))
    assert sorted(result.returncode for result in results) == [0, 1], [r.stderr for r in results]
    assert environment.read_context(child)['session_id'] in (root, other)
    environment.restore(other)
    sessions.end_codex_session(process.pid, os.environ['RAPTOR_SESSION_TOKEN'])


def test_context_lock_refuses_fifo_and_symlink(host, tmp_path):
    import os
    sid, process, _credential = host
    name = environment._name(sid, process.pid) + '.lock'
    path = environment._context_directory() / name
    path.unlink()
    os.mkfifo(path, 0o600)
    with pytest.raises(environment.CodexEnvironmentError, match='unsafe context lock'):
        environment.publish(sid, process.pid)
    path.unlink()
    target = tmp_path / 'untouched'
    target.write_text('untouched')
    path.symlink_to(target)
    with pytest.raises(OSError):
        environment.publish(sid, process.pid)
    assert target.read_text() == 'untouched'


def test_same_process_resume_rotates_generation_and_invalidates_old_alias(host):
    sid, process, credential = host
    child = str(uuid.uuid4())
    environment.publish_alias(sid, child)
    old = environment.read_context(sid)
    assert sessions.end_codex_session(process.pid, credential[1])
    successor = sessions.ensure_codex_session(process.pid)
    assert successor and successor[1] != credential[1]
    environment.publish(sid, process.pid)
    assert environment.read_context(sid)['broker_key'] != old['broker_key']
    with pytest.raises(environment.CodexEnvironmentError, match='generation changed'):
        environment.restore(child)
    environment.restore(sid)
    assert os.environ['RAPTOR_SESSION_TOKEN'] == successor[1]
    environment.publish_alias(sid, child)
    assert environment.restore(child)['RAPTOR_SESSION_TOKEN'] == successor[1]


@pytest.fixture
def child_outcome(host, tmp_path, monkeypatch):
    from core.run import cli_outcome as outcome
    from core.sandbox import summary
    root, process, _credential = host
    child = str(uuid.uuid4())
    environment.publish_alias(root, child)
    environment.restore(child)
    monkeypatch.setenv('RAPTOR_CODEX_ENVIRONMENT', '1')
    monkeypatch.setenv('CODEX_THREAD_ID', child)
    monkeypatch.setenv('CODEX_TOOL_CALL_ID', 'child_failure')
    monkeypatch.delenv('CLAUDECODE', raising=False)
    monkeypatch.delenv('RAPTOR_CODEX_HOOK', raising=False)
    run = tmp_path / 'owned-run'
    monkeypatch.setattr(summary, '_active_run_dir', run)
    monkeypatch.setattr(sys, 'argv', [str(environment.ROOT / 'libexec/raptor-example')])
    with pytest.raises(SystemExit), outcome.cli_outcome():
        sys.exit(7)
    receipts = list(broker._address(root).glob('outcome-*.json'))
    assert len(receipts) == 1
    payload = {'session_id': child, 'tool_use_id': 'child_failure',
               'hook_event_name': 'PostToolUse', 'tool_name': 'Bash',
               'tool_input': {'command': 'libexec/raptor-example'}}
    return root, process, child, payload, receipts[0], run


@pytest.mark.parametrize('hook_id', ['root', 'child'])
def test_child_hook_consumes_root_receipt_once(child_outcome, hook_id):
    from core.run import cli_outcome as outcome
    root, _process, _child, payload, receipt, run = child_outcome
    if hook_id == 'root':
        payload = dict(payload, session_id=root)
    assert outcome.consume(payload) == ('libexec/raptor-example', str(run), [])
    assert outcome.consume(payload) is None
    assert not receipt.exists()


def test_stale_child_alias_cannot_delete_root_receipt(child_outcome):
    import json
    from core.run import cli_outcome as outcome
    root, _process, child, payload, receipt, run = child_outcome
    alias = environment._context_document(child)
    alias['generation'] = '0' * 64
    path = environment._context_directory() / environment._name(child, None)
    path.write_text(json.dumps(alias))
    with pytest.raises(environment.CodexEnvironmentError, match='generation changed'):
        outcome.consume(payload)
    assert receipt.exists()
    assert outcome.consume(dict(payload, session_id=root)) == (
        'libexec/raptor-example', str(run), [])


def test_other_root_child_cannot_consume_root_receipt(child_outcome, monkeypatch):
    from core.run import cli_outcome as outcome
    root, process, _child, payload, receipt, run = child_outcome
    other, other_child = str(uuid.uuid4()), str(uuid.uuid4())
    monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', other)
    credential = sessions.ensure_codex_session(process.pid)
    assert credential
    environment.publish(other, process.pid)
    try:
        environment.publish_alias(other, other_child)
        assert outcome.consume(dict(payload, session_id=other_child)) is None
        assert receipt.exists()
        assert outcome.consume(payload) == ('libexec/raptor-example', str(run), [])
        assert os.environ['RAPTOR_CODEX_CONTEXT_ID'] == root
    finally:
        environment.restore(other)
        assert sessions.end_codex_session(process.pid, credential[1])

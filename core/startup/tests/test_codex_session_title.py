"""Native title feedback, authenticated ownership and optional failure behavior."""
import json
import io
import os
from pathlib import Path
import runpy
import socket
import sys
import tempfile
import time
from types import SimpleNamespace

import pytest

from core.hash import sha256_string
from core.json import load_json, save_json
from core.project import registry_home, sessions
from core.project.session_titles import context_title
from core.startup import codex_environment, codex_session_title as title


class Channel:
    """Protocol-shaped native responses, including interleaved notifications."""
    def __init__(self, identity='thread-one', name=None):
        self.identity, self.name = identity, name
        self.sent, self.pending, self.timeouts = [], [], []
        self.socket = self
        self.rename_on_second_read = None
        self.reads = 0

    def settimeout(self, value):
        self.timeouts.append(value)

    def send(self, raw):
        request = json.loads(raw)
        self.sent.append(request)
        method, params = request['method'], request.get('params', {})
        if method == 'initialized':
            return
        if method == 'initialize':
            result = {'userAgent': 'native-fixture'}
        elif method == 'thread/read':
            self.reads += 1
            if self.reads == 2 and self.rename_on_second_read:
                self.name = self.rename_on_second_read
            result = {'thread': {'id': self.identity, 'name': self.name,
                                 'status': {'type': 'idle'}, 'turns': []}}
        elif method == 'thread/name/set':
            assert params['threadId'] == self.identity
            self.name = params['name']
            result = {}
        else:
            pytest.fail(f'unexpected naming API: {method}')
        self.pending.extend([{'method': 'thread/status/changed',
                              'params': {'threadId': self.identity, 'status': {'type': 'idle'}}},
                             {'id': request['id'], 'result': result}])

    def recv(self, *, timeout):
        self.timeouts.append(timeout)
        return json.dumps(self.pending.pop(0))


def synchronize(channel, directory, desired='raptor · fixture · target'):
    title._synchronize(channel, channel.identity, desired, directory, time.monotonic() + .75)


def test_native_feedback_confirms_then_updates_context(tmp_path):
    channel = Channel()
    directory = tmp_path / 'titles'
    synchronize(channel, directory)
    assert channel.name == 'raptor · fixture · target'
    state = next(directory.glob('*.json'))
    assert load_json(state)['confirmed'] is None
    synchronize(channel, directory)
    assert load_json(state)['confirmed'] == channel.name
    synchronize(channel, directory, 'raptor · other · next')
    assert channel.name == 'raptor · other · next'
    assert all(0 < value <= .75 for value in channel.timeouts)
    assert {item['method'] for item in channel.sent} == {
        'initialize', 'initialized', 'thread/read', 'thread/name/set'}


@pytest.mark.parametrize('when', ['before-start', 'later-turn', 'during-read'])
def test_observed_manual_names_are_never_replaced(tmp_path, when):
    channel = Channel(name='My investigation' if when == 'before-start' else None)
    directory = tmp_path / 'titles'
    if when == 'later-turn':
        synchronize(channel, directory)
        channel.name = 'My investigation'
    elif when == 'during-read':
        channel.rename_on_second_read = 'My investigation'
    synchronize(channel, directory)
    assert channel.name == 'My investigation'
    channel.name = 'raptor · fixture · target'
    synchronize(channel, directory, 'raptor · changed · target')
    assert channel.name == 'raptor · fixture · target'  # Manual preference remains latched.


def test_independent_threads_do_not_share_manual_state(tmp_path):
    first, second = Channel(name='Manual'), Channel('thread-two')
    for channel in (first, second):
        synchronize(channel, tmp_path / 'titles')
    assert first.name == 'Manual'
    assert second.name == 'raptor · fixture · target'


@pytest.mark.parametrize('reply', [
    {'id': 1, 'error': {'code': -1, 'message': 'unavailable'}},
    {'id': 1, 'result': []},
    {'id': 22, 'method': 'item/commandExecution/requestApproval', 'params': {}},
    [],
])
def test_bad_replies_and_permission_requests_never_trigger_execution(reply):
    channel = Channel()
    channel.recv = lambda **kwargs: json.dumps(reply)
    with pytest.raises(ValueError):
        title._Client(channel, time.monotonic() + .75).call('initialize', {})
    assert len(channel.sent) == 1


@pytest.mark.parametrize('thread', [
    {'id': 'other-thread', 'status': {'type': 'idle'}, 'name': None},
    {'id': 'thread-one', 'status': {'type': 'notLoaded'}, 'name': None},
    {'id': 'thread-one', 'status': {'type': 'idle'}, 'name': 3},
    {'id': 'thread-one', 'status': {'type': 'idle'}, 'name': 'x' * 4097},
])
def test_wrong_or_unloaded_thread_is_not_named(thread):
    channel = Channel()
    channel.recv = lambda **kwargs: json.dumps({'id': 1, 'result': {'thread': thread}})
    with pytest.raises(ValueError):
        title._Client(channel, time.monotonic() + .75).title('thread-one')
    assert [item['method'] for item in channel.sent] == ['thread/read']


def test_deadline_expiry_stops_before_send():
    channel = Channel()
    with pytest.raises(TimeoutError):
        title._Client(channel, time.monotonic() - 1).call('initialize', {})
    assert not channel.sent


@pytest.fixture
def authenticated(tmp_path, monkeypatch):
    identity, pid = 'thread-one', os.getpid()
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', identity)
    monkeypatch.delenv('RAPTOR_SESSION_TARGET', raising=False)
    monkeypatch.setattr(sessions, '_comm', lambda value: 'codex')
    monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: pid)
    monkeypatch.delitem(sessions.__dict__, 'SESSIONS_DIR', raising=False)
    credential = sessions.ensure_codex_session(pid)
    assert credential
    monkeypatch.setenv('RAPTOR_SESSION_PID', credential[0])
    monkeypatch.setenv('RAPTOR_SESSION_TOKEN', credential[1])
    context = {'version': 1, 'session_id': identity, 'pid': pid,
               'root': str(codex_environment.ROOT), 'registry_home': str(tmp_path / 'registry'),
               'identity': sessions._identity_for(pid),
               'token_digest': sha256_string(credential[1]), 'broker_key': 'a' * 64,
               'launch_target': '../fixture', 'caller_dir': '/launch/subdirectory'}
    monkeypatch.setattr(codex_environment, 'read_context', lambda value: context)
    return context


def test_authenticated_projectless_target_uses_preserved_launcher_base(authenticated, monkeypatch):
    monkeypatch.setenv('RAPTOR_SESSION_TARGET', '/stale/claude-target')
    observed = []
    real = title.context_title
    def desired(project, target):
        observed.append((project, target))
        return real(project, target)
    monkeypatch.setattr(title, 'context_title', desired)
    calls = []
    monkeypatch.setattr(title, '_connect', lambda pid, deadline: calls.append(pid))
    title.update_title('thread-one')
    assert observed == [(None, '/launch/subdirectory/../fixture')]
    assert calls == [os.getpid()]
    assert os.environ['RAPTOR_SESSION_TARGET'] == '/stale/claude-target'


def test_projectless_title_uses_only_its_own_pinned_run(authenticated, tmp_path, monkeypatch):
    run = tmp_path / 'owned-run'
    run.mkdir()
    save_json(run / '.raptor-run.json', {'target_path': '/actual/current-target'})
    sessions.ledger_record_start(run, pid=os.getpid(), pin_project=None, record_pin=True)
    monkeypatch.setattr(sessions, 'ledger_pin_witness', lambda *args, **kwargs: pytest.fail('cross-root search'))
    assert title._desired(authenticated) == context_title(None, '/actual/current-target')


def test_project_switch_uses_the_current_binding_not_the_bookmark(authenticated):
    save_json(registry_home.projects_dir() / 'alpha.json', {'target': '/targets/alpha'})
    save_json(registry_home.projects_dir() / 'beta.json', {'target': '/targets/beta'})
    registry_home.active_link().symlink_to('beta.json')
    sessions.bind_session('alpha', pid=os.getpid())
    assert title._desired(authenticated) == context_title('alpha', '/targets/alpha')
    sessions.bind_session('beta', pid=os.getpid())
    assert title._desired(authenticated) == context_title('beta', '/targets/beta')
    sessions.bind_session(None, pid=os.getpid())
    assert title._desired(authenticated) == context_title(None, '../fixture')


@pytest.mark.parametrize('change', ['thread', 'alias', 'token', 'birth', 'owner', 'credential', 'pid'])
def test_invalid_or_foreign_owner_never_opens_transport(authenticated, monkeypatch, change):
    if change == 'thread':
        monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', 'another-thread')
    elif change == 'alias':
        authenticated['session_id'] = 'root-thread'
    elif change == 'token':
        authenticated['token_digest'] = 'f' * 64
    elif change == 'birth':
        authenticated['identity']['starttime'] = 'different'
    elif change == 'owner':
        monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: os.getpid() + 1)
    elif change == 'pid':
        monkeypatch.setenv('RAPTOR_SESSION_PID', str(os.getpid() + 1))
    else:
        monkeypatch.setenv('RAPTOR_SESSION_TOKEN', 'forged')
    monkeypatch.setattr(title, '_connect', lambda *args: pytest.fail('must not connect'))
    title.update_title('thread-one')
    assert not (registry_home.sessions_dir() / '.titles').exists()


@pytest.mark.parametrize('failure', [OSError('unavailable'), ValueError('refused'),
                                   ImportError('optional transport absent'), TimeoutError('deadline')])
def test_optional_transport_errors_do_not_interrupt_hook(authenticated, monkeypatch, failure, capsys):
    def unavailable(*args):
        raise failure
    monkeypatch.setattr(title, '_connect', unavailable)
    assert title.update_title('thread-one') is None
    assert capsys.readouterr().out == ''


def test_busy_transaction_lock_skips_without_connecting(authenticated, monkeypatch):
    directory = registry_home.sessions_dir() / '.titles'
    directory.mkdir(mode=0o700)
    lock = directory / f'codex-{sha256_string("thread-one")}.transaction.lock'
    monkeypatch.setattr(title, '_connect', lambda *args: pytest.fail('busy title must be skipped'))
    with title.sidecar_flock(lock, required=True, deadline_s=.025):
        assert title.update_title('thread-one') is None
    assert not list(directory.glob('*.json'))


def test_symlink_title_directory_cannot_redirect_hook_writes(authenticated, tmp_path, monkeypatch):
    destination = tmp_path / 'elsewhere'
    destination.mkdir(mode=0o700)
    (registry_home.sessions_dir() / '.titles').symlink_to(destination, target_is_directory=True)
    monkeypatch.setattr(title, '_connect', lambda *args: pytest.fail('unsafe state directory'))
    assert title.update_title('thread-one') is None
    assert not list(destination.iterdir())


@pytest.mark.parametrize('native_id', ['thread-one', 'child-thread'])
def test_session_start_names_only_after_publication_with_native_identity(authenticated, monkeypatch, native_id):
    from core.startup import init
    from core.sage.config import SageConfig
    script = codex_environment.ROOT / 'libexec/raptor-session-init'
    ordering = []
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    monkeypatch.setenv('CODEX', '1')
    monkeypatch.setenv('RAPTOR_CODEX_HOOK', '1')
    monkeypatch.setenv('RAPTOR_DIR', str(codex_environment.ROOT))
    monkeypatch.delenv('CODEX_THREAD_ID', raising=False)
    monkeypatch.delenv('RAPTOR_INSTALL_PROTECTED', raising=False)
    monkeypatch.setattr(sys, 'argv', [str(script)])
    monkeypatch.setattr(sys, 'path', sys.path.copy())
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps({
        'hook_event_name': 'SessionStart', 'session_id': native_id})))
    monkeypatch.setattr(codex_environment, 'publish', lambda sid, pid: ordering.append(('published', sid)))
    monkeypatch.setattr(title, 'update_title', lambda sid: ordering.append(('named', sid)))
    monkeypatch.setattr(init, 'main', lambda: ordering.append('banner'))
    monkeypatch.setattr(SageConfig, 'from_env', classmethod(lambda cls: SimpleNamespace(enabled=False)))
    runpy.run_path(str(script), run_name='__main__')
    assert ordering == [('published', 'thread-one'), ('named', native_id), 'banner']


@pytest.mark.skipif(not Path('/proc/self/net/unix').exists(), reason='Linux socket discovery')
def test_discovery_selects_only_a_listener_held_by_owner():
    with tempfile.TemporaryDirectory(prefix='r-ts-', dir='/tmp') as directory:
        endpoint = Path(directory) / 'app-server-control.sock'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(endpoint))
            assert title._listener_path(os.getpid()) is None  # Bound is not listening.
            server.listen()
            assert title._listener_path(os.getpid()) == endpoint
        assert title._listener_path(os.getpid()) is None


@pytest.mark.skipif(not Path('/proc/self/net/unix').exists(), reason='Linux socket discovery')
def test_directory_fd_bound_listener_is_resolved_for_its_owner():
    with tempfile.TemporaryDirectory(prefix='r-ts-', dir='/tmp') as directory:
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(f'/proc/self/fd/{parent}/app-server-control.sock')
                server.listen()
                assert title._listener_path(os.getpid()) == Path(directory) / 'app-server-control.sock'
        finally:
            os.close(parent)


def test_only_native_control_socket_shapes_are_candidates():
    root = Path('/tmp') / f'codex-daemon-{os.getuid()}'
    assert title._control_path(root / ('a' * 64))
    assert title._control_path(Path('/private/server/app-server-control.sock'))
    assert not title._control_path(root / 'unrelated.sock')
    assert not title._control_path(Path('/tmp/other') / ('a' * 64))
    assert not title._control_path(root / ('a' * 63))


@pytest.mark.skipif(not hasattr(socket, 'SO_PEERCRED'), reason='Linux peer credentials')
def test_foreign_peer_is_rejected_before_websocket_handshake(monkeypatch):
    pytest.importorskip('websockets.sync.client')
    with tempfile.TemporaryDirectory(prefix='r-ts-', dir='/tmp') as directory:
        endpoint = Path(directory) / 'app-server-control.sock'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(endpoint))
            server.listen()
            monkeypatch.setattr(title, '_listener_path', lambda pid: endpoint)
            monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: os.getpid() + 1)
            assert title._connect(os.getpid() + 1, time.monotonic() + .75) is None

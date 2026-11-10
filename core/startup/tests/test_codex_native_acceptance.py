"""Opt-in native Codex preflight; no model calls or hook-trust bypass.

Run with RAPTOR_CODEX_NATIVE_ACCEPTANCE=1 and pytest -m integration.
These tests inspect the real app-server and its normal sandbox. They do not
claim model-driven lifecycle acceptance.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time

import pytest

from core.testing.gitrepo import git_run, init_scratch_repo

ROOT = Path(__file__).resolve().parents[3]
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name != 'posix', reason='native harness uses POSIX process groups'),
    pytest.mark.skipif(os.environ.get('RAPTOR_CODEX_NATIVE_ACCEPTANCE') != '1',
                       reason='native Codex acceptance is explicitly opt-in'),
]


class NativeClient:
    def __init__(self, executable, cwd, env, stderr_path):
        self.stderr_path = stderr_path
        self.stderr = stderr_path.open('wb')
        self.process = subprocess.Popen(
            [executable, 'app-server', '--stdio'], cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
            start_new_session=True)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer = b''
        self.next_id = 0

    def request(self, method, params, timeout=10):
        self.next_id += 1
        request_id = self.next_id
        self.process.stdin.write(json.dumps(
            {'id': request_id, 'method': method, 'params': params}).encode() + b'\n')
        self.process.stdin.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b'\n' not in self.buffer:
                if not self.selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                    continue
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError('native app-server closed stdout')
                self.buffer += chunk
            while b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                message = json.loads(line)
                if 'method' in message and 'id' in message:
                    # Never auto-approve a server-initiated permission request.
                    raise RuntimeError('native app-server requires an interactive client')
                if message.get('id') == request_id:
                    return message
        raise TimeoutError(f'native {method} timed out')

    def result(self, method, params):
        response = self.request(method, params)
        assert 'error' not in response, response.get('error')
        return response['result']

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        self.selector.close()
        self.process.stdin.close()
        self.process.stdout.close()
        self.stderr.close()


@pytest.fixture
def native(tmp_path):
    executable = shutil.which('codex')
    if not executable:
        pytest.skip('Codex CLI is not installed')
    version_output = subprocess.run([executable, '--version'], check=True,
                                    capture_output=True, text=True, timeout=10).stdout
    match = re.search(r'codex-cli (\S+)', version_output)
    assert match, version_output
    primary = init_scratch_repo(tmp_path, 'primary')
    git_run(primary, 'commit', '--allow-empty', '-m', 'acceptance fixture')
    worktree = tmp_path / 'worktree'
    git_run(primary, 'worktree', 'add', '--detach', str(worktree))
    untrusted = init_scratch_repo(tmp_path, 'untrusted')
    source = (ROOT / '.codex/config.toml').read_text()
    for checkout in (primary, worktree, untrusted):
        (checkout / '.codex').mkdir()
        (checkout / '.codex/config.toml').write_text(source)
    # An untrusted checkout cannot inject additional project-local hooks.
    with (untrusted / '.codex/config.toml').open('a') as stream:
        stream.write('\n[[hooks.SessionStart]]\n[[hooks.SessionStart.hooks]]\n'
                     'type = "command"\ncommand = "must-not-execute"\n')
    home = tmp_path / 'home'
    home.mkdir()
    codex_home = tmp_path / 'codex-state'
    codex_home.mkdir()
    (codex_home / 'config.toml').write_text('\n'.join(
        '[projects.' + json.dumps(str(path)) + ']\ntrust_level = "trusted"\n'
        for path in (primary, worktree)))
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(home),
           'CODEX_HOME': str(codex_home), 'TERM': 'dumb',
           'RAPTOR_CODEX_HOOK_ROOT': str(ROOT),
           'RAPTOR_REGISTRY_HOME': str(tmp_path / 'registry')}
    for arguments in (
        ['plugin', 'marketplace', 'add', str(ROOT), '--json'],
        ['plugin', 'add', 'raptor-codex-hooks@raptor-local', '--json'],
    ):
        install = subprocess.run([executable, *arguments], env=env, cwd=primary,
                                 capture_output=True, text=True, timeout=15)
        assert install.returncode == 0, install.stderr
    client = NativeClient(executable, primary, env, tmp_path / 'native-stderr.log')
    try:
        client.result('initialize', {'clientInfo': {'name': 'raptor-native-acceptance',
                      'version': '1'}, 'capabilities': {'experimentalApi': True}})
        client.process.stdin.write(b'{"method":"initialized"}\n')
        client.process.stdin.flush()
        yield client, primary, worktree, untrusted, match[1], home
    finally:
        client.close()


def _hooks(client, cwd):
    data = client.result('hooks/list', {'cwds': [str(cwd)]})['data']
    assert len(data) == 1
    assert not data[0]['errors'], data[0]['errors']
    return data[0]['hooks']


def _check_plugin(client, cwd):
    hooks = _hooks(client, cwd)
    plugin = [hook for hook in hooks
              if hook['pluginId'] == 'raptor-codex-hooks@raptor-local']
    events = {'sessionStart', 'subagentStart', 'postToolUse', 'stop', 'sessionEnd'}
    assert len(plugin) == 5
    assert {hook['eventName'] for hook in plugin} == events
    assert all(hook['source'] == 'plugin' for hook in plugin)
    assert all(hook['trustStatus'] == 'untrusted' for hook in plugin)
    assert all('plugins/cache/raptor-local/raptor-codex-hooks/' in hook['sourcePath']
               for hook in plugin)
    assert all((Path(hook['sourcePath']).parent / 'dispatch.py').is_file()
               for hook in plugin)
    assert not any(hook['source'] == 'project' for hook in hooks), hooks
    return plugin


def test_primary_checkout_lists_all_plugin_hooks_without_trusting_them(native):
    client, primary, *_ = native
    _check_plugin(client, primary)
    nested = primary / 'core'
    nested.mkdir()
    assert len(_check_plugin(client, nested)) == 5


def test_plugin_discovery_is_identical_in_primary_and_worktree(native):
    client, primary, worktree, *_ = native
    primary_hooks = _check_plugin(client, primary)
    worktree_hooks = _check_plugin(client, worktree)
    assert {(h['key'], h['currentHash']) for h in primary_hooks} == {
        (h['key'], h['currentHash']) for h in worktree_hooks}


def test_untrusted_project_cannot_add_hooks_to_installed_plugin(native):
    client, _primary, _worktree, untrusted, *_ = native
    _check_plugin(client, untrusted)


def test_native_thread_ids_are_distinct_without_executing_untrusted_hooks(native):
    client, primary, _worktree, _untrusted, _version, home = native
    _check_plugin(client, primary)
    params = {'cwd': str(primary), 'sandbox': 'workspace-write',
              'approvalPolicy': 'on-request'}
    first = client.result('thread/start', params)['thread']['id']
    second = client.result('thread/start', params)['thread']['id']
    assert first != second
    # This is native ID/trust preflight, not authenticated RAPTOR isolation.
    assert not (home / '.local/share/raptor/codex-contexts').exists()


def test_worktree_loads_shell_settings_alongside_plugin_hooks(native):
    client, _primary, worktree, _untrusted, _version, home = native
    config = client.result('config/read', {'cwd': str(worktree), 'includeLayers': True})['config']
    assert config['shell_environment_policy']['inherit'] == 'core'
    assert config['shell_environment_policy']['set']['RAPTOR_CODEX_ENVIRONMENT'] == '1'
    assert str(home / '.raptor') in config['sandbox_workspace_write']['writable_roots']


def test_actual_raptor_skill_catalog_has_the_entry_workflows(native):
    client, *_ = native
    data = client.result('skills/list', {'cwds': [str(ROOT)]})['data']
    assert len(data) == 1
    assert not data[0]['errors'], data[0]['errors']
    names = {skill['name'] for skill in data[0]['skills']}
    assert {'scan', 'project', 'commands'} <= names


def test_native_sandbox_can_run_a_benign_command(native):
    client, *_ = native
    try:
        reply = client.request('command/exec', {
            'command': ['/usr/bin/true'], 'timeoutMs': 2000,
            'sandboxPolicy': {'type': 'readOnly', 'networkAccess': False}}, timeout=5)
    except TimeoutError:
        error = client.stderr_path.read_text(errors='replace')
        if 'sandbox uses bubblewrap and needs access to create user namespaces' in error:
            pytest.skip('native sandbox blocked: this execution environment denies user namespaces')
        raise
    assert 'error' not in reply, reply.get('error')
    result = reply['result']
    if result['exitCode'] != 0 and (
            'sandbox uses bubblewrap and needs access to create user namespaces'
            in client.stderr_path.read_text(errors='replace')):
        pytest.skip('native sandbox blocked: this execution environment denies user namespaces')
    assert result['exitCode'] == 0, result


def test_native_thread_names_round_trip_without_a_model_call(native):
    client, primary, *_ = native
    params = {'cwd': str(primary), 'sandbox': 'workspace-write',
              'approvalPolicy': 'on-request'}
    first = client.result('thread/start', params)['thread']['id']
    second = client.result('thread/start', params)['thread']['id']
    before = client.result('thread/read', {'threadId': first})['thread']
    assert before.get('name') is None
    assert before['status']['type'] != 'notLoaded'
    client.result('thread/name/set', {'threadId': first, 'name': 'raptor · fixture · target'})
    assert client.result('thread/read', {'threadId': first})['thread']['name'] == 'raptor · fixture · target'
    assert client.result('thread/read', {'threadId': second})['thread'].get('name') is None
    client.result('thread/name/set', {'threadId': first, 'name': 'Manual investigation'})
    assert client.result('thread/read', {'threadId': first})['thread']['name'] == 'Manual investigation'


def test_two_clients_share_title_updates_and_preserve_manual_names(tmp_path, monkeypatch):
    """Transport/policy acceptance only; this does not execute lifecycle hooks."""
    websocket = pytest.importorskip('websockets.sync.client')
    from core.project.session_titles import context_title
    from core.startup import codex_session_title as naming

    executable = shutil.which('codex')
    if not executable:
        pytest.skip('Codex CLI is not installed')
    # Keep the Unix socket below sockaddr_un's pathname limit, independently
    # of pytest's checkout/worker/test-name directory lengths.
    with tempfile.TemporaryDirectory(prefix='r-title-') as directory:
        root = Path(directory)
        home, state = root / 'home', root / 'state'
        home.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        endpoint = root / 'control.sock'
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
               'HOME': str(home), 'CODEX_HOME': str(state), 'TERM': 'dumb'}
        # Deliberately exclude real credentials, installed plugins and RAPTOR
        # hook markers. Only these temporary, model-free threads are accessed.
        with (tmp_path / 'title-server.log').open('wb') as log:
            process = subprocess.Popen(
                [executable, 'app-server', '--listen', 'unix://' + str(endpoint)],
                cwd=root, env=env, stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True)
            try:
                deadline = time.monotonic() + 10
                while not endpoint.exists():
                    assert process.poll() is None, (tmp_path / 'title-server.log').read_text()
                    assert time.monotonic() < deadline, 'private server readiness timed out'
                    time.sleep(.02)
                with websocket.unix_connect(str(endpoint), open_timeout=2, close_timeout=.1) as owner:
                    next_id = 0
                    owner_events = []

                    def call(client, method, params):
                        nonlocal next_id
                        next_id += 1
                        identity = next_id
                        client.send(json.dumps({'id': identity, 'method': method, 'params': params}))
                        until = time.monotonic() + 3
                        while True:
                            reply = json.loads(client.recv(timeout=max(.001, until - time.monotonic())))
                            if 'method' in reply and 'id' in reply:
                                pytest.fail('unexpected interactive server request')
                            if reply.get('id') == identity:
                                assert 'error' not in reply, reply.get('error')
                                return reply['result']
                            if client is owner:
                                owner_events.append(reply)

                    call(owner, 'initialize', {'clientInfo': {'name': 'raptor-title-acceptance',
                                                             'version': '1'}})
                    owner.send('{"method":"initialized"}')
                    first = call(owner, 'thread/start', {'cwd': str(root)})['thread']['id']
                    second = call(owner, 'thread/start', {'cwd': str(root)})['thread']['id']
                    desired = context_title('fixture', '/targets/first')
                    policy_dir = root / 'titles'

                    # Simulate the hook's already-authenticated ancestor resolver;
                    # discovery, socket peer credentials and protocol are real.
                    monkeypatch.setattr(naming.sessions, 'resolve_codex_owner_pid', lambda: process.pid)

                    def update():
                        # Native integration checks the API, not host latency.
                        # Production hooks keep their shorter optional budget.
                        deadline = time.monotonic() + 5
                        assert naming._listener_path(process.pid) == endpoint
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                            probe.connect(str(endpoint))
                            peer_pid, peer_uid, _ = struct.unpack('3i', probe.getsockopt(
                                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                            assert (peer_pid, peer_uid) == (process.pid, os.getuid()), 'server ownership'
                        adapter = naming._connect(process.pid, deadline)
                        assert adapter is not None, 'owning listener must be discoverable'
                        with adapter:
                            naming._synchronize(adapter, first, desired, policy_dir, deadline)

                    update()
                    assert call(owner, 'thread/read', {'threadId': first})['thread']['name'] == desired
                    assert any(event.get('method') == 'thread/name/updated'
                               and event['params']['threadId'] == first
                               and event['params']['threadName'] == desired for event in owner_events)
                    assert update() is None  # Native feedback acknowledges the request.
                    call(owner, 'thread/name/set', {'threadId': first, 'name': 'Manual investigation'})
                    desired = context_title('other-project', '/targets/second')
                    assert update() is None
                    assert call(owner, 'thread/read', {'threadId': first})['thread']['name'] == 'Manual investigation'
                    assert call(owner, 'thread/read', {'threadId': second})['thread'].get('name') is None

                    # The actual native listener also supports a generic
                    # unix:// advertisement; its kernel pathname is hashed.
                    read = naming._read
                    def generic_listener(path, maximum):
                        raw = read(path, maximum)
                        if path.name == 'cmdline':
                            return raw.replace(('unix://' + str(endpoint)).encode(), b'unix://')
                        return raw
                    with monkeypatch.context() as patch:
                        patch.setattr(naming, '_read', generic_listener)
                        assert naming._listener_path(process.pid).resolve() == endpoint.resolve()
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=3)

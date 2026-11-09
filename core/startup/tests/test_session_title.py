"""Native hook naming preserves manual choices and concurrent session identity."""
import errno
import io
import json
import os
from pathlib import Path
import shutil
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.json import load_json, save_json
from core.project import session_titles as policy, registry_home, sessions
from core.startup import session_title as hook


from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def titles(tmp_path, monkeypatch):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    context = ['alpha', '/targets/first']
    monkeypatch.setattr(hook, '_context', lambda: tuple(context))
    return context


def event(identity='session-one', *, title=None, source='startup', turn=False):
    payload = dict(session_id=identity, hook_event_name='UserPromptSubmit' if turn else 'SessionStart',
                   source=source)
    if title is not None:
        payload['session_title'] = title
    return payload


def emitted(payload):
    return hook.hook_output(payload).get('hookSpecificOutput', {}).get('sessionTitle')


def states():
    return [load_json(path, strict=True) for path in
            policy.state_directory().glob('*.json')]


def test_start_acknowledge_and_project_target_changes(titles):
    first = emitted(event())
    assert first == 'raptor · alpha · first'
    assert states()[0]['confirmed'] is None
    assert emitted(event(title=first, turn=True)) is None
    assert states()[0]['confirmed'] == first
    titles[:] = ['beta', '/targets/second']
    second = emitted(event(title=first, turn=True))
    assert second == 'raptor · beta · second'
    assert states()[0]['confirmed'] == first
    assert emitted(event(title=second, source='resume')) is None
    titles[:] = ['beta', '/targets/third']
    assert emitted(event(title=second, turn=True)) == 'raptor · beta · third'


@pytest.mark.skipif(not hasattr(os, 'O_PATH'), reason='Linux protected-launch metadata')
def test_protected_resume_retains_managed_title_ownership(titles, tmp_path, monkeypatch):
    from core.startup.install_guard import prepare_session_registry
    original = os.environ['RAPTOR_REGISTRY_HOME']
    prepare_session_registry('claude', owned_root=tmp_path / 'launch-one')
    first_registry = os.environ['RAPTOR_REGISTRY_HOME']
    first = emitted(event())
    assert emitted(event(title=first, turn=True)) is None
    shutil.rmtree(tmp_path / 'launch-one')
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', original)
    prepare_session_registry('claude', owned_root=tmp_path / 'launch-two')
    assert os.environ['RAPTOR_REGISTRY_HOME'] != first_registry
    titles[:] = ['beta', '/targets/second']
    assert emitted(event(title=first, source='resume')) == 'raptor · beta · second'


def test_legacy_title_state_is_migrated_without_losing_manual_preference(titles):
    legacy = registry_home.sessions_dir() / '.titles'
    first = policy.request_title(legacy, 'claude', 'session-one', 'raptor · alpha · first', None)
    policy.request_title(legacy, 'claude', 'session-one', first, 'My investigation')
    assert emitted(event(title='My investigation', source='resume')) is None
    assert states()[0]['manual'] is True
    assert next(legacy.glob('*.json')).exists()


def test_legacy_managed_title_remains_automatic_after_migration(titles):
    legacy = registry_home.sessions_dir() / '.titles'
    first = policy.request_title(legacy, 'claude', 'session-one', 'raptor · alpha · first', None)
    policy.request_title(legacy, 'claude', 'session-one', first, first)
    titles[:] = ['beta', '/targets/second']
    assert emitted(event(title=first, source='resume')) == 'raptor · beta · second'
    assert states()[0]['confirmed'] == first


def test_bad_legacy_state_is_not_reset_as_a_new_session(titles):
    legacy = registry_home.sessions_dir() / '.titles'
    policy.request_title(legacy, 'claude', 'session-one', 'raptor · alpha · first', None)
    next(legacy.glob('*.json')).write_text('null')
    with pytest.raises(ValueError):
        emitted(event())
    assert states() == []


def test_migration_preserves_exhausted_retry_budget(titles):
    legacy = registry_home.sessions_dir() / '.titles'
    for _ in range(3):
        policy.request_title(legacy, 'claude', 'session-one', 'raptor · alpha · first', None)
    assert emitted(event(source='resume')) is None
    assert states()[0]['attempts'] == 3
    assert states()[0]['manual'] is False


@pytest.mark.parametrize('kind', ['symlink', 'fifo'])
def test_legacy_state_cannot_follow_a_link_or_read_a_pipe(titles, tmp_path, kind):
    if kind == 'fifo' and not hasattr(os, 'mkfifo'):
        pytest.skip('POSIX FIFO test')
    legacy = registry_home.sessions_dir() / '.titles'
    policy.request_title(legacy, 'claude', 'session-one', 'raptor · alpha · first', None)
    path = next(legacy.glob('*.json'))
    source = tmp_path / 'source.json'
    source.write_bytes(path.read_bytes())
    path.unlink()
    if kind == 'symlink':
        path.symlink_to(source)
    else:
        os.mkfifo(path, 0o600)
    with pytest.raises((OSError, ValueError)):
        emitted(event())
    assert states() == []


def test_custom_title_before_start_and_manual_rename_are_preserved(titles):
    assert emitted(event('custom', title='My investigation')) is None
    first = emitted(event())
    assert emitted(event(title=first, turn=True)) is None
    assert emitted(event(title='Hand picked', turn=True)) is None
    titles[:] = ['changed', '/other/target']
    assert emitted(event(title='Hand picked', source='resume')) is None
    assert emitted(event(title=first, turn=True)) is None  # Manual choice is latched.


def test_failed_rename_retries_are_bounded_without_false_confirmation(titles):
    first = emitted(event())
    assert emitted(event(title=first, turn=True)) is None
    titles[:] = ['beta', '/targets/new']
    for _ in range(3):
        assert emitted(event(title=first, turn=True)) == 'raptor · beta · new'
    assert emitted(event(title=first, turn=True)) is None
    state = states()[0]
    assert state['confirmed'] == first
    assert state['requested'] != first
    assert state['attempts'] == 3


def test_older_client_without_title_feedback_is_not_rewritten_on_turn(titles):
    emitted(event())
    before = states()
    titles[:] = ['beta', '/targets/new']
    assert emitted(event(turn=True)) is None
    assert states() == before


def test_fork_does_not_take_over_parent_custom_title(titles):
    first = emitted(event())
    assert emitted(event('forked', title=first, source='fork')) is None
    assert len(states()) == 2


def test_independent_sessions_do_not_share_manual_or_pending_state(tmp_path):
    directory = tmp_path / 'titles'
    def request(number):
        return policy.request_title(directory, 'claude', f'session-{number}',
                                    f'raptor · project-{number}', None)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(request, range(8)))
    assert results == [f'raptor · project-{number}' for number in range(8)]
    assert len(list(directory.glob('*.json'))) == 8
    assert policy.request_title(directory, 'claude', 'session-0', 'new', 'Manual') is None
    assert policy.request_title(directory, 'claude', 'session-1', 'new', results[1]) == 'new'


def test_same_session_parallel_requests_do_not_lose_retry_budget(tmp_path):
    directory = tmp_path / 'titles'
    def request(_):
        try:
            return policy.request_title(directory, 'claude', 'same', 'raptor · alpha', None)
        except TimeoutError:
            return None  # A contended optional hook may skip this turn.
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(request, range(8)))
    assert sum(value is not None for value in results) == 3
    state = load_json(next(directory.glob('*.json')), strict=True)
    assert state['attempts'] == 3 and state['confirmed'] is None


@pytest.mark.parametrize('identity', ['../other', '/tmp/other', 'x' * 129, '', 'bad\nidentity'])
def test_unusable_identity_cannot_select_another_state_file(titles, identity):
    with pytest.raises(ValueError):
        hook.hook_output(event(identity))
    assert not policy.state_directory().exists()


@pytest.mark.parametrize('failure', [errno.ENOSPC, errno.EROFS, errno.EACCES])
def test_state_write_failure_is_nonfatal_and_can_retry(titles, monkeypatch, capsys, failure):
    real = policy.save_json
    def refuse(*args, **kwargs):
        raise OSError(failure, 'owned state unavailable')
    with monkeypatch.context() as patch:
        patch.setattr(policy, 'save_json', refuse)
        patch_module_attribute(patch, hook, 'sys', 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(event()).encode())))
        assert hook.main() == 0
        assert capsys.readouterr().out == ''
    assert policy.save_json is real
    assert states() == []
    assert emitted(event()) == 'raptor · alpha · first'


def test_busy_lock_skips_instead_of_writing_unlocked(titles, monkeypatch, capsys):
    from contextlib import contextmanager
    @contextmanager
    def busy(*args, **kwargs):
        assert kwargs['required'] is True and kwargs['deadline_s'] <= .1
        raise TimeoutError('owned lock busy')
        yield
    monkeypatch.setattr(policy, 'sidecar_flock', busy)
    patch_module_attribute(monkeypatch, hook, 'sys', 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(event()).encode())))
    assert hook.main() == 0
    assert capsys.readouterr().out == ''
    assert states() == []


def test_context_uses_own_binding_and_never_the_global_bookmark(tmp_path, monkeypatch):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    pid = os.getpid()
    monkeypatch.setattr(sessions, '_comm', lambda process: 'claude')
    sessions.record_session('alpha', pid=pid, token='a' * 64)
    entry = sessions._parse_entry(sessions._sessions_dir() / str(pid))
    monkeypatch.setenv(sessions.ENV_SESSION_PID, str(pid))
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, entry['token'])
    projects = registry_home.projects_dir()
    save_json(projects / 'alpha.json', {'target': '/targets/alpha'})
    save_json(projects / 'foreign.json', {'target': '/targets/foreign'})
    registry_home.active_link().symlink_to('foreign.json')
    assert hook._context() == ('alpha', '/targets/alpha')
    save_json(projects / 'alpha.json', {'target': '/targets/changed'})
    assert hook._context() == ('alpha', '/targets/changed')
    sessions.bind_session(None, pid=pid)
    monkeypatch.delenv('RAPTOR_SESSION_TARGET', raising=False)
    monkeypatch.delenv('RAPTOR_SESSION_TARGET', raising=False)
    assert hook._context() == (None, None)
    monkeypatch.setenv('RAPTOR_SESSION_TARGET', '/initial/standalone')
    assert hook._context() == (None, '/initial/standalone')
    run = tmp_path / 'scan-owned'
    run.mkdir()
    save_json(run / '.raptor-run.json', {'target_path': '/changed/standalone'})
    sessions.ledger_record_start(run, pid=pid, pin_project=None, record_pin=True)
    assert hook._context() == (None, '/changed/standalone')
    # An unrelated/mismatched project witness must not steer this session.
    sessions.ledger_record_start(run, pid=pid, pin_project='foreign', record_pin=True)
    assert hook._context() == (None, '/initial/standalone')
    monkeypatch.setattr(sessions, 'resolve_session_pid', lambda: None)
    assert hook._context() is None


def test_title_has_no_terminal_controls_or_full_target_path():
    title = policy.context_title('a\x1b[2J\nb', '/private/operator/path/target\u202e')
    assert len(title) <= 160
    assert all(char.isprintable() for char in title)
    assert '/private/operator' not in title


def test_hook_registration_is_optional_and_covers_resume_and_turns():
    root = Path(__file__).resolve().parents[3]
    hooks = load_json(root / '.claude/settings.json', strict=True)['hooks']
    for name in ('SessionStart', 'UserPromptSubmit'):
        found = [entry for group in hooks[name] for entry in group['hooks']
                 if 'raptor-session-title' in entry.get('command', '')]
        assert len(found) == 1
        assert found[0]['timeout'] <= 2
        assert found[0]['command'].endswith('|| true')


@pytest.mark.parametrize('payload', [{}, [], {'hook_event_name': 'Stop'},
                                    event(source='compact'), event(title=['invalid'])])
def test_unsupported_payloads_do_not_change_state(titles, payload):
    assert hook.hook_output(payload) == {}
    assert states() == []


def test_corrupt_state_cannot_be_replaced_as_a_fresh_automatic_session(titles, monkeypatch, capsys):
    emitted(event())
    path = next(policy.state_directory().glob('*.json'))
    path.write_text('{bad json')
    patch_module_attribute(monkeypatch, hook, 'sys', 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(event()).encode())))
    assert hook.main() == 0
    assert capsys.readouterr().out == ''
    assert path.read_text() == '{bad json'


def test_title_directory_symlink_is_not_followed(titles, tmp_path):
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    policy.state_directory().parent.mkdir(parents=True)
    policy.state_directory().symlink_to(foreign, target_is_directory=True)
    with pytest.raises(PermissionError):
        emitted(event())
    assert list(foreign.iterdir()) == []


def test_hook_entrypoint_emits_native_protocol_and_invalid_input_is_optional(tmp_path):
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[3]
    registry = tmp_path / 'registry'
    home = tmp_path / 'home'
    home.mkdir()
    temporary = tmp_path / 'tmp'
    temporary.mkdir()
    # Missing/unowned session context is intentionally a successful no-op.
    env = {'HOME': str(home), 'TMPDIR': str(temporary), 'PATH': os.environ['PATH'],
           'RAPTOR_REGISTRY_HOME': str(registry), '_RAPTOR_TRUSTED': '1'}
    for data in (json.dumps(event()), '{bad', 'x' * 65537):
        result = subprocess.run([sys.executable, str(root / 'libexec/raptor-session-title')],
                                input=data, capture_output=True, text=True,
                                env=env, timeout=5)
        assert result.returncode == 0, result.stderr
        assert result.stdout == ''


def test_successful_hook_main_emits_only_native_title_json(titles, monkeypatch, capsys):
    patch_module_attribute(monkeypatch, hook, 'sys', 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(event()).encode())))
    assert hook.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {'hookSpecificOutput': {'hookEventName': 'SessionStart',
                                           'sessionTitle': 'raptor · alpha · first'}}
    assert states()[0]['confirmed'] is None


def test_hook_entrypoint_help_retains_trust_guard(tmp_path):
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[3]
    env = {'HOME': str(tmp_path), 'TMPDIR': str(tmp_path),
           'PATH': os.environ['PATH'], '_RAPTOR_TRUSTED': '1'}
    command = [sys.executable, str(root / 'libexec/raptor-session-title'), '--help']
    result = subprocess.run(command, input='{bad', capture_output=True,
                            text=True, env=env, timeout=5)
    assert result.returncode == 0, result.stderr
    assert 'usage:' in result.stdout
    assert 'SessionStart' in result.stdout
    assert 'Examples:' in result.stdout
    assert result.stderr == ''
    env.pop('_RAPTOR_TRUSTED')
    rejected = subprocess.run(command, input='', capture_output=True,
                              text=True, env=env, timeout=5)
    assert rejected.returncode == 2
    assert 'internal dispatch script' in rejected.stderr
    assert rejected.stdout == ''


@pytest.mark.parametrize('flag', ['-h', '--help'])
def test_help_does_not_read_hook_input_or_state(flag, monkeypatch, capsys):
    class NoInput:
        @property
        def buffer(self):
            raise AssertionError('help must not read hook stdin')

    def no_context():
        raise AssertionError('help must not resolve session state')

    patch_module_attribute(monkeypatch, hook, 'sys', 'stdin', NoInput())
    monkeypatch.setattr(hook, '_context', no_context)
    with pytest.raises(SystemExit) as stopped:
        hook.main([flag])
    assert stopped.value.code == 0
    output = capsys.readouterr()
    assert 'usage:' in output.out
    assert 'Examples:' in output.out
    assert output.err == ''

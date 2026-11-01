"""Supervisor launch-gating, portable fallback and single-execution behavior."""
import errno
import os
import sys

import pytest

from core.security import launch_scratch, scratch_supervisor as supervisor


@pytest.fixture
def owned(tmp_path, monkeypatch):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    family = tmp_path / f'raptor-{os.geteuid()}'
    family.mkdir(mode=0o700)
    root = family / f'session-{os.getpid()}-123'
    root.mkdir(mode=0o700)
    metadata = launch_scratch.create(root)
    session_id = supervisor.lifecycle.register(metadata, os.getpid())
    authorization = launch_scratch.issue(tmp_path / 'authorities', metadata, os.getpid())
    monkeypatch.setenv('_RAPTOR_SCRATCH_AUTH', authorization)
    return root, metadata, session_id


def test_failed_attachment_never_executes_the_payload(tmp_path):
    marker = tmp_path / 'executed'
    class Refused:
        def attach(self, pid):
            raise OSError(errno.EACCES, 'no cgroup delegation')
    command = [sys.executable, '-I', '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).touch()', str(marker)]
    with pytest.raises(OSError):
        supervisor._spawn(command, Refused())
    assert not marker.exists()


def test_portable_fallback_preserves_exit_status_and_retains_uncertain_scratch(owned, tmp_path, monkeypatch):
    root, metadata, session_id = owned
    def unavailable(*args):
        raise OSError(errno.EROFS, 'no delegation')
    monkeypatch.setattr(supervisor.cgroups.Scope, 'create', unavailable)
    monkeypatch.setattr(supervisor, '_can_delegate', lambda *a: False)
    marker = tmp_path / 'executions'
    command = [sys.executable, '-I', '-c',
               'import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("once");sys.exit(7)', str(marker)]
    assert supervisor.supervise(metadata, command, allow_degraded=True) == 7
    assert marker.read_text() == 'once'
    assert root.exists()
    with supervisor.lifecycle.locked(session_id) as (_, value):
        assert value['state'] == 'retained'
        assert value['closure'] is None
        assert value['backend'] == 'untracked'


def test_claimed_delegated_failure_cannot_rerun_payload_portably(owned, monkeypatch):
    _, metadata, _ = owned
    monkeypatch.setattr(supervisor, '_delegated', lambda *a: 125)
    monkeypatch.setattr(supervisor, '_try_delegated', lambda *a: 126)
    def no_duplicate(*args):
        pytest.fail('a delegated failure must not execute the command twice')
    monkeypatch.setattr(supervisor, '_spawn', no_duplicate)
    assert supervisor.supervise(metadata, ['/never-execute']) == 126


def test_forged_metadata_cannot_redirect_a_valid_launch_authorization(owned, tmp_path):
    _, _, _ = owned
    with pytest.raises(PermissionError):
        supervisor.supervise(tmp_path / 'another/metadata/launch.json', ['/never-execute'])


def test_missing_cgroup_filesystem_is_optional(monkeypatch):
    def unavailable(path):
        raise FileNotFoundError
    monkeypatch.setattr(supervisor.os, 'statvfs', unavailable)
    assert supervisor._can_delegate() is False


def test_live_controller_is_not_recovered_as_an_orphan(owned):
    root, _, session_id = owned
    with supervisor.lifecycle.locked(session_id) as (node, value):
        value['backend'] = 'cgroup-v2'
        value['scope'] = {'path': '/never-open-a-live-scope', 'identity': [1, 2]}
        supervisor.lifecycle._write(node, session_id + '.json', value)
    assert supervisor.lifecycle.cleanup(session_id) == 'retained'
    assert root.exists()


def test_hidden_namespace_cannot_mistake_a_controller_for_dead(owned, monkeypatch):
    root, _, session_id = owned
    with supervisor.lifecycle.locked(session_id) as (node, value):
        recorded = value['owner_birth']
        if recorded.get('platform') != 'linux':
            pytest.skip('Linux namespace identity')
        value['backend'] = 'cgroup-v2'
        value['scope'] = {'path': '/never-open-an-unproven-scope', 'identity': [1, 2]}
        supervisor.lifecycle._write(node, session_id + '.json', value)
    monkeypatch.setattr(supervisor.lifecycle.scratch(), '_birth',
                        lambda pid: dict(recorded, pidns='different-pid-view'))
    assert supervisor.lifecycle.cleanup(session_id) == 'retained'
    assert root.exists()


def test_noninteractive_downgrade_requires_explicit_approval(monkeypatch, capsys):
    monkeypatch.setattr(supervisor, '_terminal_may_ask', lambda: False)
    assert supervisor._accept_degraded() is False
    text = capsys.readouterr().err
    assert 'refused' in text and '--allow-degraded-cleanup' in text
    assert supervisor._accept_degraded(True) is True


@pytest.mark.parametrize('answer,expected', [('y\n', True), ('\n', True), ('n\n', False), ('', False)])
def test_interactive_downgrade_requires_an_answer(monkeypatch, answer, expected):
    import io
    class Terminal(io.StringIO):
        def isatty(self): return True
    monkeypatch.setattr(supervisor, '_terminal_may_ask', lambda: True)
    monkeypatch.setattr(supervisor.sys, 'stdin', Terminal(answer))
    monkeypatch.setattr(supervisor.sys, 'stderr', Terminal())
    assert supervisor._accept_degraded() is expected
    assert 'Continue with degraded cleanup?' in supervisor.sys.stderr.getvalue()


def test_declined_downgrade_never_starts_frontend_and_cleans_unused_root(owned, monkeypatch):
    root, metadata, _ = owned
    monkeypatch.setattr(supervisor, '_delegated', lambda *a: 125)
    monkeypatch.setattr(supervisor, '_try_delegated', lambda *a: None)
    monkeypatch.setattr(supervisor, '_accept_degraded', lambda *a: False)
    def no_execution(*args):
        pytest.fail('declined launch must not execute the frontend')
    monkeypatch.setattr(supervisor, '_spawn', no_execution)
    monkeypatch.setattr(supervisor, '_terminal_may_ask', lambda: True)
    assert supervisor.supervise(metadata, ['/never-run']) == 130
    assert not root.exists()


def test_group_attachment_failure_rolls_back_and_runs_once_in_degraded_mode(owned, tmp_path, monkeypatch):
    _, metadata, session_id = owned
    class RefusedScope:
        def __init__(self, path):
            self.path = path
            self.identity = [1, 2]
        @classmethod
        def create(cls, parent=None): return cls(tmp_path / ('front' if parent else 'scope'))
        def attach(self, pid): raise PermissionError('attachment refused')
        def close_admission(self): pass
        def stop(self): pass
        def release(self): pass
        def close(self): pass
    monkeypatch.setattr(supervisor.cgroups, 'Scope', RefusedScope)
    monkeypatch.setattr(supervisor, '_try_delegated', lambda *a: None)
    monkeypatch.setattr(supervisor, '_accept_degraded', lambda *a: True)
    output = tmp_path / 'executions'
    command = [sys.executable, '-I', '-c',
               'import sys;open(sys.argv[1],"a").write("once\\n")', str(output)]
    assert supervisor.supervise(metadata, command, allow_degraded=True) == 0
    assert output.read_text() == 'once\n'
    with supervisor.lifecycle.locked(session_id) as (_, value):
        assert value['backend'] == 'untracked'
        assert value['state'] == 'retained'
        assert 'scope' not in value


def test_unavailable_optional_group_module_does_not_block_launch(owned, monkeypatch):
    _, metadata, _ = owned
    monkeypatch.setattr(supervisor, 'cgroups', None)
    monkeypatch.setattr(supervisor, '_accept_degraded', lambda *a: True)
    assert supervisor.supervise(metadata, [sys.executable, '-I', '-c', 'raise SystemExit(6)'], allow_degraded=True) == 6


def _terminal_roundtrip(tmp_path):
    import errno
    import pty
    import select
    import signal
    import time
    report = tmp_path / 'interrupts'
    pid, terminal = pty.fork()
    if pid == 0:
        code = r'''
import pathlib,signal,sys
report=pathlib.Path(sys.argv[1])
def interrupt(*args):
    with report.open('a') as stream: stream.write('interrupt\n')
    print('INTERRUPTED',flush=True)
signal.signal(signal.SIGINT,interrupt)
print('READY',flush=True)
sys.stdin.readline()
sys.exit(7)
'''
        try:
            result = supervisor._spawn([sys.executable, '-I', '-c', code, str(report)])
            os._exit(supervisor._result(result))
        except BaseException:
            os._exit(126)
    reaped = False
    try:
        data = b''
        deadline = time.monotonic() + 5
        for expected in (b'READY', b'INTERRUPTED'):
            while expected not in data and time.monotonic() < deadline:
                if select.select([terminal], [], [], .1)[0]:
                    try:
                        data += os.read(terminal, 4096)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            break
                        raise
            assert expected in data, data
            if expected == b'READY':
                os.write(terminal, b'\x03')
        os.write(terminal, b'quit\n')
        while time.monotonic() < deadline:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                reaped = True
                assert os.waitstatus_to_exitcode(status) == 7
                break
            time.sleep(.02)
        assert reaped, 'supervisor did not preserve terminal completion'
        assert report.read_text() == 'interrupt\n'
    finally:
        os.close(terminal)
        if not reaped:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


def test_supervised_command_keeps_terminal_interrupt_and_exit_status(tmp_path):
    from pathlib import Path
    import subprocess
    # Run forkpty in a fresh interpreter, outside pytest/plugin worker threads.
    code = ("import pathlib,runpy,sys;sys.path.insert(0,sys.argv[1]);"
            "module=runpy.run_path(sys.argv[2]);"
            "module['_terminal_roundtrip'](pathlib.Path(sys.argv[3]))")
    result = subprocess.run([sys.executable, '-I', '-c', code,
                             str(Path(__file__).resolve().parents[3]), str(Path(__file__).resolve()),
                             str(tmp_path)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_tracking_group_empty_does_not_authorize_scratch_deletion(owned):
    root, _, session_id = owned
    class Empty:
        def __init__(self): self.released = False
        def close_admission(self): pass
        def stop(self, **kwargs): return False
        def release(self): self.released = True
    scope, front = Empty(), Empty()
    with supervisor.lifecycle.locked(session_id) as (node, value):
        value.update(backend='cgroup-v2-tracking', state='active',
                     scope={'path': '/not-recovered', 'identity': [1, 2]})
        supervisor.lifecycle._write(node, session_id + '.json', value)
    assert supervisor._finish(session_id, scope, front, 7) == 7
    assert scope.released and front.released
    assert root.exists()
    assert supervisor.lifecycle.cleanup(session_id) == 'retained'
    with supervisor.lifecycle.locked(session_id) as (_, value):
        assert value['closure'] is None
        assert value['state'] == 'retained'


def test_shutdown_allows_audit_salvage_before_forced_kill(monkeypatch):
    from types import SimpleNamespace
    handlers = {}
    clock = [0.0]
    kills = []
    polls = [0]
    def install(signum, callback):
        old = handlers.get(signum)
        handlers[signum] = callback
        return old
    def wait(child, flags):
        polls[0] += 1
        if polls[0] == 1:
            handlers[15](15, None)
        if kills and kills[-1][1] == 9:
            return child, 9
        return 0, 0
    def sleep(seconds): clock[0] += 1
    monkeypatch.setattr(supervisor, 'signal', SimpleNamespace(
        SIGTERM=15, SIGHUP=1, SIGINT=2, SIGKILL=9, SIG_IGN=object(), signal=install))
    monkeypatch.setattr(supervisor, 'time', SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    monkeypatch.setattr(supervisor, 'os', SimpleNamespace(
        WNOHANG=1, waitpid=wait, waitstatus_to_exitcode=lambda status: -status,
        kill=lambda child, signum: kills.append((clock[0], signum))))
    assert supervisor._wait(123) == -9
    assert kills[0] == (0.0, 15)
    assert kills[-1][0] >= 30


def test_missing_tracking_controller_is_not_permission_to_kill_or_delete(owned, monkeypatch):
    root, _, session_id = owned
    with supervisor.lifecycle.locked(session_id) as (node, value):
        value.update(backend='cgroup-v2-tracking', owner_pid=999999999,
                     scope={'path': '/never-touch-an-unproven-group', 'identity': [1, 2]})
        supervisor.lifecycle._write(node, session_id + '.json', value)
    def no_recovery(*args):
        pytest.fail('ordinary cleanup must not kill orphaned tracking-only work')
    monkeypatch.setattr(supervisor.cgroups.Scope, 'recover', no_recovery)
    assert supervisor.lifecycle.cleanup(session_id) == 'retained'
    assert root.exists()


@pytest.mark.parametrize('scoped', [False, True])
def test_service_scratch_follows_the_tracked_session_only(tmp_path, monkeypatch, scoped):
    monkeypatch.setenv('_RAPTOR_JOERN_TMP_BASE', '/operator/original-base')
    session = tmp_path / 'private-session-tmp'
    session.mkdir()
    receipt = tmp_path / 'service-path'
    class Scope:
        def attach(self, pid):
            assert not receipt.exists(), 'frontend ran before scope attachment'
    command = [sys.executable, '-I', '-c',
               'import os,pathlib,sys;pathlib.Path(sys.argv[1]).write_text(os.environ["_RAPTOR_JOERN_TMP_BASE"])',
               str(receipt)]
    assert supervisor._spawn(command, Scope() if scoped else None,
                             service_scratch=session if scoped else None) == 0
    assert receipt.read_text() == (str(session) if scoped else '/operator/original-base')
    assert os.environ['_RAPTOR_JOERN_TMP_BASE'] == '/operator/original-base'


def test_stalled_manager_is_reaped_and_late_claim_is_revoked(owned, monkeypatch):
    import subprocess
    import time
    _, metadata, session_id = owned
    launch = subprocess.Popen
    started = []
    attempts = []
    def manager(command):
        attempts.append(command[command.index('--attempt') + 1])
        process = launch([sys.executable, '-I', '-c', 'import time;time.sleep(30)'])
        started.append(process)
        return process
    monkeypatch.setattr(supervisor, '_can_delegate', lambda: True)
    monkeypatch.setattr(supervisor.subprocess, 'Popen', manager)
    monkeypatch.setattr(supervisor, '_DELEGATION_START_SECONDS', .05)
    before = time.monotonic()
    assert supervisor._try_delegated(metadata, session_id, ['/never-run']) is None
    assert time.monotonic() - before < 5
    assert started[0].returncode == -9
    with pytest.raises(ChildProcessError):
        os.waitpid(started[0].pid, os.WNOHANG)
    with pytest.raises(PermissionError, match='no longer current'):
        supervisor._claim(session_id, 'cgroup-v2-tracking', attempt=attempts[0])
    with supervisor.lifecycle.locked(session_id) as (_, value):
        assert value['state'] == 'retained'
        assert 'delegation_attempt' not in value


def test_startup_deadline_cannot_cancel_a_claimed_frontend(owned, monkeypatch):
    from types import SimpleNamespace
    _, metadata, session_id = owned
    monkeypatch.setattr(supervisor, '_can_delegate', lambda: True)
    monkeypatch.setattr(supervisor, 'subprocess', SimpleNamespace(
        Popen=lambda command: SimpleNamespace(pid=123, returncode=None)))
    monkeypatch.setattr(supervisor, '_DELEGATION_START_SECONDS', -1)
    def wait(child, *, startup_expired):
        with supervisor.lifecycle.locked(session_id) as (_, value):
            attempt = value['delegation_attempt']
        scope = SimpleNamespace(path=metadata.parent / 'scope', identity=[1, 2])
        supervisor._claim(session_id, 'cgroup-v2-tracking', scope, scope, attempt=attempt)
        assert startup_expired() is False
        return 7
    monkeypatch.setattr(supervisor, '_wait', wait)
    assert supervisor._try_delegated(metadata, session_id, ['/already-running']) == 7


def test_wait_failure_stops_claimed_group_without_deleting_uncertain_scratch(owned, tmp_path, monkeypatch):
    root, _, session_id = owned
    scopes = []
    class TrackingScope:
        def __init__(self, path):
            self.path = path
            self.identity = [1, 2]
            self.stopped = self.released = False
        @classmethod
        def create(cls, parent=None):
            scope = cls(tmp_path / ('front' if parent else 'scope'))
            scopes.append(scope)
            return scope
        def close_admission(self): pass
        def stop(self, **kwargs): self.stopped = True; return True
        def release(self): self.released = True
        def close(self): pass
    def lost_wait(*args, **kwargs):
        raise OSError('lost frontend wait after release')
    monkeypatch.setattr(supervisor.cgroups, 'Scope', TrackingScope)
    monkeypatch.setattr(supervisor, '_spawn', lost_wait)
    assert supervisor._delegated(session_id, ['/already-released']) == 126
    assert scopes[0].stopped and all(scope.released for scope in scopes)
    assert root.exists()
    with supervisor.lifecycle.locked(session_id) as (_, value):
        assert value['state'] == 'retained'
        assert value['closure'] is None

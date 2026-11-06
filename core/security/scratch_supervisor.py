"""Outside launcher supervisor for optional delegated cgroup scratch cleanup."""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import signal
import secrets
import subprocess
import sys
import time


def _module(name):
    spec = importlib.util.spec_from_file_location('raptor_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SHUTDOWN_GRACE_SECONDS = 30.0
_GROUP_DRAIN_GRACE_SECONDS = 10.0
_DELEGATION_START_SECONDS = 10.0

lifecycle = _module('scratch_lifecycle')
_CGROUP_LOAD_ERROR = None
try:
    cgroups = _module('cgroup_scope')
except (OSError, ImportError, SyntaxError) as exc:
    cgroups = None
    _CGROUP_LOAD_ERROR = str(exc)[:512]


def _record_tracking_failure(session_id: str, stage: str, error) -> None:
    """Keep bounded diagnostics in the private record, away from startup UX."""
    cause = getattr(error, '__cause__', None) or error
    item = {'stage': stage, 'error': str(cause)[:512]}
    if isinstance(cause, OSError):
        item['errno'] = cause.errno
    with lifecycle.locked(session_id) as (node, value):
        diagnostics = value.setdefault('tracking_diagnostics', [])
        if len(diagnostics) < 6:
            diagnostics.append(item)
        lifecycle._write(node, session_id + '.json', value)


def _authorized(metadata: Path) -> str:
    bound, _ = lifecycle.scratch()._restore_authorized(os.environ.get('_RAPTOR_SCRATCH_AUTH', ''))
    if bound != metadata:
        raise PermissionError('scratch scope does not belong to this launcher')
    return lifecycle.session_for(metadata)


def _claim(session_id: str, backend: str, scope=None, front=None, *, attempt: str | None = None) -> tuple[int, dict]:
    identity = None
    if scope is not None:
        identity = {'path': str(scope.path), 'identity': scope.identity,
                    'frontend': {'path': str(front.path), 'identity': front.identity}}
    return lifecycle.claim(session_id, backend, identity, attempt=attempt)


def _wait(child: int, *, startup_expired=None) -> int:
    requested = []
    previous = {}
    def request(signum, _frame):
        requested.append(signum)
    for signum in (signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.signal(signum, request)
    previous[signal.SIGINT] = signal.signal(signal.SIGINT, signal.SIG_IGN)
    shutdown = None
    try:
        while True:
            pid, status = os.waitpid(child, os.WNOHANG)
            if pid:
                return os.waitstatus_to_exitcode(status)
            if startup_expired is not None and startup_expired():
                # The callback revoked the unclaimed attempt under the same
                # lock used by _claim. A late manager cannot release payload.
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                startup_expired = None
            if requested:
                signum = requested.pop(0)
                try:
                    os.kill(child, signum)
                except ProcessLookupError:
                    pass
                if shutdown is None:
                    shutdown = time.monotonic() + _SHUTDOWN_GRACE_SECONDS
            if shutdown is not None and time.monotonic() >= shutdown:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            time.sleep(.02)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


class LaunchNotStarted(OSError):
    """The child was reaped behind its gate; payload execution never began."""


def _spawn(command: list[str], scope=None, *, service_scratch: Path | None = None) -> int:
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(write)
        try:
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(signum, signal.SIG_DFL)
            if os.read(read, 1) != b'1':
                os._exit(125)
            os.close(read)
            if service_scratch is not None:
                os.environ['_RAPTOR_JOERN_TMP_BASE'] = str(service_scratch)
            os.execvpe(command[0], command, os.environ)
        except BaseException:
            os.write(2, b'raptor: unable to start supervised command\n')
            os._exit(126)
    os.close(read)
    # The payload can become terminal-ready as soon as its gate opens.
    # Protect the supervisor before that release, not only inside _wait.
    previous_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        released = False
        try:
            if scope is not None:
                scope.attach(child)
            os.write(write, b'1')
            released = True
        except (OSError, ValueError) as exc:
            raise LaunchNotStarted('scope attachment failed before payload execution') from exc
        finally:
            os.close(write)
            if not released:
                # Closing the gate makes the child exit without executing payload.
                os.waitpid(child, 0)
        return _wait(child)
    finally:
        signal.signal(signal.SIGINT, previous_int)


def _result(code: int) -> int:
    return 128 - code if code < 0 else code


def _finish(session_id: str, scope, front, code: int) -> int:
    group_closed = False
    try:
        front.close_admission()
        scope.close_admission()
        killed = scope.stop(grace=_GROUP_DRAIN_GRACE_SECONDS)
        group_closed = True
        if killed:
            print('raptor: stopped remaining processes at session shutdown', file=sys.stderr)
        # An unrestricted frontend can migrate itself or ask a service manager
        # to start work outside this group. Empty membership is useful tracking,
        # not proof that scratch has no remaining users. A protected lifecycle
        # backend must supply that stronger evidence before automatic deletion.
        with lifecycle.locked(session_id) as (node, value):
            value.update(state='retained', closure=None,
                         reason='tracked group ended; external scratch users cannot be excluded')
            lifecycle._write(node, session_id + '.json', value)
        print(f'raptor: session {session_id}: scratch retained; inspect with bin/raptor cleanup --list',
              file=sys.stderr)
    except (OSError, ValueError, TypeError):
        try:
            with lifecycle.locked(session_id) as (node, value):
                if value['state'] != 'removed':
                    value.update(state='cleanup-error', reason='session teardown or cleanup incomplete')
                    lifecycle._write(node, session_id + '.json', value)
        except (OSError, ValueError, TypeError):
            pass
        print(f'raptor: session {session_id}: cleanup incomplete; inspect with bin/raptor cleanup --list',
              file=sys.stderr)
    finally:
        if group_closed:
            try:
                front.release()
                scope.release()
            except (OSError, ValueError):
                print(f'raptor: session {session_id}: empty cgroup cleanup incomplete', file=sys.stderr)
    return _result(code)


def _delegated(session_id: str, command: list[str], *, attempt: str | None = None) -> int:
    scope = front = None
    claimed = False
    stage = 'create session cgroup'
    try:
        scope = cgroups.Scope.create()
        stage = 'create frontend cgroup'
        front = cgroups.Scope.create(scope.path)
        previous_owner = _claim(session_id, 'cgroup-v2-tracking', scope, front, attempt=attempt)
        claimed = True
        try:
            with lifecycle.locked(session_id) as (_, value):
                service_scratch = Path(value['root']) / 'tmp'
            code = _spawn(command, front, service_scratch=service_scratch)
        except LaunchNotStarted as exc:
            _record_tracking_failure(session_id, "attach frontend to cgroup", exc)
            # Attachment/setup failure is optional for a launcher session. The
            # blocked child has been reaped, so rollback cannot run it twice.
            with lifecycle.locked(session_id) as (node, value):
                value.update(owner_pid=previous_owner[0], owner_birth=previous_owner[1],
                             state='retained', backend='untracked', reason='cgroup attachment unavailable')
                value.pop('scope', None)
                lifecycle._write(node, session_id + '.json', value)
            claimed = False
            return 125
        return _finish(session_id, scope, front, code)
    except (OSError, ValueError, TypeError) as exc:
        _record_tracking_failure(session_id, stage, exc)
        if claimed:
            print(f'raptor: session {session_id}: supervision failed; stopping tracked work', file=sys.stderr)
            return _finish(session_id, scope, front, 126)
        return 125  # Caller may fall back only if control state confirms no claim.
    finally:
        for item in (front, scope):
            if item is not None:
                if not claimed:
                    try:
                        item.close_admission()
                        item.stop()
                        item.release()
                    except (OSError, ValueError):
                        pass
                item.close()


def _delegation_unavailable_reason() -> str | None:
    if sys.platform != 'linux':
        return 'systemd cgroup delegation requires Linux'
    if cgroups is None:
        return f'cgroup backend could not be loaded: {_CGROUP_LOAD_ERROR or "unavailable"}'
    try:
        if os.statvfs(cgroups.CGROUP_ROOT).f_flag & os.ST_RDONLY:
            return 'cgroup mount is read-only; use a host session or a delegated container'
        if not os.access('/usr/bin/systemd-run', os.X_OK):
            return 'systemd-run is unavailable'
        runtime = Path(os.environ.get('XDG_RUNTIME_DIR') or f'/run/user/{os.geteuid()}')
        if not os.environ.get('DBUS_SESSION_BUS_ADDRESS') and not (runtime / 'bus').exists():
            return 'no systemd user bus; use a login session with a running user manager'
    except OSError as exc:
        return f'cgroup delegation prerequisites unavailable (errno={exc.errno})'
    return None


def _can_delegate() -> bool:
    return _delegation_unavailable_reason() is None


def _try_delegated(metadata: Path, session_id: str, command: list[str]) -> int | None:
    if not _can_delegate():
        _record_tracking_failure(session_id, 'systemd delegation prerequisites',
                                 _delegation_unavailable_reason() or 'delegation unavailable')
        return None
    attempt = secrets.token_hex(16)
    with lifecycle.locked(session_id) as (node, value):
        value['delegation_attempt'] = attempt
        lifecycle._write(node, session_id + '.json', value)
    runner = ['/usr/bin/systemd-run', '--user', '--scope', '--quiet', '-p', 'Delegate=yes',
              sys.executable, '-I', str(Path(__file__).resolve()), '--delegated',
              '--metadata', str(metadata), '--attempt', attempt, '--', *command]
    try:
        process = subprocess.Popen(runner)
    except OSError as exc:
        with lifecycle.locked(session_id) as (node, value):
            if value.get('delegation_attempt') == attempt:
                value.pop('delegation_attempt')
                lifecycle._write(node, session_id + '.json', value)
        _record_tracking_failure(session_id, 'start systemd user scope', exc)
        return None
    deadline = time.monotonic() + _DELEGATION_START_SECONDS

    def startup_expired():
        if time.monotonic() < deadline:
            return False
        with lifecycle.locked(session_id) as (node, value):
            if value['backend'] != 'untracked' or value['owner_pid'] != os.getpid():
                return False  # A claimed session has no startup time limit.
            if value.get('delegation_attempt') != attempt:
                return False
            value.pop('delegation_attempt')
            lifecycle._write(node, session_id + '.json', value)
        _record_tracking_failure(session_id, 'start systemd user scope',
                                 'delegation startup deadline exceeded')
        return True

    code = _wait(process.pid, startup_expired=startup_expired)
    # _wait reaps the exact runner PID; prevent Popen's finalizer reaping again.
    process.returncode = code
    with lifecycle.locked(session_id) as (node, value):
        started = value['owner_pid'] != os.getpid() or value['backend'] != 'untracked'
        if value.get('delegation_attempt') == attempt:
            value.pop('delegation_attempt')
            lifecycle._write(node, session_id + '.json', value)
    if started:
        return _result(code)
    _record_tracking_failure(session_id, 'systemd user scope',
                             f'exited before claiming the session (status={code})')
    return None  # Inner controller never claimed the session or released payload.


def _accept_degraded(approved: bool = False) -> bool:
    # Compatibility flag remains accepted, but retaining uncertain scratch is
    # now the safe default. No terminal input or weaker sandbox is required.
    print('raptor: session process tracking unavailable; temporary files will be retained. '
          'Details: bin/raptor cleanup --list', file=sys.stderr)
    return True


def supervise(metadata: Path, command: list[str], *, delegated: bool = False,
              allow_degraded: bool = False, attempt: str | None = None) -> int:
    session_id = _authorized(metadata)
    if delegated:
        return _delegated(session_id, command, attempt=attempt) if cgroups is not None else 125
    if sys.platform == 'linux' and cgroups is not None:
        delegated_code = _delegated(session_id, command)
        with lifecycle.locked(session_id) as (_, value):
            if value['backend'] != 'untracked' or value['owner_pid'] != os.getpid():
                return delegated_code
    code = _try_delegated(metadata, session_id, command)
    if code is not None:
        return code
    _accept_degraded(allow_degraded)
    _claim(session_id, 'untracked')
    code = _spawn(command)
    with lifecycle.locked(session_id) as (node, value):
        if value['state'] not in {'closed', 'removed'}:
            value.update(state='retained', reason='no verified process-tree cleanup backend')
            lifecycle._write(node, session_id + '.json', value)
            print(f'raptor: session {session_id}: scratch retained; inspect with bin/raptor cleanup --list',
                  file=sys.stderr)
    return _result(code)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--delegated', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--attempt', help=argparse.SUPPRESS)
    parser.add_argument('--allow-degraded-cleanup', action='store_true',
                        help='compatibility option; unavailable tracking retains scratch automatically')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] != ['--'] or len(args.command) < 2:
        parser.error('expected -- followed by the command')
    try:
        return supervise(args.metadata, args.command[1:], delegated=args.delegated,
                         allow_degraded=args.allow_degraded_cleanup, attempt=args.attempt)
    except (OSError, ValueError, TypeError):
        print('raptor: scratch supervision unavailable; no additional command started', file=sys.stderr)
        return 126


if __name__ == '__main__':
    raise SystemExit(main())

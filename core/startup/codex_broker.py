"""Private, capability-authenticated file IPC across Codex's PID sandbox.

No network access, shell injection, or command-execution interface. The host
validates the bound live owner on every request and exits when it disappears.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time

from core.hash import sha256_string
from core.startup import codex_environment as environment


# Resolve only this platform-owned prefix. Keep private IPC descendants
# lexical so _directory still rejects links below the trusted temp root.
_IPC_ROOT = Path("/tmp")
_POLL_MIN = 0.02   # 20 ms — responsive when requests arrive
_POLL_MAX = 0.5    # 500 ms — idle ceiling


def _address(session_id):
    environment._session_id(session_id)
    key = sha256_string(str(environment.ROOT) + '\0' + session_id)[:40]
    return _IPC_ROOT.resolve(strict=True) / f'raptor-codex-env-{os.getuid()}' / key


def request(session_id, message):
    context = environment.read_context(session_id)
    session_id = context['session_id']
    message = dict(message, capability=context['broker_key'])
    name = secrets.token_hex(16)
    with environment._directory(_address(session_id)) as directory:
        environment._atomic(directory, name + '.request', json.dumps(message))
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    result = json.loads(environment._read(directory, name + '.response'))
                    if not isinstance(result, dict) or result.get('ok') is not True:
                        raise environment.CodexEnvironmentError('host session validation failed')
                    return result
                except FileNotFoundError:
                    time.sleep(0.02)
            raise environment.CodexEnvironmentError('host environment broker unavailable')
        finally:
            for suffix in ('.request', '.response'):
                try:
                    os.unlink(name + suffix, dir_fd=directory)
                except FileNotFoundError:
                    pass


def _lock(directory):
    fd = os.open('server.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(fd)
        raise environment.CodexEnvironmentError('unsafe broker lock')
    return fd


def start(session_id, pid):
    address = _address(session_id)
    with environment._directory(address, create=True) as directory:
        lock = _lock(directory)
        try:
            deadline = time.monotonic() + 3
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    try:
                        current = request(session_id, {'op': 'environment'})
                    except (OSError, environment.CodexEnvironmentError):
                        # A retired generation can still be closing its stable
                        # server lock. Never unlink it or race a second broker;
                        # retry the same inode before starting the successor.
                        try:
                            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise environment.CodexEnvironmentError('prior broker did not retire')
                        time.sleep(0.02)
                        continue
                    if current['environment']['RAPTOR_SESSION_PID'] == str(pid):
                        return
                    raise environment.CodexEnvironmentError('another live owner holds this context')
        finally:
            os.close(lock)
    from core.config import RaptorConfig
    child_env = RaptorConfig.get_safe_env()
    child_env.update({'RAPTOR_DIR': str(environment.ROOT), '_RAPTOR_TRUSTED': '1',
                      'RAPTOR_CODEX_HOOK': '1'})
    script = environment.ROOT / 'libexec/raptor-codex-env-broker'
    process = subprocess.Popen([sys.executable, '-I', str(script), session_id],
                               env=child_env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        result = request(session_id, {'op': 'environment'})
        if result['environment']['RAPTOR_SESSION_PID'] == str(pid):
            return
    except (OSError, ValueError):
        pass
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=3)
    raise environment.CodexEnvironmentError('host broker did not initialize')


def serve(session_id):
    context = environment.read_context(session_id)
    pid = context['pid']
    os.environ.pop('RAPTOR_REGISTRY_HOME', None)
    if context['registry_home']:
        os.environ['RAPTOR_REGISTRY_HOME'] = context['registry_home']
    with environment._directory(_address(session_id)) as directory:
        lock = _lock(directory)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lock)
            return
        try:
            environment._atomic(directory, 'ready', str(os.getpid()))
            poll = _POLL_MIN
            while True:
                try:
                    fields = environment._entry(pid, context['session_id'])
                    if (context['identity'] != environment._identity(fields)
                            or not secrets.compare_digest(context['token_digest'], environment._digest(fields))):
                        return
                except (OSError, ValueError):
                    return
                # Bound each pass; an unauthenticated request cannot execute
                # commands or obtain values, even if it reaches this directory.
                names = (name for name in os.listdir(directory)
                         if len(name) == 40 and name.endswith('.request')
                         and all(c in '0123456789abcdef' for c in name[:32]))
                served = 0
                for index, name in enumerate(names):
                    if index >= 32:
                        break
                    try:
                        value = json.loads(environment._read(directory, name))
                        result = {'ok': False}
                        if (isinstance(value, dict) and isinstance(value.get('capability'), str)
                                and secrets.compare_digest(value['capability'], context['broker_key'])):
                            del value['capability']
                            if value == {'op': 'environment'}:
                                result = {'ok': True, 'environment': environment.overlay(context, fields)}
                            elif (set(value) == {'op', 'pid', 'token', 'identity'}
                                  and value['op'] == 'identity' and value['pid'] == pid
                                  and value['identity'] == environment._identity(fields)
                                  and isinstance(value['token'], str)
                                  and secrets.compare_digest(value['token'], fields['token'])):
                                result = {'ok': True}
                        environment._atomic(directory, name[:32] + '.response', json.dumps(result))
                        os.unlink(name, dir_fd=directory)
                        served += 1
                    except (OSError, ValueError, TypeError, RecursionError):
                        try:
                            os.unlink(name, dir_fd=directory)
                        except FileNotFoundError:
                            pass
                        continue
                if served:
                    poll = _POLL_MIN
                else:
                    poll = min(poll * 1.5, _POLL_MAX)
                time.sleep(poll)
        finally:
            # Remove only protocol-owned message files while still holding the
            # stable server lock. Interrupted replies can contain credentials.
            for name in os.listdir(directory):
                protocol = (len(name) in (40, 41) and name.endswith(('.request', '.response'))
                            and all(c in '0123456789abcdef' for c in name[:32]))
                outcome = re.fullmatch(r'outcome-[0-9a-f]{64}-[0-9]+\.json', name)
                if protocol or outcome:
                    try:
                        os.unlink(name, dir_fd=directory)
                    except FileNotFoundError:
                        pass
            try:
                os.unlink('ready', dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(lock)

"""Optional naming through the firing session's existing local Codex server.

Never start a server, resume a thread, alter permissions or infer the current
thread from a list. Linux peer credentials tie the transport to the same live
owner already authenticated by the native hook. Missing transport is a no-op.
Display metadata never changes project binding or the target of an analysis.
"""
from __future__ import annotations

import logging
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import time

from core.atomic_fs.fs_lock import sidecar_flock
from core.hash import sha256_string
from core.json import load_json, loads
from core.project import registry_home, sessions
from core.project.session_titles import context_title, request_title
from core.startup import codex_environment as environment

_BUDGET = .75
_MAX_BYTES = 64 * 1024
logger = logging.getLogger(__name__)


def _read(path: Path, maximum: int) -> bytes:
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('Codex transport metadata exceeds naming budget')
    return data


def _listener_path(pid: int) -> Path | None:
    """Discover an advertised listener or a listener held by this owner.

    Explicit --listen paths are authoritative. For the native shared daemon,
    recognize its control listener by basename, never a guessed /tmp path.
    A client with no discoverable control listener (including stdio-only
    --no-daemon versions) is deliberately unsupported rather than relaunched.
    """
    process = Path('/proc') / str(pid)
    arguments = _read(process / 'cmdline', _MAX_BYTES).split(b'\0')
    explicit = set()
    for index, argument in enumerate(arguments):
        value = None
        if argument == b'--listen' and index + 1 < len(arguments):
            value = arguments[index + 1]
        elif argument.startswith(b'--listen='):
            value = argument[len(b'--listen='):]
        if value and value.startswith(b'unix:///'):
            explicit.add(os.fsdecode(value[len(b'unix://'):]))
    if explicit:
        # The actual owner's advertised path is enough for discovery; peer
        # credentials below still prove who accepted the connection. Secure
        # bind implementations may record /proc/self/fd/... in net/unix rather
        # than this pathname, so do not require a textual table-path match.
        if len(explicit) != 1:
            return None
        path = Path(next(iter(explicit)))
        return path if '..' not in path.parts else None
    inodes = set()
    with os.scandir(process / 'fd') as descriptors:
        for index, descriptor in enumerate(descriptors):
            if index >= 512:
                return None
            try:
                link = os.readlink(descriptor.path)
            except FileNotFoundError:
                continue
            if link.startswith('socket:[') and link.endswith(']'):
                inodes.add(link[8:-1])
    matches = set()
    table = _read(process / 'net/unix', 1024 * 1024)
    for line in os.fsdecode(table).splitlines()[1:]:
        fields = line.split(maxsplit=7)
        if (len(fields) != 8 or fields[6] not in inodes
                or fields[3] != '00010000' or fields[4] != '0001'):
            continue
        path = Path(fields[7])
        if (len(path.parts) == 6 and path.parts[:4] == ('/', 'proc', 'self', 'fd')
                and path.parts[4].isdigit()):
            parent = Path(os.readlink(process / 'fd' / path.parts[4]))
            path = parent / path.name
        if not path.is_absolute() or '..' in path.parts:
            continue
        if _control_path(path):
            matches.add(path)
    return next(iter(matches)) if len(matches) == 1 else None


def _control_path(path):
    # Native versions expose either the descriptive alias or a hashed name in
    # their private daemon directory. This classifies owner-held listeners; it
    # never guesses a socket path or scans the machine-wide daemon directory.
    return path.name == 'app-server-control.sock' or (
        path.parent == Path('/tmp') / f'codex-daemon-{os.getuid()}'
        and re.fullmatch(r'[0-9a-f]{64}', path.name) is not None)


def _remaining(deadline):
    duration = deadline - time.monotonic()
    if duration <= 0:
        raise TimeoutError('Codex naming budget exhausted')
    return duration


def _connect(pid, deadline):
    # Import only after authenticated hook context and a listener are present.
    path = _listener_path(pid)
    if path is None:
        return None
    # Native Codex may advertise a symlink alias for its control socket. Pin
    # the private canonical parent, then authenticate the connected peer; the
    # alias itself never grants ownership or selects a different process.
    path = path.resolve(strict=True)
    from websockets.sync.client import unix_connect
    from websockets.exceptions import WebSocketException
    with environment._directory(path.parent) as directory:
        info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            return None
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(_remaining(deadline))
            channel.connect(f'/proc/self/fd/{directory}/{path.name}')
            peer_pid, peer_uid, _ = struct.unpack(
                '3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if (peer_pid != pid or peer_uid != os.getuid()
                    or sessions.resolve_codex_owner_pid() != pid):
                return None
            # The WebSocket owns a duplicate of the already peer-checked
            # channel. It cannot reconnect by pathname to a replacement server.
            duplicate = channel.dup()
            try:
                duplicate.settimeout(None)
                return unix_connect(sock=duplicate,
                                    open_timeout=_remaining(deadline), close_timeout=.01,
                                    max_size=_MAX_BYTES)
            except WebSocketException as exc:
                duplicate.close()
                raise ValueError('Codex title connection unavailable') from exc
            except BaseException:
                duplicate.close()
                raise


class _Client:
    def __init__(self, channel, deadline):
        self.channel, self.deadline, self.sequence = channel, deadline, 0

    def call(self, method, params):
        self.sequence += 1
        identity = self.sequence
        self.send({'id': identity, 'method': method, 'params': params})
        while True:
            message = loads(self.channel.recv(timeout=_remaining(self.deadline)), max_bytes=_MAX_BYTES)
            if not isinstance(message, dict) or ('method' in message and 'id' in message):
                raise ValueError('unexpected interactive Codex message')
            if message.get('id') == identity:
                if 'error' in message or not isinstance(message.get('result'), dict):
                    raise ValueError('Codex naming request refused')
                return message['result']

    def send(self, message):
        self.channel.socket.settimeout(_remaining(self.deadline))
        self.channel.send(json.dumps(message))

    def title(self, session_id):
        thread = self.call('thread/read', {'threadId': session_id, 'includeTurns': False}).get('thread')
        if (not isinstance(thread, dict) or thread.get('id') != session_id
                or not isinstance(thread.get('status'), dict)
                or thread['status'].get('type') == 'notLoaded'):
            raise ValueError('Codex thread is not loaded in its authenticated owner')
        title = thread.get('name')
        if title is not None and (not isinstance(title, str) or len(title) > 4096):
            raise ValueError('invalid Codex title feedback')
        return title


def _synchronize(channel, session_id, desired, directory, deadline):
    """Read native feedback, apply shared policy, then recheck before writing."""
    client = _Client(channel, deadline)
    client.call('initialize', {'clientInfo': {'name': 'raptor-session-title', 'version': '1'}})
    client.send({'method': 'initialized'})
    current = client.title(session_id)
    requested = request_title(directory, 'codex', session_id, desired, current)
    if requested is None:
        return
    latest = client.title(session_id)
    if latest != current:
        # Preserve a manual rename observed while this hook was deciding.
        request_title(directory, 'codex', session_id, desired, latest)
        return
    client.call('thread/name/set', {'threadId': session_id, 'name': requested})


def _desired(context):
    pid = context['pid']
    project, state = sessions.session_binding(pid)
    if state not in {'bound', 'none'}:
        return None
    if project is not None:
        record = load_json(registry_home.projects_dir() / f'{project}.json',
                           strict=True, max_bytes=1024 * 1024)
        if not isinstance(record, dict) or not isinstance(record.get('target'), str):
            return None
        return context_title(project, record['target'])
    runs = sessions.ledger_runs(pid)
    if runs:
        _, latest = max(enumerate(runs), key=lambda pair: (pair[1]['epoch'], pair[0]))
        # Naming never scans other roots to find a missing witness. The exact
        # authenticated logical owner is sufficient and keeps hooks bounded.
        found, pinned, _ = sessions._ledger_pin_witness(latest['run_dir'], pid=pid)
        if found and pinned is None:
            record = load_json(Path(latest['run_dir']) / '.raptor-run.json',
                               strict=True, max_bytes=1024 * 1024)
            if isinstance(record, dict) and isinstance(record.get('target_path'), str):
                return context_title(None, record['target_path'])
    target, caller = context['launch_target'], context['caller_dir']
    if target and not Path(target).is_absolute():
        target = str(Path(caller) / target) if caller and Path(caller).is_absolute() else None
    return context_title(None, target or caller)


def update_title(session_id) -> None:
    """Best effort after SessionStart publication or authenticated Stop restore."""
    try:
        if not hasattr(socket, 'SO_PEERCRED'):
            return
        context = environment.read_context(session_id)
        pid = context['pid']
        if (context['session_id'] != session_id
                or os.environ.get('RAPTOR_CODEX_CONTEXT_ID') != session_id
                or os.environ.get('RAPTOR_SESSION_PID') != str(pid)
                or sessions.resolve_session_pid() != pid
                or sessions.resolve_codex_owner_pid() != pid
                or not secrets.compare_digest(context['token_digest'],
                                              sha256_string(os.environ.get('RAPTOR_SESSION_TOKEN', '')))
                or context['identity']['starttime'] != sessions.proc_starttime(pid)):
            return
        desired = _desired(context)
        if desired is None:
            return
        directory = registry_home.sessions_dir() / '.titles'
        # Pin and validate the shared state directory before its lock is opened.
        with environment._directory(directory, create=True):
            lock = directory / f'codex-{sha256_string(session_id)}.transaction.lock'
            with sidecar_flock(lock, required=True, deadline_s=.025, subject='Codex title'):
                deadline = time.monotonic() + _BUDGET
                channel = _connect(pid, deadline)
                if channel is None:
                    return
                from websockets.exceptions import WebSocketException
                try:
                    with channel:
                        _synchronize(channel, session_id, desired, directory, deadline)
                except WebSocketException:
                    logger.debug('Optional Codex title transport closed', exc_info=True)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, ImportError):
        logger.debug('Optional Codex title update unavailable', exc_info=True)

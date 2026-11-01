"""Private ownership records and conservative cleanup for launcher scratch.

This module is also an isolated, stdlib-only maintenance entry point. A record
is not proof of process-tree closure: only a supervising backend may record
closure. Unsupervised roots require explicit, individually selected removal.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

MAX_RECORD = 16384
_ID = re.compile(r'[a-f0-9]{32}')
_ROOT = re.compile(r'session-(?:[0-9]+-[0-9]+|[a-f0-9]{32})')
_scratch_module = None


def scratch():
    global _scratch_module
    if _scratch_module is None:
        spec = importlib.util.spec_from_file_location('raptor_scratch_metadata',
                                                      Path(__file__).with_name('launch_scratch.py'))
        _scratch_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_scratch_module)
    return _scratch_module


def registry() -> Path:
    override = os.environ.get('RAPTOR_REGISTRY_HOME')
    if override:
        base = Path(override)
        if not base.is_absolute():
            raise ValueError('RAPTOR_REGISTRY_HOME must be absolute')
        return base / '.scratch-lifecycle'
    return Path.home() / '.local/state/raptor/scratch-lifecycle'


def authority_family() -> Path:
    override = os.environ.get('RAPTOR_REGISTRY_HOME')
    if override:
        base = Path(override)
        if not base.is_absolute():
            raise ValueError('RAPTOR_REGISTRY_HOME must be absolute')
    else:
        base = Path.home() / '.local/share/raptor'
    return base / 'sessions.d/.scratch-authorities'


def _register_authorities(session_id: str, root: Path) -> dict:
    requested = authority_family()
    base = requested.parent.resolve() / requested.name
    control = registry().resolve()
    if base == root or root in base.parents or control == root or root in control.parents:
        raise ValueError('scratch control state must be outside the managed root')
    family = scratch()._open_directory(base, create=True)
    child = None
    try:
        scratch()._private(os.fstat(family), True)
        name = 'session-' + session_id
        os.mkdir(name, 0o700, dir_fd=family)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=family)
        return {'path': str(base / name), 'identity': _identity(os.fstat(child)),
                'family_identity': _identity(os.fstat(family))}
    finally:
        if child is not None:
            os.close(child)
        os.close(family)


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError('invalid scratch session identifier')
    return value


def _identity(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino]


def _open_registry(*, create: bool = False) -> int:
    path = registry()
    # Operator-selected ancestor symlinks are resolved once. All subsequent
    # traversal is pinned and refuses symlinks at the registry/root boundary.
    parent = path.parent.resolve(strict=not create)
    node = scratch()._open_directory(parent, create=create)
    try:
        if create:
            try:
                os.mkdir(path.name, 0o700, dir_fd=node)
            except FileExistsError:
                pass
        result = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=node)
        try:
            scratch()._private(os.fstat(result), True)
        except BaseException:
            os.close(result)
            raise
        return result
    finally:
        os.close(node)


def _read_file(node: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=node)
    try:
        info = os.fstat(fd)
        scratch()._private(info, False)
        if info.st_size > MAX_RECORD:
            raise ValueError('oversized scratch control record')
        raw = os.read(fd, MAX_RECORD + 1)
        if len(raw) > MAX_RECORD:
            raise ValueError('oversized scratch control record')
        return raw
    finally:
        os.close(fd)


def _write(node: int, name: str, value: dict) -> None:
    raw = json.dumps(value, separators=(',', ':')).encode()
    if len(raw) > MAX_RECORD:
        raise ValueError('oversized scratch control record')
    temporary = '.write-' + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=node)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=node, dst_dir_fd=node)
        os.fsync(node)
    finally:
        try:
            os.unlink(temporary, dir_fd=node)
        except FileNotFoundError:
            pass


def _validate(value, session_id: str) -> dict:
    if (not isinstance(value, dict) or type(value.get('v')) is not int or value['v'] != 1
            or value.get('id') != session_id):
        raise ValueError('invalid scratch control record')
    if value.get('state') not in {'retained', 'active', 'closed', 'cleaning', 'cleanup-error', 'removed'}:
        raise ValueError('invalid scratch lifecycle state')
    for key in ('root', 'backend'):
        if not isinstance(value.get(key), str):
            raise ValueError('invalid scratch lifecycle string')
    for key in ('root_identity', 'family_identity', 'metadata_identity'):
        identity = value.get(key)
        if not isinstance(identity, list) or len(identity) != 2 or any(type(i) is not int or i < 0 for i in identity):
            raise ValueError('invalid scratch filesystem identity')
    if (type(value.get('owner_pid')) is not int or value['owner_pid'] <= 0
            or not isinstance(value.get('owner_birth'), dict)
            or type(value.get('removal_authorized')) is not bool
            or value.get('closure') not in {None, 'never-released', 'pid-namespace', 'cgroup-v2'}
            or value.get('quarantine') not in {None, '.cleanup-' + session_id}):
        raise ValueError('invalid scratch lifecycle ownership')
    authority = value.get('authorities')
    if not isinstance(authority, dict) or not isinstance(authority.get('path'), str):
        raise ValueError('invalid scratch authority record')
    for key in ('identity', 'family_identity'):
        identity = authority.get(key)
        if not isinstance(identity, list) or len(identity) != 2 or any(type(i) is not int or i < 0 for i in identity):
            raise ValueError('invalid scratch authority identity')
    if value['backend'] in {'cgroup-v2', 'cgroup-v2-tracking'}:
        scope = value.get('scope')
        if not isinstance(scope, dict) or not isinstance(scope.get('path'), str) or not isinstance(scope.get('identity'), list):
            raise ValueError('invalid cgroup scope recovery identity')
        front = scope.get('frontend')
        if front is not None and (not isinstance(front, dict) or not isinstance(front.get('path'), str)
                                  or not isinstance(front.get('identity'), list)):
            raise ValueError('invalid cgroup child recovery identity')
    return value


@contextmanager
def locked(session_id: str):
    session_id = _identifier(session_id)
    node = _open_registry()
    fd = None
    try:
        fd = os.open(session_id + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=node)
        scratch()._private(os.fstat(fd), False)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        value = json.loads(_read_file(node, session_id + '.json'))
        yield node, _validate(value, session_id)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(node)


def register(metadata: Path, owner_pid: int) -> str:
    """Register only a newly allocated private launcher root; never adopt one."""
    if metadata.name != 'launch.json' or metadata.parent.name != 'metadata':
        raise ValueError('invalid launch metadata path')
    metadata = metadata.parent.parent.resolve(strict=True) / 'metadata/launch.json'
    scratch().read(metadata, require_sealed=False)
    root = metadata.parent.parent
    if not _ROOT.fullmatch(root.name) or root.parent.name != f'raptor-{os.geteuid()}':
        raise ValueError('invalid managed scratch root')
    label = root.name.removeprefix('session-')
    session_id = label if _ID.fullmatch(label) else secrets.token_hex(16)
    with ExitStack() as descriptors:
        parent = scratch()._open_directory(root.parent)
        descriptors.callback(os.close, parent)
        node = scratch()._open_directory(root)
        descriptors.callback(os.close, node)
        meta = os.open('metadata', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=node)
        descriptors.callback(os.close, meta)
        # Claim the physical root exactly once before publishing any control
        # records or credential groups. A duplicate registration has no effects.
        marker = os.open('session-id', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=meta)
        with os.fdopen(marker, 'w') as stream:
            stream.write(session_id)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(meta)
        authorities = _register_authorities(session_id, root)
        control = _open_registry(create=True)
        descriptors.callback(os.close, control)
        scratch()._private(os.fstat(parent), True)
        value = {'v': 1, 'id': session_id, 'root': str(root),
                 'root_identity': _identity(os.fstat(node)),
                 'family_identity': _identity(os.fstat(parent)),
                 'metadata_identity': _identity(os.stat('launch.json', dir_fd=meta, follow_symlinks=False)),
                 'owner_pid': owner_pid, 'owner_birth': scratch()._birth(owner_pid),
                 'created': time.time(), 'state': 'retained', 'backend': 'untracked',
                 'closure': None, 'quarantine': None, 'removal_authorized': False,
                 'authorities': authorities,
                 'reason': 'process-tree closure has not been established'}
        _write(control, session_id + '.json', value)
        return session_id


def session_for(metadata: Path) -> str:
    node = scratch()._open_directory(metadata.parent)
    try:
        return _identifier(_read_file(node, 'session-id').decode('ascii'))
    finally:
        os.close(node)


def claim(session_id: str, backend: str, scope: dict | None = None, *,
          allow_active: bool = False, attempt: str | None = None):
    """Transfer a verified launcher's lifetime to its supervising descendant."""
    with locked(session_id) as (node, value):
        if attempt is not None and value.get('delegation_attempt') != attempt:
            raise PermissionError('delegation attempt is no longer current')
        allowed_states = {'retained', 'active'} if allow_active else {'retained'}
        if value['state'] not in allowed_states or value['backend'] != 'untracked':
            raise PermissionError('scratch session already has a supervisor')
        owner = value['owner_pid']
        current = os.getpid()
        for _ in range(64):
            if current == owner:
                break
            if current <= 1:
                raise PermissionError('scratch owner is not a live ancestor')
            current = scratch()._parent(current)
        else:
            raise PermissionError('scratch owner ancestry unavailable')
        if value['owner_birth'] != scratch()._birth(owner):
            raise PermissionError('scratch owner identity changed')
        previous = value['owner_pid'], value['owner_birth']
        value.update(owner_pid=os.getpid(), owner_birth=scratch()._birth(os.getpid()),
                     state='active', backend=backend, reason=None)
        if scope is not None:
            value['scope'] = scope
        _write(node, session_id + '.json', value)
        return previous


def record_closed(session_id: str, proof: str) -> None:
    """Called by the owning outside supervisor after verifying tree closure."""
    if proof not in {'never-released', 'pid-namespace', 'cgroup-v2'}:
        raise ValueError('unknown process-tree closure mechanism')
    with locked(session_id) as (node, value):
        if (value['owner_pid'] != os.getpid()
                or value['owner_birth'] != scratch()._birth(os.getpid())):
            raise PermissionError('only the original supervisor may record closure')
        if value['state'] not in {'retained', 'active'}:
            raise ValueError('scratch session cannot transition to closed')
        value.update(state='closed', closure=proof, reason=None)
        _write(node, session_id + '.json', value)


def _mounts_below(root: Path) -> bool:
    if sys.platform != 'linux':
        return False  # Device boundaries below remain checked on every platform.
    # In the cleaner's view, reject even same-device bind mounts. Failure to
    # inspect mount topology fails cleanup rather than walking into a mount.
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        text = line.split()[4]
        path = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), text))
        if path == root or root in path.parents:
            return True
    return False


def _erase(node: int, device: int, deadline: float, *, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError('scratch cleanup depth limit exceeded')
    with os.scandir(node) as entries:
        for entry in entries:
            name = entry.name
            if time.monotonic() > deadline:
                raise TimeoutError('scratch cleanup time budget exceeded; retry cleanup')
            info = os.stat(name, dir_fd=node, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=node)
                try:
                    actual = os.fstat(child)
                    if not os.path.samestat(info, actual) or actual.st_dev != device:
                        raise PermissionError('scratch directory identity or filesystem changed')
                    _erase(child, device, deadline, depth=depth + 1)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=node)
            else:
                # Unlink the entry, never follow a symlink or write/chmod a hardlink.
                os.unlink(name, dir_fd=node)



def _cleanup_authorities(value: dict, deadline: float) -> None:
    data = value['authorities']
    path = Path(data['path'])
    if not path.is_absolute() or path.name != 'session-' + value['id'] or path.parent.name != '.scratch-authorities':
        raise ValueError('invalid scratch authority group')
    family = scratch()._open_directory(path.parent)
    node = None
    try:
        scratch()._private(os.fstat(family), True)
        if _identity(os.fstat(family)) != data['family_identity']:
            raise PermissionError('scratch authority family changed')
        try:
            node = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=family)
        except FileNotFoundError:
            return
        info = os.fstat(node)
        scratch()._private(info, True)
        if _identity(info) != data['identity'] or _mounts_below(path):
            raise PermissionError('scratch authority group changed or contains a mount')
        _erase(node, info.st_dev, deadline)
        if _identity(os.stat(path.name, dir_fd=family, follow_symlinks=False)) != data['identity']:
            raise PermissionError('scratch authority group changed during cleanup')
        os.rmdir(path.name, dir_fd=family)
    finally:
        if node is not None:
            os.close(node)
        os.close(family)


def cleanup(session_id: str, *, force: bool = False, budget: float = 10) -> str:
    session_id = _identifier(session_id)
    deadline = time.monotonic() + budget
    with locked(session_id) as (control, value):
        if value['state'] == 'removed':
            return 'removed'
        if value.get('closure') not in {None, 'never-released', 'pid-namespace', 'cgroup-v2'}:
            raise ValueError('invalid scratch closure record')
        if not (value.get('closure') or value.get('removal_authorized') is True or force):
            return 'retained'
        root = Path(value['root'])
        if (not root.is_absolute() or not _ROOT.fullmatch(root.name)
                or root.parent.name != f'raptor-{os.geteuid()}'):
            raise ValueError('refusing invalid scratch cleanup root')
        parent = scratch()._open_directory(root.parent)
        node = None
        try:
            scratch()._private(os.fstat(parent), True)
            if _identity(os.fstat(parent)) != value['family_identity']:
                raise PermissionError('scratch family identity changed')
            quarantine = '.cleanup-' + session_id
            name = root.name
            if value.get('quarantine') is not None:
                if value['quarantine'] != quarantine:
                    raise ValueError('invalid scratch quarantine name')
                try:
                    os.stat(quarantine, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass  # Interrupted after journal write but before rename.
                else:
                    name = quarantine
            try:
                node = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                if value.get('quarantine') is not None and value.get('removal_authorized') is True:
                    # Authorized cleanup completed its unlink but crashed before
                    # committing the final journal update. Both names are gone.
                    for candidate in (root.name, quarantine):
                        try:
                            os.stat(candidate, dir_fd=parent, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        raise PermissionError('scratch cleanup identity is ambiguous')
                    _cleanup_authorities(value, deadline)
                    value.update(state='removed', reason=None)
                    _write(control, session_id + '.json', value)
                    return 'removed'
                raise
            info = os.fstat(node)
            scratch()._private(info, True)
            if _identity(info) != value['root_identity']:
                raise PermissionError('scratch root identity changed')
            actual_root = root.parent / name
            if _mounts_below(actual_root):
                raise PermissionError('scratch contains a mount; retain it for host cleanup')
            if value.get('quarantine') is None:
                meta = os.open('metadata', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=node)
                try:
                    marker = _read_file(meta, 'session-id').decode('ascii')
                    metadata = os.stat('launch.json', dir_fd=meta, follow_symlinks=False)
                    scratch()._private(metadata, False)
                    if marker != session_id or _identity(metadata) != value['metadata_identity']:
                        raise PermissionError('scratch metadata identity changed')
                finally:
                    os.close(meta)
            value.update(state='cleaning', quarantine=quarantine, removal_authorized=True, reason=None)
            _write(control, session_id + '.json', value)
            if name != quarantine:
                try:
                    os.stat(quarantine, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise FileExistsError('scratch quarantine already exists')
                os.rename(name, quarantine, src_dir_fd=parent, dst_dir_fd=parent)
            if _identity(os.stat(quarantine, dir_fd=parent, follow_symlinks=False)) != value['root_identity']:
                raise PermissionError('scratch identity changed during quarantine')
            _erase(node, info.st_dev, deadline)
            os.rmdir(quarantine, dir_fd=parent)
            _cleanup_authorities(value, deadline)
            value.update(state='removed', reason=None)
            _write(control, session_id + '.json', value)
            return 'removed'
        except (OSError, ValueError):
            value.update(state='cleanup-error', reason='scratch cleanup incomplete; inspect and retry')
            _write(control, session_id + '.json', value)
            raise
        finally:
            if node is not None:
                os.close(node)
            os.close(parent)


def records(limit: int = 1000):
    try:
        node = _open_registry()
    except FileNotFoundError:
        return
    try:
        with os.scandir(node) as entries:
            count = 0
            for entry in entries:
                if not entry.name.endswith('.json') or not _ID.fullmatch(entry.name[:-5]):
                    continue
                count += 1
                if count > limit:
                    return
                try:
                    value = json.loads(_read_file(node, entry.name))
                    yield _validate(value, entry.name[:-5])
                except (OSError, ValueError, TypeError):
                    yield {'id': entry.name[:-5], 'state': 'invalid', 'root': '(unavailable)'}
    finally:
        os.close(node)


def _terminal_sanitizer():
    spec = importlib.util.spec_from_file_location('raptor_cleanup_terminal',
                                                 Path(__file__).with_name('log_sanitisation.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.sanitise_for_terminal


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Inspect and clean RAPTOR-owned session scratch.')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--list', action='store_true', help='list records without changing files')
    mode.add_argument('--dry-run', action='store_true', help='show what normal cleanup could remove')
    parser.add_argument('--session', type=_identifier, help='select one session ID')
    parser.add_argument('--force', action='store_true', help='explicitly allow removal without closure proof')
    parser.add_argument('--limit', type=int, default=1000, help='maximum records inspected (default: 1000)')
    args = parser.parse_args(argv)
    if args.force and (not args.session or args.list or args.dry_run):
        parser.error('--force requires --session and a cleanup action')
    if not 1 <= args.limit <= 10000:
        parser.error('--limit must be between 1 and 10000')
    failed = False
    sanitise_for_terminal = _terminal_sanitizer()
    try:
        selected = records(args.limit)
        if args.session:
            node = _open_registry()
            try:
                value = json.loads(_read_file(node, args.session + '.json'))
                selected = [_validate(value, args.session)]
            finally:
                os.close(node)
        for value in selected:
            state = value['state']
            if not (args.list or args.dry_run or state == 'invalid'):
                try:
                    state = cleanup(value['id'], force=args.force)
                except (OSError, ValueError, TypeError):
                    state = 'cleanup-error'
                    failed = True
            print(f"{sanitise_for_terminal(str(value['id']))}  {sanitise_for_terminal(str(state))}  "
                  f"{sanitise_for_terminal(str(value.get('backend', 'unknown')))}  "
                  f"{sanitise_for_terminal(str(value.get('root', '(unavailable)')))}")
        return int(failed)
    except (OSError, ValueError, TypeError) as exc:
        print(f'raptor: scratch cleanup unavailable ({type(exc).__name__}); inspect operator state', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

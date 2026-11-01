"""Launcher-owned scratch metadata; helpers never adopt ambient TMPDIR."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

_restored = False
_metadata_path: Path | None = None


def _private(info: os.stat_result, directory: bool) -> None:
    valid_kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_kind or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PermissionError('launch scratch metadata must be private and owned by this user')
    if not directory and info.st_nlink != 1:
        raise PermissionError('launch scratch metadata must not be hard linked')


def _open_directory(path: Path, *, create: bool = False) -> int:
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('launch scratch path must be absolute')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    node = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=node)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=node)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=node)
            os.close(node)
            node = child
        return node
    except BaseException:
        os.close(node)
        raise


def create(session_root: Path, *, protected: bool = False) -> Path:
    """Populate a freshly-created launcher directory, without reusing files."""
    root = session_root.resolve(strict=True)
    if (root.parent.name != f'raptor-{os.geteuid()}'
            or not re.fullmatch(r'session-(?:[0-9]+-[0-9]+|[a-f0-9]{32})', root.name)
            or any(not char.isprintable() for char in str(root))):
        raise ValueError('expected a fresh launcher session directory')
    node = _open_directory(root)
    try:
        _private(os.fstat(node), True)
        os.mkdir('tmp', 0o700, dir_fd=node)
        os.mkdir('metadata', 0o700, dir_fd=node)
        meta = os.open('metadata', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=node)
        try:
            target = os.open('launch.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=meta)
            with os.fdopen(target, 'w') as stream:
                json.dump({'v': 1, 'tmpdir': str(root / 'tmp'), 'protected': protected}, stream)
        finally:
            os.close(meta)
    finally:
        os.close(node)
    return root / 'metadata/launch.json'


def read(metadata: Path, *, require_sealed: bool = True, require_protected: bool = False) -> str:
    """Read a metadata path obtained from an identity-checked session row."""
    if metadata.name != 'launch.json' or metadata.parent.name != 'metadata':
        raise ValueError('invalid launch scratch metadata location')
    root = metadata.parent.parent
    node = _open_directory(root)
    meta = target = scratch = None
    try:
        _private(os.fstat(node), True)
        meta = os.open('metadata', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=node)
        _private(os.fstat(meta), True)
        target = os.open('launch.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=meta)
        info = os.fstat(target)
        _private(info, False)
        if info.st_size > 4096:
            raise ValueError('oversized launch scratch metadata')
        data = os.read(target, 4097)
        if len(data) > 4096:
            raise ValueError('oversized launch scratch metadata')
        value = json.loads(data)
        if (not isinstance(value, dict) or set(value) != {'v', 'tmpdir', 'protected'}
                or type(value['v']) is not int or value['v'] != 1
                or type(value['protected']) is not bool
                or value['tmpdir'] != str(root / 'tmp')):
            raise ValueError('invalid launch scratch metadata')
        if require_protected and not value['protected']:
            raise PermissionError('launch metadata does not request protection')
        if require_sealed and value['protected'] and not os.fstatvfs(meta).f_flag & os.ST_RDONLY:
            raise PermissionError('protected launch metadata is not read-only')
        scratch = os.open('tmp', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=node)
        _private(os.fstat(scratch), True)
        return value['tmpdir']
    finally:
        for descriptor in (scratch, target, meta, node):
            if descriptor is not None:
                os.close(descriptor)


def prepare_protection(metadata: Path) -> None:
    """Mark a new launch before the guard seals its metadata directory."""
    read(metadata, require_sealed=False)
    directory = _open_directory(metadata.parent)
    target = None
    try:
        target = os.open(metadata.name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        _private(os.fstat(directory), True)
        info = os.fstat(target)
        _private(info, False)
        if info.st_size > 4096:
            raise ValueError('oversized launch scratch metadata')
        raw = os.read(target, 4097)
        if len(raw) > 4096:
            raise ValueError('oversized launch scratch metadata')
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {'v', 'tmpdir', 'protected'}
                or type(value['v']) is not int or value['v'] != 1
                or type(value['protected']) is not bool
                or value['tmpdir'] != str(metadata.parent.parent / 'tmp')):
            raise ValueError('invalid launch scratch metadata')
        value['protected'] = True
        data = json.dumps(value).encode()
        os.lseek(target, 0, os.SEEK_SET)
        offset = 0
        while offset < len(data):
            written = os.write(target, data[offset:])
            if written <= 0:
                raise OSError('could not write launch scratch metadata')
            offset += written
        os.ftruncate(target, len(data))
    finally:
        if target is not None:
            os.close(target)
        os.close(directory)


def allocate(base: Path, pid: int, *, protected: bool = False) -> Path:
    """Create fresh scratch under the operator's base, without sweeping users."""
    base = base.resolve(strict=True)
    node = _open_directory(base)
    family = None
    family_name = f'raptor-{os.geteuid()}'
    name = 'session-' + secrets.token_hex(16)
    try:
        try:
            os.mkdir(family_name, 0o700, dir_fd=node)
        except FileExistsError:
            pass
        family = os.open(family_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=node)
        _private(os.fstat(family), True)
        os.mkdir(name, 0o700, dir_fd=family)
    finally:
        if family is not None:
            os.close(family)
        os.close(node)
    return create(base / family_name / name, protected=protected)


def _ps(pid: int, field: str) -> str:
    # Portable process inspection. Never resolve ps from a target PATH or
    # inherit loader overrides while authenticating the launcher.
    result = subprocess.run(['/bin/ps', '-o', field + '=', '-p', str(pid)],
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                            capture_output=True, text=True, timeout=5, check=True)
    value = result.stdout.strip()
    if not value:
        raise ProcessLookupError('scratch issuer has exited')
    return value


def _parent(pid: int) -> int:
    if pid == os.getpid():
        return os.getppid()
    if sys.platform != 'linux':
        return int(_ps(pid, 'ppid'))
    value = Path(f'/proc/{pid}/stat').read_text()
    return int(value[value.rfind(')') + 2:].split()[1])


def _birth(pid: int) -> dict:
    if sys.platform != 'linux':
        return {'platform': sys.platform, 'start': _ps(pid, 'lstart')}
    value = Path(f'/proc/{pid}/stat').read_text()
    return {'platform': sys.platform,
            'start': value[value.rfind(')') + 2:].split()[19],
            'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'pidns': str(os.stat(f'/proc/{pid}/ns/pid').st_ino)}


def _packet(entry: Path, pid: int, token: str, kind: str = 'launch') -> str:
    return json.dumps({'entry': str(entry.resolve(strict=True)), 'pid': pid,
                       'token': token, 'kind': kind})


def _restore_authorized(raw: str, *, require_sealed: bool = True) -> tuple[Path, str]:
    # Only the namespace setup guard opts out of sealing before it installs
    # the read-only mount. Normal helper restoration always requires sealing.
    # Scratch-only delegation must never restore project settings or session
    # credentials. Its issuer must be a live ancestor in this PID view.
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != {'entry', 'pid', 'token', 'kind'}
            or type(value['pid']) is not int or value['pid'] <= 0
            or not isinstance(value['token'], str) or not value['token'] or not value['token'].isascii()
            or len(value['token']) > 256 or not isinstance(value['entry'], str)
            or value['kind'] not in {'launch', 'session'}):
        raise ValueError('invalid scratch authorization')
    pid = value['pid']
    current = os.getpid()
    for _ in range(64):
        if current == pid:
            break
        if current <= 1:
            raise PermissionError('scratch issuer is not an ancestor')
        current = _parent(current)
    else:
        raise PermissionError('scratch issuer ancestry is unavailable')
    entry = Path(value['entry'])
    if entry.name != str(pid):
        raise ValueError('invalid scratch issuer entry')
    directory = _open_directory(entry.parent)
    target = None
    try:
        _private(os.fstat(directory), True)
        target = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(target)
        _private(info, False)
        if info.st_size > 65536:
            raise ValueError('oversized scratch issuer entry')
        data = os.read(target, 65537)
        if len(data) > 65536:
            raise ValueError('oversized scratch issuer entry')
    finally:
        if target is not None:
            os.close(target)
        os.close(directory)
    if value['kind'] == 'launch':
        fields = json.loads(data)
        if (not isinstance(fields, dict) or set(fields) != {'v', 'identity', 'metadata', 'token'}
                or type(fields['v']) is not int or fields['v'] != 1 or fields['identity'] != _birth(pid)
                or not isinstance(fields['token'], str)
                or not secrets.compare_digest(value['token'], fields['token'])):
            raise PermissionError('scratch issuer credential is invalid or stale')
        metadata = Path(fields['metadata'])
    else:
        from core.project import sessions
        fields = {}
        for line in data.decode('utf-8-sig').splitlines():
            key, sep, text = line.partition('=')
            if sep:
                fields.setdefault(key.strip(), text.strip())
        live = sessions._identity_for(pid)
        if (not live or fields.get('v') != sessions.ENTRY_VERSION
                or any(fields.get(key) != text for key, text in live.items())
                or not secrets.compare_digest(value['token'], fields.get('token', ''))):
            raise PermissionError('scratch issuer credential is invalid or stale')
        if not fields.get('scratch_metadata'):
            raise ValueError('scratch issuer metadata is missing')
        metadata = Path(fields['scratch_metadata'])
    return metadata, read(metadata, require_sealed=require_sealed)


def restore() -> None:
    """Capture authoritative scratch once, without changing project identity."""
    global _restored, _metadata_path
    if os.name != 'posix' or _restored:
        return
    from core.security.env_sanitisation import _record_subprocess_tmpdir
    authorization = os.environ.get('_RAPTOR_SCRATCH_AUTH')
    invalid_authorization = None
    if authorization:
        try:
            _metadata_path, path = _restore_authorized(authorization)
        except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
            invalid_authorization = exc
        else:
            _record_subprocess_tmpdir(path)
            _refresh_delegation(Path(json.loads(authorization)['entry']))
            _restored = True
            return
    # Frontends that hide their owner behind a native sandbox restore their
    # existing identity-checked project context before reaching this fallback.
    from core.project import sessions
    pid = sessions.resolve_session_pid()
    if pid is not None:
        entry = sessions._sessions_dir() / str(pid)
        fields = sessions._parse_entry(entry)
        if fields.get('scratch_metadata'):
            if not fields.get('token') or not sessions._identity_matches(pid, fields):
                raise PermissionError('launch session identity changed during scratch restoration')
            metadata = Path(fields['scratch_metadata'])
            path = read(metadata)
            os.environ['_RAPTOR_SCRATCH_AUTH'] = _packet(entry, pid, fields['token'], 'session')
            _metadata_path = metadata
            _record_subprocess_tmpdir(path)
            _refresh_delegation(entry)
            _restored = True
            return
    if invalid_authorization is not None:
        raise PermissionError('scratch authorization is unavailable or stale') from invalid_authorization
    from core.security.env_sanitisation import initialize_standalone_tmpdir
    initialize_standalone_tmpdir()
    _restored = True


def _managed_session_id(metadata: Path) -> str | None:
    directory = _open_directory(metadata.parent)
    fd = None
    try:
        try:
            fd = os.open('session-id', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
        except FileNotFoundError:
            return None
        _private(os.fstat(fd), False)
        value = os.read(fd, 65).decode('ascii')
        if not re.fullmatch(r'[a-f0-9]{32}', value):
            raise ValueError('invalid scratch session identifier')
        return value
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def _refresh_delegation(entry: Path) -> None:
    # A helper's authority belongs to the physical launcher session, not its
    # logical project binding. Every delegation stays in that same group.
    if re.fullmatch(r'auth-[a-f0-9]{32}', entry.parent.name):
        base = entry.parent.parent
        session_id = _managed_session_id(_metadata_path) if _metadata_path else None
        if session_id and base.name == 'session-' + session_id:
            base = base.parent
    else:
        base = entry.parent / '.scratch-authorities'
    try:
        authorization = delegate(base)
    except (OSError, subprocess.SubprocessError):
        return  # A read-only helper can restore without minting credentials.
    if authorization is not None:
        os.environ['_RAPTOR_SCRATCH_AUTH'] = authorization


def issue(base: Path, metadata: Path, pid: int) -> str:
    """Issue scratch-only credentials for a live launcher/helper process."""
    identity = _birth(pid)
    if not base.is_absolute():
        raise ValueError('scratch authority directory must be absolute')
    session_id = _managed_session_id(metadata)
    if session_id is not None:
        family = _open_directory(base, create=True)
        try:
            _private(os.fstat(family), True)
            group = 'session-' + session_id
            try:
                os.mkdir(group, 0o700, dir_fd=family)
            except FileExistsError:
                pass
        finally:
            os.close(family)
        base = base / group
    directory_fd = _open_directory(base, create=True)
    issuer_fd = None
    name = 'auth-' + secrets.token_hex(16)
    token = secrets.token_hex(32)
    try:
        _private(os.fstat(directory_fd), True)
        os.mkdir(name, 0o700, dir_fd=directory_fd)
        issuer_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
        fd = os.open(str(pid), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=issuer_fd)
        with os.fdopen(fd, 'w') as stream:
            json.dump({'v': 1, 'identity': identity, 'metadata': str(metadata), 'token': token}, stream)
    finally:
        if issuer_fd is not None:
            os.close(issuer_fd)
        os.close(directory_fd)
    return _packet(base / name / str(pid), pid, token)


def delegate(base: Path) -> str | None:
    if _metadata_path is None:
        return None
    return issue(base, _metadata_path, os.getpid())


def _register_lifecycle(metadata: Path, owner_pid: int) -> None:
    # CLI setup only: importing/using create() in an ordinary helper or a test
    # must not create operator state. Isolated launchers load only adjacent code.
    spec = importlib.util.spec_from_file_location('raptor_scratch_lifecycle',
                                                  Path(__file__).with_name('scratch_lifecycle.py'))
    if spec is None or spec.loader is None:
        raise RuntimeError("scratch lifecycle module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.register(metadata, owner_pid)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('session_root', type=Path)
    parser.add_argument('--protected', action='store_true')
    parser.add_argument('--authorize', action='store_true')
    parser.add_argument('--allocate', action='store_true')
    parser.add_argument('--read', action='store_true')
    parser.add_argument('--restore-auth', action='store_true')
    parser.add_argument('--prepare-protection', action='store_true')
    parser.add_argument('--issuer', type=int)
    parser.add_argument('--state-dir', type=Path)
    args = parser.parse_args()
    if args.restore_auth:
        metadata, _ = _restore_authorized(os.environ.get('_RAPTOR_SCRATCH_AUTH', ''))
        print(metadata)
    elif args.read:
        print(read(args.session_root, require_protected=args.protected))
    elif args.prepare_protection:
        prepare_protection(args.session_root)
    elif args.authorize:
        if args.issuer is None or args.state_dir is None:
            parser.error('--authorize requires --issuer and --state-dir')
        print(issue(args.state_dir, args.session_root, args.issuer))
    elif args.allocate:
        if args.issuer is None:
            parser.error('--allocate requires --issuer')
        metadata = allocate(args.session_root, args.issuer, protected=args.protected)
        _register_lifecycle(metadata, args.issuer)
        print(metadata)
    else:
        metadata = create(args.session_root, protected=args.protected)
        _register_lifecycle(metadata, args.issuer or os.getpid())
        print(metadata)
    return 0


if __name__ == '__main__':
    # The launcher invokes this adjacent module by absolute filename with -I.
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError) as exc:
        print(f'RAPTOR: launcher scratch setup failed ({type(exc).__name__})', file=sys.stderr)
        raise SystemExit(1) from None

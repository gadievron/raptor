"""Launcher-only, inherited read-only mount policy for a protected installation.

Uses RAPTOR-owned user/mount/PID namespaces without outer filesystem
Landlock or seccomp, preserving descendant namespace setup. No network or IPC namespace isolation. Executed by absolute path with python -I.
"""
from __future__ import annotations

import importlib.util
import marshal
import os
import shutil
from pathlib import Path
import stat
import sys
import sysconfig
import tempfile

class ProtectionError(RuntimeError):
    pass



def physical_path(path: Path, *, strict: bool = True) -> Path:
    """Use kernel dentry names, including on case-folded filesystems."""
    resolved = path.resolve(strict=strict)
    if sys.platform != 'linux':
        return resolved
    missing = []
    parent = resolved
    while not parent.exists():
        if strict:
            raise FileNotFoundError(parent)
        missing.append(parent.name)
        parent = parent.parent
    descriptor = os.open(parent, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if stat.S_ISLNK(os.fstat(descriptor).st_mode):
            raise ProtectionError(f'path changed to a symlink during validation: {path}')
        actual = Path(os.readlink(f'/proc/self/fd/{descriptor}'))
    finally:
        os.close(descriptor)
    return actual.joinpath(*reversed(missing))


ROOT = physical_path(Path(__file__).resolve().parents[2])


def installation_output() -> Path:
    nominal = ROOT / 'out'
    if nominal.is_symlink():
        raise ProtectionError('installation out/ must not be a symlink')
    return physical_path(nominal, strict=False)


def _term(value) -> str:
    # Load only the owning checkout's stdlib-only terminal sanitizer.
    import importlib.util
    path = Path(__file__).resolve().parents[1] / 'security/log_sanitisation.py'
    spec = importlib.util.spec_from_file_location('raptor_install_terminal', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.sanitise_for_terminal(str(value))


def protected_paths() -> list[Path]:
    paths = [ROOT, Path(sys.executable).resolve()]
    for name in ("stdlib", "platstdlib", "purelib", "platlib"):
        path = Path(sysconfig.get_path(name)).resolve()
        if path.exists():
            paths.append(path)
    if 'posix_user' in sysconfig.get_scheme_names():
        for name in ('purelib', 'platlib'):
            path = Path(sysconfig.get_path(name, scheme='posix_user')).resolve()
            if path.exists():
                paths.append(path)
    venv = ROOT / ".venv"
    if venv.exists():
        paths.append(venv.resolve())
    # The isolated setup interpreter may differ from the Python selected by
    # libexec shebangs. Locate venv state without executing that interpreter
    # (which could run site hooks before protection). Do not seal its HOME.
    for name in ("python3", "python"):
        executable = shutil.which(name)
        if not executable:
            continue
        launcher = Path(os.path.abspath(executable))
        paths.append(launcher.resolve(strict=True))
        prefix = launcher.parent.parent
        configuration = prefix / "pyvenv.cfg"
        if configuration.is_file():
            paths.extend([launcher.parent.resolve(), configuration.resolve()])
            paths.extend(path.resolve() for path in (prefix / 'lib').glob('python*') if path.is_dir())
    return list(dict.fromkeys(physical_path(path) for path in paths))


def validate_user_state(paths: list[Path], frontend: str | None = None) -> None:
    home = physical_path(Path.home(), strict=False)
    for path in paths:
        if path == home or path in home.parents:
            raise ProtectionError('protected code covers the user home; keep installation and user state separate')
    if frontend != 'claude':
        return
    configuration = physical_path(Path(os.environ.get('CLAUDE_CONFIG_DIR') or home / '.claude'), strict=False)
    account = physical_path(home / '.claude.json', strict=False)
    for path in paths:
        covers_config = path == configuration or path in configuration.parents
        foreign_config = configuration in path.parents and not (path == ROOT or ROOT in path.parents)
        if covers_config or foreign_config or path == account or path in account.parents:
            raise ProtectionError('protected code overlaps Claude user configuration; use independent installation content')


def _reject_stdio(message: str) -> None:
    # On a refusal, do not report through a second, not-yet-validated regular
    # file descriptor: it could also alias installed code or control state.
    try:
        safe_devices = ('/dev/null', '/dev/zero', '/dev/full', '/dev/random', '/dev/urandom')
        for descriptor in (0, 1, 2):
            try:
                info = os.fstat(descriptor)
            except OSError:
                continue
            if stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode) or os.isatty(descriptor):
                continue
            if stat.S_ISCHR(info.st_mode) and any(os.path.samestat(info, os.stat(path)) for path in safe_devices):
                continue
            replacement = os.open('/dev/null', os.O_RDONLY if descriptor == 0 else os.O_WRONLY)
            try:
                os.dup2(replacement, descriptor, inheritable=True)
            finally:
                os.close(replacement)
    except OSError:
        os._exit(126)  # Never let an unsafe error channel receive Python shutdown output.
    raise ProtectionError(message)


def audit_protected_paths(paths: list[Path], *, exclude_output: bool = True, follow_links: bool = True) -> list[Path]:
    """Reject writable hardlink aliases and include external symlink targets.

    No content hashes: this checks metadata before untrusted descendants start.
    An outside process with this UID can still change the host installation;
    protection only constrains the launched process tree.
    """
    anchors = list(dict.fromkeys(physical_path(path) for path in paths))
    validate_user_state(anchors)
    pending = []
    seen_directories = set()
    output = str(installation_output()) if exclude_output else ""
    stdio = {}
    for descriptor in (0, 1, 2):
        try:
            info = os.fstat(descriptor)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode):
            stdio.setdefault((info.st_dev, info.st_ino), []).append(descriptor)

    def inspect(path: str, info) -> None:
        if exclude_output and (path == output or path.startswith(output + '/')):
            return
        if stat.S_ISLNK(info.st_mode):
            if not follow_links:
                raise ProtectionError(f"symlink in launch control state: {path}")
            target = physical_path(Path(path))
            if not any(target == anchor or anchor in target.parents for anchor in anchors):
                validate_user_state([target])
                if target == Path('/') or any(target in anchor.parents for anchor in anchors):
                    raise ProtectionError(f"installation symlink exposes an ancestor: {path}")
                anchors.append(target)
                inspect(str(target), target.stat())
        elif stat.S_ISDIR(info.st_mode):
            identity = (info.st_dev, info.st_ino)
            if identity not in seen_directories:
                seen_directories.add(identity)
                pending.append(path)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink == 0:
                return  # Another launcher atomically replaced an old cache/record.
            if (info.st_dev, info.st_ino) in stdio:
                _reject_stdio(f"stdio aliases protected installation/control content: {path}")
            if info.st_nlink != 1:
                raise ProtectionError(f"hard-linked installation file: {path}; reinstall with independent copies")
        else:
            raise ProtectionError(f"non-regular installation content: {path}")

    for anchor in list(anchors):
        inspect(str(anchor), anchor.stat())
    while pending:
        try:
            entries = os.scandir(pending.pop())
        except FileNotFoundError:
            continue  # A retired authority group or temporary cache directory.
        with entries as current:
            for entry in current:
                if exclude_output and entry.path == output:
                    continue
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue  # Concurrent launchers remove atomic temporary files.
                inspect(entry.path, info)
    return list(dict.fromkeys(anchors))


def reject_loop_backing(device: str) -> None:
    """A writable disk-image file can bypass mounts of the filesystem inside it."""
    import re
    pending = [Path('/sys/dev/block') / device]
    seen = set()
    while pending:
        node = pending.pop().resolve()
        if node in seen:
            continue
        seen.add(node)
        if (device.split(':', 1)[0] == '7'
                or any(re.fullmatch(r'loop[0-9]+', part) for part in node.parts)):
            raise ProtectionError('loop-backed installation filesystems are unsupported; use independent local files')
        slaves = node / 'slaves'
        try:
            with os.scandir(slaves) as entries:
                pending.extend(Path(entry.path) for entry in entries)
        except FileNotFoundError:
            pass  # Memory filesystems and physical block devices have no slaves.


_LOCAL_FILESYSTEMS = frozenset({'ext2', 'ext3', 'ext4', 'xfs', 'tmpfs', 'ramfs', 'f2fs'})


def require_local_filesystem(path: Path, device: str, kind: str, *, parent: bool = False) -> None:
    if kind not in _LOCAL_FILESYSTEMS and not (parent and kind == 'devtmpfs'):
        raise ProtectionError(f"unsupported installation filesystem {kind}: {path}; use a local non-stacked layout")
    reject_loop_backing(device)


def protected_mount_aliases(protected: list[Path]) -> list[Path]:
    """Seal every existing bind-mount spelling of the protected physical tree."""
    import re
    output = installation_output()
    mounts = []
    types = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        fields = left.split()
        decode = lambda value: Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value))
        point, origin = decode(fields[4]), decode(fields[3])
        if right.split()[0] == 'proc' and point != Path('/proc') and Path('/proc') not in point.parents:
            raise ProtectionError(f"additional host procfs mount is unsupported: {point}")
        mounts.append((point, fields[2], origin))
        types[point] = right.split()[0]
    def coordinate(path):
        point, device, origin = max(
            (entry for entry in mounts if path == entry[0] or entry[0] in path.parents),
            key=lambda entry: len(entry[0].parts))
        return device, origin / path.relative_to(point)
    portions = [*protected, *(point for point, _, _ in mounts
                 if any(anchor in point.parents for anchor in protected)
                 and not (point == output or output in point.parents))]
    for anchor in portions:
        point, device, _ = max(
            (entry for entry in mounts if anchor == entry[0] or entry[0] in anchor.parents),
            key=lambda entry: len(entry[0].parts))
        require_local_filesystem(anchor, device, types[point])
    result = list(protected)
    for anchor in portions:
        device, origin = coordinate(anchor)
        for point, other_device, other_origin in mounts:
            if device != other_device:
                continue
            if origin == other_origin or other_origin in origin.parents:
                result.append(point / origin.relative_to(other_origin))
            elif origin in other_origin.parents:
                result.append(point)
    return list(dict.fromkeys(result))


def ancestor_bindings(paths: list[Path]) -> list[Path]:
    """Pin parent names, including aliases, without making their contents read-only."""
    import re
    if not paths:
        return []
    parents = {parent for path in paths for parent in path.parents if parent != Path('/')}
    mounts = []
    types = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        fields = left.split()
        decode = lambda value: Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value))
        point = decode(fields[4])
        mounts.append((point, fields[2], decode(fields[3])))
        types[point] = right.split()[0]
    result = set(parents)
    for parent in parents | {Path('/')}:
        point, device, origin = max(
            (entry for entry in mounts if parent == entry[0] or entry[0] in parent.parents),
            key=lambda entry: len(entry[0].parts))
        require_local_filesystem(parent, device, types[point], parent=True)
    for parent in parents:
        point, device, origin = max(
            (entry for entry in mounts if parent == entry[0] or entry[0] in parent.parents),
            key=lambda entry: len(entry[0].parts))
        physical = origin / parent.relative_to(point)
        for other_point, other_device, other_origin in mounts:
            if device == other_device and (physical == other_origin or other_origin in physical.parents):
                result.add(other_point / physical.relative_to(other_origin))
    # /dev is replaced with a private device tree; do not restore host /dev.
    return sorted((path for path in result if path != Path('/')
                   and not (path == Path('/dev') or Path('/dev') in path.parents)), key=str)


def checked_write_path(path: Path, protected: list[Path], output: Path) -> Path:
    resolved = physical_path(path, strict=False)
    output = physical_path(output, strict=False)
    for special in (Path('/proc'), Path('/sys'), Path('/dev')):
        if (resolved == special or special in resolved.parents or resolved in special.parents):
            if special == Path('/dev') and (resolved == Path('/dev/shm') or Path('/dev/shm') in resolved.parents):
                continue
            raise ProtectionError(f'writable state cannot expose a host virtual filesystem: {path}')
    for protected_path in protected:
        if resolved == protected_path or resolved in protected_path.parents:
            raise ProtectionError(f"writable path covers protected code: {path}")
        if protected_path in resolved.parents:
            if (output.parent == ROOT and (resolved == output or output in resolved.parents)
                    and (protected_path == ROOT or protected_path in ROOT.parents)):
                continue
            raise ProtectionError(f"writable path is inside protected code: {path}")
    return resolved


def writable_paths(protected: list[Path], frontend: str | None = None) -> list[Path]:
    home = Path.home()
    output = installation_output()
    paths = [output]
    # Default grants use state subtrees; every override must exclude protected code.
    for variable, fallback in (
        ("RAPTOR_OUT_DIR", output),
        ("RAPTOR_REGISTRY_HOME", home / ".raptor"),
        ("TMPDIR", home / ".cache/raptor/tmp"),
    ):
        paths.append(Path(os.environ.get(variable) or fallback))
    resolved_paths = []
    for path in paths:
        if not path.is_absolute():
            raise ProtectionError(f"writable path must be absolute: {path}")
        resolved = checked_write_path(path, protected, output)
        resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved_paths.append(resolved)
    return list(dict.fromkeys(resolved_paths))


def close_inherited_fds(protected: list[Path], output: Path, *, keep_fds: tuple = ()) -> None:
    # Read-only mounts do not revoke descriptors into the old writable view.
    # Even read-only files can be reopened through /proc/self/fd, and directory
    # descriptors permit openat() into the host tree. Keep terminal/stdio only
    # when they cannot refer into protected code; close every extra descriptor.
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 2:
            if fd in keep_fds:
                continue
            try:
                os.close(fd)
            except OSError:
                pass
            continue
        try:
            raw_target = os.readlink(f"/proc/self/fd/{fd}")
            if raw_target.startswith("anon_inode:"):
                _reject_stdio(f"stdio fd {fd} is an inherited anonymous kernel object")
            target = Path(raw_target)
            mode = os.fstat(fd).st_mode
            if stat.S_ISDIR(mode):
                _reject_stdio(f"stdio fd {fd} is a directory from the host mount namespace")
            if stat.S_ISBLK(mode):
                _reject_stdio(f"stdio fd {fd} is a raw block device")
            if stat.S_ISCHR(mode) and not os.isatty(fd):
                safe_devices = ('/dev/null', '/dev/zero', '/dev/full', '/dev/random', '/dev/urandom')
                if not any(os.path.samestat(os.fstat(fd), os.stat(path)) for path in safe_devices):
                    _reject_stdio(f"stdio fd {fd} is an unsupported device")
        except OSError:
            continue
        if target.is_absolute():
            canonical = target.resolve()
            for path in protected:
                if canonical == path or path in canonical.parents:
                    if path == ROOT and (canonical == output or output in canonical.parents):
                        continue
                    _reject_stdio(f"stdio fd {fd} refers to protected code: {canonical}")


def _compile_bytecode(source: bytes, filename: str) -> bytes | None:
    try:
        compiled = compile(source, filename, "exec", dont_inherit=True)
    except SyntaxError:
        return None  # Intentionally invalid corpus fixtures are not importable code.
    return (importlib.util.MAGIC_NUMBER + b"\x03\x00\x00\x00"
            + importlib.util.source_hash(source) + marshal.dumps(compiled))


def _bytecode_worker(parent: int) -> None:
    import ctypes
    import signal
    # Workers are trusted compilation only, before namespace setup. They must
    # not survive a killed launcher. Check the fork-to-prctl parent-death race.
    if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise ProtectionError("could not arm bytecode worker parent-death signal")
    if os.getppid() != parent:
        os._exit(1)


def _bytecode_sources():
    excluded = {"out", ".git", "__pycache__", "node_modules", "tests", "fixtures", "corpus"}
    output = str(installation_output())
    pending = [str(ROOT)]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.path == output:
                    continue
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in excluded:
                        pending.append(entry.path)
                    continue
                # Only Python sources and their caches need preparation.
                if not entry.name.endswith(".py") or not entry.is_file(follow_symlinks=False):
                    continue
                path = Path(entry.path)
                cache = Path(importlib.util.cache_from_source(entry.path))
                if cache.parent.is_symlink():
                    raise ProtectionError(f"symlinked bytecode cache: {cache}")
                node = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(node, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise ProtectionError(f"hard-linked or non-regular installation source: {path}")
                    source = stream.read()
                expected_header = (importlib.util.MAGIC_NUMBER + b"\x03\x00\x00\x00"
                                   + importlib.util.source_hash(source))
                try:
                    node = os.open(cache, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise ProtectionError(f"unsafe or symlinked bytecode cache: {cache}") from error
                else:
                    with os.fdopen(node, "rb") as stream:
                        info = os.fstat(stream.fileno())
                        if info.st_nlink != 1:
                            raise ProtectionError(f"hard-linked bytecode cache: {cache}")
                        if not stat.S_ISREG(info.st_mode):
                            raise ProtectionError(f"bytecode cache must be a regular file: {cache}")
                        # Cache bodies are trusted installation content, just
                        # like source. This is invalidation, not authentication.
                        if stream.read(16) == expected_header:
                            continue
                yield path, cache, source


def _save_bytecode(cache: Path, expected: bytes | None) -> None:
    if expected is None:
        return
    # Never unmarshal existing cache data in the unconfined launcher.
    if cache.exists():
        with cache.open("rb") as stream:
            if stream.read(len(expected) + 1) == expected:
                return
    cache.parent.mkdir(parents=True, exist_ok=True)
    node, temporary = tempfile.mkstemp(prefix=".raptor-pyc-", dir=cache.parent)
    try:
        with os.fdopen(node, "wb") as stream:
            stream.write(expected)
        os.replace(temporary, cache)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def precompile() -> None:
    # All source/cache validation and cache writes remain in the parent. Workers
    # only compile source bytes; they never execute source or load old bytecode.
    from itertools import chain, islice
    sys.pycache_prefix = None
    sources = _bytecode_sources()
    first = list(islice(sources, 9))
    workers = min(4, len(os.sched_getaffinity(0)))
    if len(first) < 9 or workers < 2:
        for path, cache, source in chain(first, sources):
            _save_bytecode(cache, _compile_bytecode(source, str(path)))
        return
    import multiprocessing
    from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, as_completed, wait
    from concurrent.futures.process import BrokenProcessPool
    # Linux launcher setup is single-threaded here. Fork shares trusted setup
    # state without re-importing the installation in child startup.
    try:
        pool = ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("fork"),
                                   initializer=_bytecode_worker, initargs=(os.getpid(),))
    except OSError:
        # Restricted IPC resources need not prevent full serial validation.
        for path, cache, source in chain(first, sources):
            _save_bytecode(cache, _compile_bytecode(source, str(path)))
        return
    try:
        with pool:
            pending = {}
            for path, cache, source in chain(first, sources):
                pending[pool.submit(_compile_bytecode, source, str(path))] = cache
                if len(pending) >= workers * 2:
                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for result in done:
                        _save_bytecode(pending.pop(result), result.result())
            for result in as_completed(pending):
                _save_bytecode(pending[result], result.result())
    except BrokenProcessPool as error:
        raise ProtectionError("bytecode compilation worker failed; no frontend was started") from error


def require_platform() -> None:
    if sys.platform != "linux":
        raise ProtectionError("installation protection requires Linux with user and mount namespaces")


def open_grant(path: Path, protected: list[Path]) -> int:
    node = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=node)
            os.close(node)
            node = child
            if stat.S_ISLNK(os.fstat(node).st_mode):
                raise ProtectionError(f"writable grant contains a symlink after validation: {path}")
        actual = Path(os.readlink(f"/proc/self/fd/{node}"))
        checked_write_path(actual, protected, ROOT / "out")
        info = os.fstat(node)
        for anchor in protected:
            if os.path.samestat(info, anchor.stat()):
                raise ProtectionError(f"writable grant aliases a protected root: {path}")
        return node
    except BaseException:
        os.close(node)
        raise


def reject_mount_aliases(paths: list[Path], protected: list[Path]) -> None:
    import re
    output = installation_output()
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        fields = left.split()
        decode = lambda value: Path(re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value))
        point, origin = decode(fields[4]), decode(fields[3])
        if right.split()[0] == "proc" and point != Path("/proc") and Path("/proc") not in point.parents:
            raise ProtectionError(f"additional host procfs mount is unsupported: {point}")
        mounts.append((point, fields[2], origin))

    def coordinate(path):
        candidates = [(point, device, origin) for point, device, origin in mounts
                      if path == point or point in path.parents]
        if not candidates:
            raise ProtectionError(f"cannot identify mount for {path}")
        point, device, origin = max(candidates, key=lambda item: len(item[0].parts))
        return device, origin / path.relative_to(point)

    protected_portions = []
    for anchor in protected:
        protected_portions.append(anchor)
        for point, _, _ in mounts:
            if anchor not in point.parents:
                continue
            if anchor == ROOT and (point == output or output in point.parents):
                continue
            # An installed vendor/package tree may itself be a bind mount.
            # Protect its physical source too, not only the install's fs root.
            protected_portions.append(point)
    protected_coordinates = [coordinate(path) for path in protected_portions]
    root_device, root_origin = coordinate(ROOT)
    output_coordinate = (root_device, root_origin / output.relative_to(ROOT))
    for grant in paths:
        # A recursive writable bind includes every existing submount.
        portions = [grant] + [point for point, _, _ in mounts if grant in point.parents]
        for portion in portions:
            device, origin = coordinate(portion)
            for protected_device, protected_origin in protected_coordinates:
                if device != protected_device:
                    continue
                if origin == protected_origin or origin in protected_origin.parents or protected_origin in origin.parents:
                    # Only the actual installation out subtree is exempt, never an alias to it.
                    output_device, output_origin = output_coordinate
                    if (portion == output or output in portion.parents) and device == output_device and (
                            origin == output_origin or output_origin in origin.parents):
                        continue
                    raise ProtectionError(f"writable mount aliases protected code: {portion}")


def prepare_session_registry(frontend: str | None, *, owned_root: Path | None = None) -> None:
    if frontend is None:
        return
    # PIDs repeat between outer PID namespaces. Reuse the existing registry
    # override protocol, but give each launch
    # its own session directory. Projects/bookmarks stay shared by symlink.
    home = Path.home()
    original = os.environ.get("RAPTOR_REGISTRY_HOME")
    projects = (Path(original) if original else home / ".raptor") / "projects"
    sessions = Path(original) if original else home / ".local/share/raptor"
    base = (owned_root / "tmp" / "protected-sessions" if owned_root is not None
            else sessions / "protected-sessions")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    projects.mkdir(mode=0o700, parents=True, exist_ok=True)
    registry = Path(tempfile.mkdtemp(prefix="session-", dir=base))
    (registry / "projects").symlink_to(projects, target_is_directory=True)
    os.environ["RAPTOR_REGISTRY_HOME"] = str(registry)


def verify_inside() -> None:
    require_platform()
    status = Path("/proc/self/status").read_text()
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    if (not os.statvfs(ROOT).f_flag & os.ST_RDONLY
            or fields.get("NoNewPrivs", "").strip() != "1"
            or any(int(fields.get(name, "1").strip(), 16) != 0
                   for name in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"))):
        raise ProtectionError("protected launcher stage requires read-only mounts, no capabilities and no_new_privs")


def native_namespace():
    # Load only our adjacent, trusted, stdlib-only setup module. Never resolve
    # helpers from cwd, target paths or PATH, and never invoke an external runner.
    path = Path(__file__).with_name("_install_namespace.py")
    spec = importlib.util.spec_from_file_location("raptor_install_namespace", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scratch_metadata():
    path = ROOT / 'core/security/launch_scratch.py'
    spec = importlib.util.spec_from_file_location('raptor_launch_scratch', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def enter_frontend(command: list[str]) -> None:
    verify_inside()
    os.environ["RAPTOR_INSTALL_PROTECTED"] = "1"
    os.environ["_RAPTOR_JOERN_TMP_BASE"] = os.environ["TMPDIR"]
    os.environ.pop("PYTHONPYCACHEPREFIX", None)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.execvp(command[0], command)


def _security_module(name: str):
    path = ROOT / 'core/security' / (name + '.py')
    spec = importlib.util.spec_from_file_location('raptor_guard_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _lifecycle_context(metadata: Path | None):
    if metadata is None:
        return None
    try:
        os.lstat(metadata.parent / 'session-id')
    except FileNotFoundError:
        return None  # Direct kernel checks/legacy launches have no session row.
    lifecycle = _security_module('scratch_lifecycle')
    session_id = lifecycle.session_for(metadata)
    with lifecycle.locked(session_id) as (_, value):
        namespace_owned = value['backend'] == 'untracked' and value['state'] in {'retained', 'active'}
    if namespace_owned:
        bound, _ = scratch_metadata()._restore_authorized(
            os.environ.get('_RAPTOR_SCRATCH_AUTH', ''), require_sealed=False)
        if bound != metadata:
            raise ProtectionError('namespace cleanup does not belong to the launcher')
    return lifecycle, session_id, namespace_owned


def _run_namespace(grants, readonly, command, frontend, context, bindings=()) -> int:
    if context is None or not context[2]:
        # Direct kernel checks without a managed launcher record have no
        # scratch lifetime to close here.
        prepare_session_registry(frontend)
        return native_namespace().run(grants, lambda: enter_frontend(command), readonly=readonly, bindings=bindings)
    lifecycle, session_id, _ = context
    lifecycle.claim(session_id, 'pid-namespace', allow_active=True)
    with lifecycle.locked(session_id) as (_, value):
        owned_root = Path(value['root'])
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read)
        try:
            prepare_session_registry(frontend, owned_root=owned_root)
            status = native_namespace().run(grants, lambda: enter_frontend(command),
                                             readonly=readonly, bindings=bindings, close_in_child=(write,))
            # Only the setup supervisor retains this writer. Namespace PID 1
            # closes it before any frontend/target can execute, and run() returns
            # only after reaping that init. No inherited environment token is a
            # substitute for this process-tree closure receipt.
            os.write(write, b'C')
            os._exit(status)
        except BaseException as exc:
            print(f'raptor: protected namespace setup failed ({type(exc).__name__})',
                  file=sys.stderr, flush=True)
            os._exit(126)
    os.close(write)
    try:
        waiter = _security_module('scratch_supervisor')
        status = waiter._wait(child)
        proof = os.read(read, 2)
        if proof == b'C':
            lifecycle.record_closed(session_id, 'pid-namespace')
            try:
                lifecycle.cleanup(session_id)
            except (OSError, ValueError, TypeError):
                print(f'raptor: session {session_id}: cleanup incomplete; inspect with bin/raptor cleanup --list',
                      file=sys.stderr)
        else:
            with lifecycle.locked(session_id) as (node, value):
                value.update(state='retained', reason='namespace closure receipt unavailable')
                lifecycle._write(node, session_id + '.json', value)
        return waiter._result(status)
    finally:
        os.close(read)


def main() -> int:
    try:
        arguments = sys.argv[1:]
        if arguments[:1] == ["--verify"]:
            verify_inside()
            return 0
        frontend = None
        if arguments[:1] == ["--frontend"]:
            if len(arguments) < 4 or arguments[1] != "claude":
                raise ProtectionError("invalid frontend identity")
            frontend = arguments[1]
            arguments = arguments[2:]
        if len(arguments) < 2 or arguments[0] != "--":
            raise ProtectionError("expected -- followed by the command")
        command = arguments[1:]
        require_platform()
        protected = protected_paths()
        validate_user_state(protected, frontend)
        close_inherited_fds(protected, ROOT / "out")
        protected = audit_protected_paths(protected)
        validate_user_state(protected, frontend)
        close_inherited_fds(protected, ROOT / "out")
        paths = writable_paths(protected, frontend)
        reject_mount_aliases(paths, protected)
        grants = []
        readonly = []
        bindings = []
        try:
            code_seals = set(protected_mount_aliases(protected))
            for path in sorted(code_seals, key=str):
                readonly.append((path, open_grant(path, [])))
            context = None
            metadata = os.environ.get('_RAPTOR_LAUNCH_METADATA')
            if metadata:
                metadata = Path(metadata)
                expected = scratch_metadata().read(metadata, require_sealed=False, require_protected=True)
                if expected != os.environ.get('TMPDIR'):
                    raise ProtectionError('scratch grant differs from launcher metadata')
                metadata_directory = physical_path(metadata.parent)
                if any(path == metadata_directory or metadata_directory in path.parents for path in paths):
                    raise ProtectionError('writable grant overlaps launch metadata')
                readonly.append((metadata_directory, open_grant(metadata_directory, [])))
                context = _lifecycle_context(metadata)
                if context is not None:
                    control = physical_path(context[0].registry())
                    if any(path == control or control in path.parents for path in paths):
                        raise ProtectionError('writable scratch/output overlaps cleanup control state')
                    readonly.append((control, open_grant(control, [])))
                    authorities = physical_path(context[0].authority_family())
                    readonly.append((authorities, open_grant(authorities, [])))
            controls = [path for path, _ in readonly if path not in code_seals]
            audit_protected_paths(controls, exclude_output=False, follow_links=False)
            close_inherited_fds([path for path, _ in readonly], ROOT / "out",
                                keep_fds=tuple(node for _, node in readonly))
            sealed = {path for path, _ in readonly}
            for path in protected_mount_aliases(list(sealed)):
                if path not in sealed:
                    readonly.append((path, open_grant(path, [])))
                    sealed.add(path)
            for path in paths:
                grants.append((path, open_grant(path, protected)))
            for path in ancestor_bindings([path for path, _ in readonly]):
                bindings.append((path, open_grant(path, [])))
            precompile()
            return _run_namespace(grants, readonly, command, frontend, context, bindings)
        finally:
            for _, node in [*grants, *readonly, *bindings]:
                try:
                    os.close(node)
                except OSError:
                    pass
    except (OSError, RuntimeError, ImportError, ValueError, TypeError) as exc:
        try:
            print(f"raptor: installation protection failed: {_term(exc)}\n"
                  "No frontend was started. Start a new terminal session without --protect-install for normal behavior.", file=sys.stderr)
        except (OSError, ValueError):
            return 126  # Unsafe inherited stderr may have been deliberately closed.
        return 126
    return 126


if __name__ == "__main__":
    raise SystemExit(main())

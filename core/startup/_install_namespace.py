"""Linux launcher namespace setup; stdlib-only, no external sandbox runner.

Uses the same user/mount/PID namespace ordering as core.sandbox._spawn and
mount_ns. Unlike a target sandbox, it keeps the host tree readable and network
available. No filesystem Landlock is installed around future target sandboxes.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import platform
import signal
import stat
import sys
import tempfile
import select

USER, MOUNT, PID = 0x10000000, 0x00020000, 0x20000000
BIND, REC, PRIVATE = 0x1000, 0x4000, 0x40000
NOSUID, NODEV, NOEXEC = 2, 4, 8
AT_RECURSIVE = 0x8000
RDONLY = 1
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
_LIBC.mount.restype = ctypes.c_int


class MountAttr(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ('attr_set', 'attr_clr', 'propagation', 'userns_fd')]


class CapHeader(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]


class CapData(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ('effective', 'permitted', 'inheritable')]



def _term(value) -> str:
    # Load only the owning checkout's stdlib-only terminal sanitizer.
    import importlib.util
    path = Path(__file__).resolve().parents[1] / 'security/log_sanitisation.py'
    spec = importlib.util.spec_from_file_location('raptor_install_terminal', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.sanitise_for_terminal(str(value))


def checked(result: int, operation: str) -> None:
    if result < 0:
        number = ctypes.get_errno()
        raise OSError(number, f'native installation namespace: {operation}: {os.strerror(number)}')


def mount(source: str | None, target: str, kind: str | None = None, flags: int = 0, data: str | None = None) -> None:
    encode = lambda value: None if value is None else os.fsencode(value)
    checked(_LIBC.mount(encode(source), encode(target), encode(kind), flags, encode(data)), f'mount {target}')


def mount_attributes(path: str, *, set_flags: int = 0, clear_flags: int = 0, recursive: bool = False) -> None:
    # asm-generic and x86 syscall tables: Linux 5.12+.
    if platform.machine() not in {'x86_64', 'aarch64', 'riscv64'}:
        raise OSError(errno.ENOSYS, 'native installation namespaces require x86_64/aarch64/riscv64')
    attr = MountAttr(set_flags, clear_flags, 0, 0)
    checked(_LIBC.syscall(442, -100, os.fsencode(path), AT_RECURSIVE if recursive else 0,
                         ctypes.byref(attr), ctypes.sizeof(attr)), f'mount_setattr {path}')


def user_namespace(inside_uid: int, inside_gid: int, *, mount_namespace: bool = False) -> None:
    uid, gid = os.geteuid(), os.getegid()
    checked(_LIBC.unshare(USER | (MOUNT if mount_namespace else 0)), 'unshare user/mount')
    # These are launcher self-mappings, not a replacement for target idmap
    # helpers. No subordinate IDs or privileged helper are requested.
    Path('/proc/self/uid_map').write_text(f'{inside_uid} {uid} 1\n')
    if Path('/proc/self/setgroups').read_text().strip() != 'deny':
        Path('/proc/self/setgroups').write_text('deny\n')
    Path('/proc/self/gid_map').write_text(f'{inside_gid} {gid} 1\n')


def drop_capabilities(last: int | None = None) -> None:
    # Lock root/setuid fixups before clearing every capability. A future
    # descendant may still create its own, less privileged user namespace.
    checked(_LIBC.prctl(38, 1, 0, 0, 0), 'no_new_privs')
    checked(_LIBC.prctl(28, 0x0f, 0, 0, 0), 'lock securebits')
    if last is None:
        last = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
    if not 0 <= last < 64:
        raise OSError(errno.ENOSYS, 'unsupported kernel capability range')
    for capability in range(last + 1):
        checked(_LIBC.prctl(24, capability, 0, 0, 0), 'drop capability bounding set')
    header, data = CapHeader(0x20080522, 0), (CapData * 2)()
    checked(_LIBC.capset(ctypes.byref(header), ctypes.byref(data)), 'clear capabilities')


def repin_current_mount(path: Path, original: int) -> int:
    # Linux rejects bind sources whose mount belongs to another namespace.
    # Reopen in this namespace without following links, then check the inode
    # against the caller's pinned grant before using the new descriptor.
    node = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=node)
            os.close(node)
            node = child
            if stat.S_ISLNK(os.fstat(node).st_mode):
                raise OSError(errno.ELOOP, f'state grant changed to a symlink: {path}')
        if not os.path.samestat(os.fstat(node), os.fstat(original)):
            raise OSError(errno.ESTALE, f'state grant changed before namespace setup: {path}')
        return node
    except BaseException:
        os.close(node)
        raise


def device_sources() -> list[tuple[str, int]]:
    nodes = []
    try:
        for name in ('null', 'zero', 'full', 'random', 'urandom', 'tty'):
            node = os.open('/dev/' + name, os.O_PATH | os.O_CLOEXEC)
            nodes.append((name, node))
            if not stat.S_ISCHR(os.fstat(node).st_mode):
                raise OSError(errno.EINVAL, f'/dev/{name} is not a character device')
        return nodes
    except BaseException:
        for _, node in nodes:
            os.close(node)
        raise


def minimal_devices(nodes: list[tuple[str, int]]) -> None:
    mount('tmpfs', '/dev', 'tmpfs', NOSUID | NOEXEC, 'mode=755,size=8m,nr_inodes=16384')
    for name, node in nodes:
        path = '/dev/' + name
        Path(path).touch(mode=0o600)
        mount(f'/proc/self/fd/{node}', path, flags=BIND)
    Path('/dev/pts').mkdir()
    mount('devpts', '/dev/pts', 'devpts', NOSUID | NOEXEC,
          'newinstance,ptmxmode=0666,mode=0620,gid=0,max=256')
    Path('/dev/shm').mkdir()
    mount('tmpfs', '/dev/shm', 'tmpfs', NOSUID | NODEV,
          'mode=1777,size=256m,nr_inodes=65536')
    for name, destination in [('ptmx', 'pts/ptmx'), ('fd', '/proc/self/fd'),
                              ('stdin', '/proc/self/fd/0'), ('stdout', '/proc/self/fd/1'),
                              ('stderr', '/proc/self/fd/2')]:
        Path('/dev', name).symlink_to(destination)


def setup_mounts(grants: list[tuple[Path, int]], nodes: list[tuple[str, int]],
                 readonly: tuple | list = (), bindings: tuple | list = ()) -> None:
    # PID namespace entry has already happened. This procfs cannot expose the
    # old host view through /proc/PID/root or /proc/PID/fd.
    mount('proc', '/proc', 'proc', NOSUID | NODEV | NOEXEC)
    minimal_devices(nodes)
    # Leave ordinary user files and /tmp writable. Only installation mounts
    # and control metadata are sealed; no broad HOME/configuration grants.
    mount_attributes('/', set_flags=NOSUID | NODEV, recursive=True)
    mount_attributes('/dev', clear_flags=NODEV, recursive=True)
    mount_attributes('/dev/shm', set_flags=NODEV)
    policies = [(path, True) for path, _ in readonly]
    policies.extend((path, False) for path, _ in grants)
    policy_roots = {path for path, _ in policies}
    def needs_binding(path):
        if path in policy_roots:
            return False  # Its final policy mount already pins this name.
        parents = [(anchor, sealed) for anchor, sealed in policies if anchor in path.parents]
        if not parents:
            return True
        return not max(parents, key=lambda item: len(item[0].parts))[1]
    # Never rebind an original writable descriptor beneath sealed code: that
    # would reopen a hole in the read-only subtree merely to pin a name.
    operations = [(path, node, None) for path, node in bindings if needs_binding(path)]
    # Private shm parent names must also be pinned, but cannot use host /dev.
    for path, _ in readonly:
        if Path('/dev/shm') in path.parents:
            operations.extend((parent, None, None) for parent in path.parents
                              if Path('/dev/shm') in parent.parents and needs_binding(parent))
    operations.extend((path, node, True) for path, node in readonly)
    operations.extend((path, node, False) for path, node in grants)
    for path, node, sealed in sorted(operations, key=lambda item: len(item[0].parts)):
        if Path('/dev/shm') in path.parents:
            destination = Path('/dev/shm')
            for part in path.relative_to(destination).parts:
                destination /= part
                destination.mkdir(mode=0o700, exist_ok=True)
        source = str(path) if node is None else f'/proc/self/fd/{node}'
        mount(source, str(path), flags=BIND | REC)
        if sealed is None:
            continue  # Keep the parent's permissions; the mount pins its name.
        if sealed:
            mount_attributes(str(path), set_flags=RDONLY | NOSUID | NODEV, recursive=True)
        else:
            mount_attributes(str(path), set_flags=NOSUID | NODEV, clear_flags=RDONLY, recursive=True)
        actual = bool(os.statvfs(path).f_flag & os.ST_RDONLY)
        if actual != sealed:
            raise OSError(errno.EROFS, f'installation/state mount has incorrect write policy: {path}')


def exit_code(status: int) -> int:
    return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)


def arm_parent_death(death: int) -> None:
    checked(_LIBC.prctl(1, signal.SIGKILL, 0, 0, 0), 'arm namespace parent death')
    # PR_SET_PDEATHSIG alone has a fork->prctl race. The inherited pipe tells
    # us if the outside supervisor already died before the signal was armed.
    if select.select([death], [], [], 0)[0] and not os.read(death, 1):
        os._exit(125)


def _close_setup_fds(death: int) -> None:
    # CLOEXEC does not protect the Python namespace init, which forks without
    # exec. Setup/import machinery may retain descriptors beyond the explicit
    # mount pins. Keep only validated stdio and the parent-death race pipe.
    for name in os.listdir('/proc/self/fd'):
        descriptor = int(name)
        if descriptor <= 2 or descriptor == death:
            continue
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise  # The listing's own, already-closed descriptor is normal.


def namespace_init(death: int, enter) -> None:
    arm_parent_death(death)
    _close_setup_fds(death)
    os.close(death)
    frontend = os.fork()
    if frontend == 0:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, signal.SIG_DFL)
        try:
            enter()
        except BaseException as error:
            print(f'raptor: protected frontend could not start: {_term(error)}', file=sys.stderr, flush=True)
        os._exit(126)

    signal.signal(signal.SIGINT, lambda *_: None)  # terminal also signals frontend
    def forward(signum, _frame):
        try:
            os.kill(frontend, signum)
        except ProcessLookupError:
            pass
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, forward)
    while True:
        try:
            pid, status = os.waitpid(-1, 0)
        except InterruptedError:
            continue
        if pid == frontend:
            # Exiting PID 1 makes the kernel kill any remaining namespace
            # processes, including descendants that changed sessions/groups.
            os._exit(exit_code(status))


def run(grants: list[tuple[Path, int]], enter, *, readonly: tuple | list = (),
        close_in_child: tuple | list = (), bindings: tuple | list = ()) -> int:
    uid, gid = os.geteuid(), os.getegid()
    cwd = os.getcwd()
    last_cap = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
    original_grants = [node for _, node in [*grants, *readonly, *bindings]]
    descriptors = []
    death_r, death_w = os.pipe2(os.O_CLOEXEC)
    try:
        parent = os.getppid()
        checked(_LIBC.prctl(1, signal.SIGKILL, 0, 0, 0), 'arm launcher parent death')
        if os.getppid() != parent:
            raise OSError(errno.ESRCH, 'launcher parent exited during namespace startup')
        # Root-mapped setup permits a fresh devpts instance. The application
        # later gets its original numeric identity in a second namespace.
        user_namespace(0, 0, mount_namespace=True)
        mount(None, '/', flags=PRIVATE | REC)
        local_bindings = []
        for path, original in bindings:
            node = repin_current_mount(path, original)
            descriptors.append(node)
            local_bindings.append((path, node))
        local_grants = []
        for path, original in grants:
            node = repin_current_mount(path, original)
            descriptors.append(node)
            local_grants.append((path, node))
        local_readonly = []
        for path, original in readonly:
            node = repin_current_mount(path, original)
            descriptors.append(node)
            local_readonly.append((path, node))
        # Device pins must also belong to the new mount namespace, before its
        # host /dev is covered by the private device filesystem.
        nodes = device_sources()
        descriptors.extend(node for _, node in nodes)
        checked(_LIBC.unshare(PID), 'unshare pid')
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        init = os.fork()
        if init == 0:
            for fd in close_in_child:
                os.close(fd)
            os.close(death_w)
            try:
                arm_parent_death(death_r)
                setup_mounts(local_grants, nodes, local_readonly, local_bindings)
                # Re-resolve cwd in the new mount view. A detached/inherited
                # cwd must never retain an old writable mount reference.
                os.chdir('/')
                os.chdir(cwd)
                for node in [*descriptors, *original_grants]:
                    os.close(node)
                # Creating the final user namespace makes the mount namespace
                # belong to an ancestor: its readonly flags cannot be relaxed.
                user_namespace(uid, gid)
                drop_capabilities(last_cap)
                namespace_init(death_r, enter)
            except BaseException as error:
                print(f'raptor: installation protection failed: {_term(error)}\nNo frontend was started.',
                      file=sys.stderr, flush=True)
                os._exit(126)
        os.close(death_r)
        death_r = -1
        for node in descriptors:
            os.close(node)
        descriptors.clear()
        # The outside supervisor has no setup capabilities/device FDs. The
        # caller owns the pinned, permitted state FDs and closes them on return.
        # Cache cap_last_cap before fork: procfs may already refer to an exited
        # child namespace by the time the outside supervisor gets scheduled.
        drop_capabilities(last_cap)
        checked(_LIBC.prctl(1, signal.SIGKILL, 0, 0, 0), 'rearm launcher parent death')
        if os.getppid() != parent:
            raise OSError(errno.ESRCH, 'launcher parent exited during namespace startup')
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        def forward(signum, _frame):
            try:
                # Let the frontend salvage its current audit. The outside
                # waiter bounds graceful shutdown; parent death kills init
                # and the kernel then terminates all namespace descendants.
                os.kill(init, signum)
            except ProcessLookupError:
                pass
        for signum in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, forward)
        while True:
            try:
                _, status = os.waitpid(init, 0)
                return exit_code(status)
            except InterruptedError:
                continue
    except BaseException:
        if 'init' in locals() and init > 0:
            try:
                os.kill(init, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(init, 0)
            except ChildProcessError:
                pass
        raise
    finally:
        # The parent-death signal and pipe close the supervision race.
        for node in [death_r, death_w, *descriptors]:
            try:
                os.close(node)
            except OSError:
                pass


def probe() -> None:
    # Exercise the actual complete backend in a worker. The probe parent stays
    # outside the namespaces so it can remove its host scratch directory.
    with tempfile.TemporaryDirectory(prefix='raptor-native-ns-probe-') as temporary:
        node = os.open(temporary, os.O_PATH | os.O_CLOEXEC)
        try:
            worker = os.fork()
            if worker == 0:
                try:
                    code = run([(Path(temporary), node)], lambda: os._exit(0))
                except OSError as error:
                    print(error, file=sys.stderr, flush=True)
                    code = 126
                os._exit(code)
            _, status = os.waitpid(worker, 0)
            if exit_code(status) != 0:
                raise OSError(errno.EPERM, 'native installation namespace probe failed')
        finally:
            os.close(node)


if __name__ == '__main__':
    try:
        if sys.argv[1:] != ['--probe']:
            raise ValueError('expected --probe')
        probe()
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(126)

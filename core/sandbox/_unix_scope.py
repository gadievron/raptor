"""AF_UNIX connect scoping for the mount-ns spawn path.

Why this exists
---------------
The mount-ns spawn path allows ``socket(AF_UNIX)`` (Python >= 3.14
multiprocessing forkserver needs it), on the rationale that pathname
sockets are unreachable through read-only mounts and abstract sockets
are netns-scoped. That rationale had a hole: the OUTPUT directory is a
READ-WRITE bind, so a host-side process (or a sibling sandbox sharing
the dir) could bind a unix socket inside it and the sandboxed child
could ``connect(2)`` — a live bidirectional channel out of the sandbox.

Neither Landlock (no access right covers unix connect), the mount
namespace (the bind is rw by design), nor classic seccomp-BPF (the
sockaddr lives behind a pointer) can express "connect only to THIS
sandbox's sockets". Seccomp user-space notification can: ``connect(2)``
is routed to a supervisor thread in the RAPTOR parent, which reads the
sockaddr from the child's memory, resolves pathname targets inside the
child's own mount view via ``openat2(RESOLVE_IN_ROOT |
RESOLVE_NO_SYMLINKS)``, applies the policy, and — crucially — EXECUTES
the connect itself on a ``pidfd_getfd``-duplicated handle of the
child's socket. Executing instead of continuing eliminates the classic
user-notify TOCTOU (a sibling thread rewriting the sockaddr after the
check): the address the supervisor validated is the address it
connects, and for pathname targets the O_PATH fd pins the exact inode.

Policy
------
- Non-AF_UNIX connects: executed on the child's behalf — never
  CONTINUE'd, closing the family-swap TOCTOU. The socket's own netns
  governs routing, so netns isolation is preserved; but Landlock
  network rules are TASK-scoped, not socket-scoped, so the supervisor
  re-applies the run's declared TCP policy itself: when the run
  declared ``allowed_tcp_ports``, AF_INET/AF_INET6 stream connects to
  any other port get EACCES (the same errno the child's own Landlock
  domain would have returned). Without this re-check the supervisor —
  an unconfined parent task — would silently void the child's
  Landlock CONNECT_TCP rules on every mount-ns run.
- AF_UNIX abstract: executed only when this run gave the child its
  OWN network namespace (abstract names are netns-scoped). On
  shared-netns runs (``block_network=False`` without a coordinator
  netns) the name resolves in the HOST's abstract namespace, so the
  connect is refused (EPERM) — the child's Landlock abstract-socket
  scope (ABI 6) cannot help here because it, too, is task-scoped and
  never evaluates for a supervisor-executed connect.
- AF_UNIX unnamed (zero-length): executed as read (kernel EINVAL).
- AF_UNIX pathname: allowed only when the resolved target inode lives
  on one of the sandbox's PRIVATE tmpfs mounts (/tmp, /run, /dev/shm —
  per-sandbox by construction on this path) or is one of the
  explicitly allowlisted sockets owned by this sandbox instance (its
  egress-proxy lane). Everything else — the rw output bind included —
  gets EPERM. Symlinked paths are refused (RESOLVE_NO_SYMLINKS), so a
  child cannot bounce through /tmp into the output dir.
- Relative sockaddr paths are refused (no legitimate in-sandbox user;
  resolving them against a racing cwd is not worth the surface).

Binds remain unrestricted by design (documented operator ruling) —
only CONNECT is scoped.

Availability
------------
Requires seccomp user-notify (Linux 5.0 + libseccomp 2.5),
``pidfd_getfd`` (5.6) and ``openat2`` (5.6). ``probe_unix_scope()``
checks all three once per process; on hosts that lack them the caller
must fail CLOSED by keeping AF_UNIX in the seccomp blocklist (the
pre-allow_unix behaviour).
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import fcntl
import logging
import os
import platform
import socket
import stat as stat_mod
import struct
import threading
import time

from . import state

logger = logging.getLogger(__name__)

# asm-generic syscall numbers (post-2011 table; same gate as landlock.py)
_ARCH_OK = platform.machine() in (
    "x86_64", "aarch64", "riscv64", "loongarch64", "s390x",
)
_SYS_PIDFD_OPEN = 434
_SYS_PIDFD_GETFD = 438
_SYS_OPENAT2 = 437

# pidfd_open(2) flag (include/uapi/linux/pidfd.h, Linux 6.9+): open a
# pidfd for a specific TASK rather than a thread-group leader.
_PIDFD_THREAD = 0x80  # == O_EXCL

# openat2 resolve flags (include/uapi/linux/openat2.h)
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_IN_ROOT = 0x10

# seccomp user-notify ioctls over struct seccomp_notif (80 bytes:
# u64 id + u32 pid + u32 flags + seccomp_data{int nr, u32 arch,
# u64 ip, u64 args[6]}) and struct seccomp_notif_resp (24 bytes:
# u64 id + s64 val + s32 error + u32 flags). _IOWR('!', nr, size).
_NOTIF_FMT = "<QII" + "iIQ" + "6Q"
_NOTIF_SIZE = struct.calcsize(_NOTIF_FMT)
_RESP_FMT = "<QqiI"
_RESP_SIZE = struct.calcsize(_RESP_FMT)
assert _NOTIF_SIZE == 80, _NOTIF_SIZE
assert _RESP_SIZE == 24, _RESP_SIZE


def _iowr(nr: int, size: int) -> int:
    return (3 << 30) | (size << 16) | (0x21 << 8) | nr


def _iow(nr: int, size: int) -> int:
    return (1 << 30) | (size << 16) | (0x21 << 8) | nr


_IOCTL_NOTIF_RECV = _iowr(0, _NOTIF_SIZE)
_IOCTL_NOTIF_SEND = _iowr(1, _RESP_SIZE)
_IOCTL_NOTIF_ID_VALID = _iow(2, 8)

# Bound on concurrently in-flight proxied connects. A child spamming
# blocking connects to a never-accepting listener would otherwise grow
# one supervisor worker per attempt.
_MAX_INFLIGHT = 32

# Bound on how long one executed connect may keep a supervisor worker
# (and its dup of the child's socket) alive. Comfortably above the
# kernel's own TCP connect timeout ladder; a hostile child pointing a
# blocking connect at a never-completing target cannot park workers
# past this. The child sees ETIMEDOUT, which a blocking connect can
# already produce.
_CONNECT_DEADLINE_S = 120.0

# Watchdog deadline for everything BEFORE a worker legitimately enters
# the bounded EINPROGRESS wait: sockaddr read, policy checks, and the
# connect(2) entry itself — all sub-millisecond for every legitimate
# shape even on a loaded host (a nonblocking connect returns
# immediately; the only way to spend real time here is the OFD flag
# race parking a worker in a blocking connect), so 3 s is a >1000x
# margin. Workers that reach the EINPROGRESS poll extend their
# deadline to the full connect budget before waiting.
_PRE_CONNECT_DEADLINE_S = 3.0

_libc = None


def _get_libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
    return _libc


def _sc(nr: int, *args) -> tuple[int, int]:
    libc = _get_libc()
    cargs = []
    for a in args:
        if isinstance(a, bytes):
            cargs.append(ctypes.c_char_p(a))
        elif isinstance(a, int):
            cargs.append(ctypes.c_ulong(a & 0xFFFFFFFFFFFFFFFF))
        else:
            cargs.append(a)
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr), *cargs)
    return int(r), (ctypes.get_errno() if r == -1 else 0)


def _pidfd_open(pid: int, flags: int = 0) -> int:
    r, e = _sc(_SYS_PIDFD_OPEN, pid, flags)
    if r < 0:
        raise OSError(e, os.strerror(e))
    return r


def _tgid_of(tid: int) -> int:
    """Thread-group id of ``tid`` from ``/proc/<tid>/status``.

    ``/proc/<tid>`` resolves for non-leader tasks too (hidden from
    readdir, directly accessible). Raises OSError when the task is
    gone or the field is missing (treated as "deny" by the caller).
    """
    with open(f"/proc/{tid}/status", "rb") as f:
        for line in f:
            if line.startswith(b"Tgid:"):
                return int(line.split()[1])
    raise OSError(errno.ESRCH, os.strerror(errno.ESRCH))


def _pidfd_open_task(tid: int) -> int:
    """pidfd for the notifying task — leader or spawned thread.

    ``seccomp_notif.pid`` is the calling THREAD's tid.
    ``pidfd_open(tid, 0)`` only accepts thread-group leaders, so a
    connect(2) made from a spawned thread used to fail here before any
    policy ran — denying every threaded caller inside a mount-ns
    sandbox. The non-leader refusal errno is kernel-dependent: EINVAL
    through 6.15 (``pidfd_prepare`` rejects non-leaders as invalid),
    ENOENT from the pidfs rework (~6.16) on. The supervisor always
    passes a kernel-supplied tid > 0 with flags 0, so either errno
    here can only mean "not a thread-group leader" (a dead tid is
    ESRCH). For non-leader tids, retry with PIDFD_THREAD (Linux 6.9+;
    pidfd_getfd works on task pidfds because the fd table is shared
    across the thread group), then fall back to resolving the tgid
    from /proc/<tid>/status on older kernels.

    Identity safety is unchanged: every path is followed by the
    caller's ID_VALID re-check — if the notification is still alive,
    the calling task is still blocked in the syscall, so neither the
    tid nor the tgid it belonged to can have been recycled.
    """
    try:
        return _pidfd_open(tid)
    except OSError as e:
        if e.errno not in (errno.ENOENT, errno.EINVAL):
            raise
    try:
        return _pidfd_open(tid, _PIDFD_THREAD)
    except OSError as e:
        # EINVAL: kernel < 6.9 rejects the flag — resolve the leader.
        if e.errno not in (errno.EINVAL, errno.ENOENT):
            raise
    return _pidfd_open(_tgid_of(tid))


def _pidfd_getfd(pidfd: int, target_fd: int) -> int:
    r, e = _sc(_SYS_PIDFD_GETFD, pidfd, target_fd, 0)
    if r < 0:
        raise OSError(e, os.strerror(e))
    return r


def _getsockopt_int(fd: int, level: int, opt: int) -> int | None:
    libc = _get_libc()
    val = ctypes.c_int(0)
    size = ctypes.c_uint(ctypes.sizeof(val))
    rc = libc.getsockopt(fd, level, opt,
                         ctypes.byref(val), ctypes.byref(size))
    return int(val.value) if rc == 0 else None


def _openat2(dirfd: int, path: bytes, flags: int, resolve: int) -> int:
    how = struct.pack("<QQQ", flags, 0, resolve)
    r, e = _sc(_SYS_OPENAT2, dirfd, path,
               ctypes.c_char_p(how), len(how))
    if r < 0:
        raise OSError(e, os.strerror(e))
    return r


def probe_unix_scope() -> bool:
    """True when the connect-scoping supervisor can run here.

    Checks (cached per process):
      1. libseccomp exposes ``seccomp_notify_fd`` AND the kernel
         accepts a filter with SCMP_ACT_NOTIFY (functional child-
         process probe, mirroring the Landlock self-test doctrine).
      2. ``pidfd_open``/``pidfd_getfd`` work (self-probe).
      3. ``openat2`` exists.
    """
    with state._cache_lock:
        if state._unix_scope_cache is not None:
            return state._unix_scope_cache
        state._unix_scope_cache = _probe_unix_scope_uncached()
        if not state._unix_scope_cache:
            logger.debug(
                "Sandbox: AF_UNIX connect scoping unavailable on this "
                "host — allow_unix_sockets will stay disabled "
                "(fail-closed)."
            )
        return state._unix_scope_cache


def _probe_unix_scope_uncached() -> bool:
    if not _ARCH_OK or not hasattr(socket, "AF_UNIX"):
        return False
    # openat2 — invalid dirfd distinguishes EBADF (implemented) from
    # ENOSYS.
    try:
        _openat2(-1, b"x", os.O_PATH, _RESOLVE_IN_ROOT)
        return False  # cannot succeed; treat as broken
    except OSError as e:
        if e.errno == errno.ENOSYS:
            return False
    # pidfd_open/getfd on ourselves.
    try:
        pidfd = _pidfd_open(os.getpid())
    except OSError:
        return False
    try:
        try:
            dup = _pidfd_getfd(pidfd, 0)
        except OSError:
            return False
        os.close(dup)
    finally:
        os.close(pidfd)
    # libseccomp notify API + kernel NOTIFY support, in a throwaway
    # child (loading a filter is one-way for the task).
    from .seccomp import check_seccomp_available
    if not check_seccomp_available():
        return False
    lib = state._libseccomp_cache
    try:
        _ = lib.seccomp_notify_fd
    except AttributeError:
        return False
    r, w = os.pipe()
    # Same suppression as every other production fork site: the probe
    # child only does ctypes calls + os.write + _exit — no Python
    # locks, no allocator-heavy work (see the module fork-safety
    # contract in _spawn.py).
    import warnings
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", category=DeprecationWarning,
            message=r".*fork.*may lead to deadlocks.*",
        )
        pid = os.fork()
    if pid == 0:  # probe child
        try:
            os.close(r)
            ok = b"0"
            try:
                lib.seccomp_init.restype = ctypes.c_void_p
                lib.seccomp_init.argtypes = [ctypes.c_uint32]
                lib.seccomp_notify_fd.restype = ctypes.c_int
                lib.seccomp_notify_fd.argtypes = [ctypes.c_void_p]
                lib.seccomp_load.restype = ctypes.c_int
                lib.seccomp_load.argtypes = [ctypes.c_void_p]
                _SCMP_ACT_ALLOW = 0x7FFF0000
                _SCMP_ACT_NOTIFY = 0x7FC00000
                # seccomp_load requires NO_NEW_PRIVS without
                # CAP_SYS_ADMIN — probe child only, one-way is fine.
                _get_libc().prctl(38, 1, 0, 0, 0)
                ctx = lib.seccomp_init(_SCMP_ACT_ALLOW)
                if ctx:
                    nr = lib.seccomp_syscall_resolve_name(b"acct")
                    if (nr >= 0
                            and lib.seccomp_rule_add_array(
                                ctx, _SCMP_ACT_NOTIFY, nr, 0, None) == 0
                            and lib.seccomp_load(ctx) == 0
                            and lib.seccomp_notify_fd(ctx) >= 0):
                        ok = b"1"
            except Exception:  # noqa: BLE001 — probe child, any failure = unavailable
                ok = b"0"
            with contextlib.suppress(OSError):
                os.write(w, ok)
        finally:
            os._exit(0)
    os.close(w)
    try:
        data = os.read(r, 1)
    finally:
        os.close(r)
        with contextlib.suppress(OSError):
            os.waitpid(pid, 0)
    return data == b"1"


class UnixScopeSupervisor:
    """Per-run supervisor for SCMP_ACT_NOTIFY'd ``connect(2)`` calls.

    One instance per sandboxed run; ``serve_forever()`` runs on a
    daemon thread owned by the spawn layer and exits when the notify
    fd is closed (``close()``) or errors. Every notification is
    answered — never with CONTINUE — so a supervisor death fails
    closed: the kernel returns ENOSYS to a notified syscall whose
    listener vanished.
    """

    def __init__(self, notify_fd: int,
                 allowed_socket_paths: list[str] | None = None,
                 label: str = "sandbox",
                 allowed_tcp_ports: list[int] | None = None,
                 netns_isolated: bool = False) -> None:
        self._fd = notify_fd
        self._label = label
        self._closed = threading.Event()
        self._inflight = threading.Semaphore(_MAX_INFLIGHT)
        # Per-notification deadlines, swept by serve_forever's poll
        # tick. O_NONBLOCK lives on the OPEN FILE DESCRIPTION shared
        # with the child, so a sibling child thread can clear it
        # between the worker's F_SETFL and its connect(2) — parking
        # the worker in a fully BLOCKING connect that the EINPROGRESS
        # poll path never bounds. The watchdog answers the
        # notification (ETIMEDOUT) at deadline REGARDLESS of worker
        # state, so the CHILD's syscall — and with it the run's
        # walltime — is bounded even when the worker stays parked.
        # Parked workers keep their inflight slot (never recycled
        # while parked): at most _MAX_INFLIGHT threads + socket dups
        # park, further connects fail EAGAIN (closed, not open), and
        # the dups release at teardown.
        self._notif_lock = threading.Lock()
        self._notif_deadlines: dict[int, float] = {}
        # The run's declared TCP policy. Landlock CONNECT_TCP rules are
        # task-scoped and never evaluate for a connect WE execute, so
        # the supervisor is the enforcement point on this path. None
        # means "no TCP port policy declared" (matching landlock_fn
        # construction in _spawn.py).
        self._allowed_tcp_ports: frozenset[int] | None = (
            frozenset(int(p) for p in allowed_tcp_ports)
            if allowed_tcp_ports else None)
        # True when the child got its own network namespace (fresh
        # CLONE_NEWNET). Abstract AF_UNIX names are netns-scoped;
        # without this, an abstract connect resolves in the HOST's
        # abstract namespace and must be refused.
        self._netns_isolated = bool(netns_isolated)
        # Pin the allowlisted sockets by (dev, ino) NOW, from the
        # parent's view — inode identity is immune to any path games
        # the child can play later.
        self._allowed_inodes: set[tuple[int, int]] = set()
        for p in allowed_socket_paths or []:
            try:
                st = os.stat(p)
            except OSError:
                continue
            if stat_mod.S_ISSOCK(st.st_mode):
                self._allowed_inodes.add((st.st_dev, st.st_ino))
        self._connect_nr = None
        try:
            from .seccomp import check_seccomp_available
            if check_seccomp_available():
                lib = state._libseccomp_cache
                self._connect_nr = lib.seccomp_syscall_resolve_name(
                    b"connect")
        except Exception:  # noqa: BLE001 — resolved lazily; mismatched nr just denies
            self._connect_nr = None

    # -- lifecycle ----------------------------------------------------

    def start(self) -> None:
        t = threading.Thread(target=self.serve_forever,
                             name=f"unix-scope-{self._label}",
                             daemon=True)
        t.start()

    def close(self) -> None:
        """Stop supervising. In-flight children get ENOSYS from the
        kernel once the fd is gone — fail-closed."""
        if not self._closed.is_set():
            self._closed.set()
            with contextlib.suppress(OSError):
                os.close(self._fd)

    # -- main loop ----------------------------------------------------

    def serve_forever(self) -> None:
        # Poll with a short timeout instead of blocking in the RECV
        # ioctl: close() from the run's finally cannot reliably wake a
        # thread already blocked inside ioctl(2) (the in-flight call
        # holds its own reference to the file), so a blocking design
        # would leak one supervisor thread per run. POLLNVAL after
        # close() and the timeout both route back to the closed-check.
        import select
        poller = select.poll()
        try:
            poller.register(self._fd, select.POLLIN)
        except OSError:
            return
        try:
            while not self._closed.is_set():
                try:
                    events = poller.poll(500)
                except OSError:
                    return
                self._sweep_expired()
                if not events:
                    continue
                if any(ev & (select.POLLNVAL | select.POLLERR | select.POLLHUP)
                       for _fd, ev in events):
                    return
                buf = bytearray(_NOTIF_SIZE)
                try:
                    fcntl.ioctl(self._fd, _IOCTL_NOTIF_RECV, buf)
                except OSError as e:
                    if e.errno in (errno.EINTR, errno.ENOENT):
                        # ENOENT: the notification was cancelled (the
                        # caller died) between poll and receive.
                        continue
                    # EBADF/ENOTTY after close() — the listener died.
                    return
                (nid, pid, _flags, nr, _arch, _ip,
                 a0, a1, a2, _a3, _a4, _a5) = struct.unpack(
                    _NOTIF_FMT, bytes(buf))
                if not self._inflight.acquire(blocking=False):
                    self._respond(nid, -errno.EAGAIN)
                    continue
                with self._notif_lock:
                    self._notif_deadlines[nid] = (
                        time.monotonic() + _PRE_CONNECT_DEADLINE_S)
                threading.Thread(
                    target=self._handle_one,
                    args=(nid, pid, nr, a0, a1, a2),
                    name=f"unix-scope-conn-{self._label}",
                    daemon=True,
                ).start()
        finally:
            self.close()

    # -- notification handling ----------------------------------------

    def _sweep_expired(self) -> None:
        """Answer notifications whose worker blew its deadline.

        The deny is authoritative for the CHILD (its syscall returns
        ETIMEDOUT); the worker may stay parked (see _notif_deadlines)
        and its own late respond is rejected by the kernel (unknown
        id) and suppressed. A pathname connect that later completes on
        the parked dup was ALREADY policy-validated, so the late
        completion grants nothing policy denied — the child merely
        holds a socket that connected after it saw ETIMEDOUT.
        """
        now = time.monotonic()
        with self._notif_lock:
            expired = [nid for nid, dl in self._notif_deadlines.items()
                       if dl <= now]
            for nid in expired:
                del self._notif_deadlines[nid]
        for nid in expired:
            logger.warning(
                "unix-scope[%s]: notification %d exceeded its deadline"
                " — answering ETIMEDOUT (worker may be parked on a"
                " child-schedule target)", self._label, nid)
            self._respond(nid, -errno.ETIMEDOUT)

    def _deregister_notif(self, nid: int) -> None:
        with self._notif_lock:
            self._notif_deadlines.pop(nid, None)

    def _extend_notif(self, nid: int, seconds: float) -> None:
        """Called when a worker enters a LEGITIMATE bounded wait (the
        EINPROGRESS poll) — extend the watchdog to the wait's own
        budget. Only ever extends a still-registered notification."""
        with self._notif_lock:
            if nid in self._notif_deadlines:
                self._notif_deadlines[nid] = (
                    time.monotonic() + seconds + 10.0)

    def _respond(self, nid: int, error: int, val: int = 0) -> None:
        resp = struct.pack(_RESP_FMT, nid, val, error, 0)
        with contextlib.suppress(OSError):
            fcntl.ioctl(self._fd, _IOCTL_NOTIF_SEND, bytearray(resp))

    def _id_valid(self, nid: int) -> bool:
        try:
            fcntl.ioctl(self._fd, _IOCTL_NOTIF_ID_VALID,
                        struct.pack("<Q", nid))
            return True
        except OSError:
            return False

    def _handle_one(self, nid: int, pid: int, nr: int,
                    sockfd: int, addr_ptr: int, addr_len: int) -> None:
        try:
            error, val = self._decide_and_execute(
                nid, pid, nr, sockfd, addr_ptr, addr_len)
            self._deregister_notif(nid)
            self._respond(nid, error, val)
        except Exception:  # noqa: BLE001 — supervisor must always answer; deny on any internal error
            logger.debug("unix-scope: handler error", exc_info=True)
            self._deregister_notif(nid)
            self._respond(nid, -errno.EPERM)
        finally:
            self._inflight.release()

    def _decide_and_execute(self, nid, pid, nr, sockfd, addr_ptr,
                            addr_len) -> tuple[int, int]:
        if self._connect_nr is not None and nr != self._connect_nr:
            return -errno.ENOSYS, 0
        if addr_len < 2 or addr_len > 128 or addr_ptr == 0:
            return -errno.EINVAL, 0
        # Read the sockaddr from the child's memory. Read FIRST, then
        # confirm the notification is still alive (ID_VALID): if it
        # is, the memory belonged to the still-blocked caller.
        try:
            with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
                mem.seek(addr_ptr)
                addr = mem.read(addr_len)
        except (OSError, ValueError):
            return -errno.EPERM, 0
        if addr is None or len(addr) < 2 or not self._id_valid(nid):
            return -errno.EPERM, 0
        family = struct.unpack_from("=H", addr, 0)[0]

        # Duplicate the child's socket. pidfd_open pins the process
        # (via the task pidfd or tgid resolution for non-leader
        # threads — see _pidfd_open_task); ID_VALID after it proves we
        # pinned the RIGHT one (the caller is still blocked in the
        # syscall, so its ids can't have been recycled before the
        # open).
        try:
            pidfd = _pidfd_open_task(pid)
        except OSError as e:
            return -(e.errno or errno.EPERM), 0
        try:
            if not self._id_valid(nid):
                return -errno.EPERM, 0
            try:
                dupfd = _pidfd_getfd(pidfd, sockfd)
            except OSError as e:
                if e.errno in (errno.EBADF, errno.ENOTSOCK):
                    return -e.errno, 0
                return -errno.EPERM, 0
        finally:
            os.close(pidfd)

        try:
            if family != socket.AF_UNIX:
                return self._connect_inet_policied(dupfd, addr, family,
                                                   pid, nid=nid)
            path = addr[2:addr_len]
            nul = path.find(b"\x00")
            if len(path) == 0:
                # Unnamed — kernel returns EINVAL; execute as read.
                return self._connect_raw(dupfd, addr, nid=nid)
            if nul == 0:
                # Abstract — netns-scoped, so only safe when THIS run
                # gave the child its own netns. On shared-netns runs
                # the name resolves in the HOST's abstract namespace
                # (Landlock's ABI-6 abstract scope is task-scoped and
                # never evaluates for a supervisor-executed connect).
                if self._netns_isolated:
                    return self._connect_raw(dupfd, addr, nid=nid)
                logger.warning(
                    "unix-scope[%s]: denied abstract AF_UNIX connect "
                    "%r from pid %d — the child shares the host "
                    "network namespace, so the name resolves in the "
                    "HOST's abstract namespace", self._label,
                    path[1:65], pid)
                return -errno.EPERM, 0
            if nul > 0:
                path = path[:nul]
            if not path.startswith(b"/"):
                logger.warning(
                    "unix-scope[%s]: denied relative AF_UNIX connect "
                    "path %r from pid %d", self._label,
                    path[:64], pid)
                return -errno.EPERM, 0
            return self._connect_pathname(dupfd, pid, path, nid=nid)
        finally:
            os.close(dupfd)

    def _connect_inet_policied(self, dupfd: int, addr: bytes,
                               family: int, pid: int,
                               nid: int | None = None) -> tuple[int, int]:
        """Re-apply the run's declared TCP policy before executing.

        Landlock CONNECT_TCP rules live in the CHILD's task domain;
        a connect executed by this (unconfined) supervisor never
        evaluates them. When the run declared ``allowed_tcp_ports``,
        enforce the same policy here: stream connects to any other
        port get EACCES — the errno Landlock itself uses.
        """
        if (self._allowed_tcp_ports is not None
                and family in (socket.AF_INET, socket.AF_INET6)):
            if len(addr) < 4:
                return -errno.EINVAL, 0
            # SO_TYPE lookup failure counts as stream (fail closed).
            sotype = _getsockopt_int(dupfd, socket.SOL_SOCKET,
                                     socket.SO_TYPE)
            if sotype is None or sotype == socket.SOCK_STREAM:
                port = struct.unpack_from("!H", addr, 2)[0]
                if port not in self._allowed_tcp_ports:
                    logger.warning(
                        "unix-scope[%s]: denied TCP connect to port %d "
                        "from pid %d — outside the run's "
                        "allowed_tcp_ports %s", self._label, port, pid,
                        sorted(self._allowed_tcp_ports))
                    return -errno.EACCES, 0
        return self._connect_raw(dupfd, addr, nid=nid)

    def _connect_raw(self, dupfd: int, addr: bytes,
                     nid: int | None = None) -> tuple[int, int]:
        """Execute connect(2) with the address bytes WE read — immune
        to the child rewriting its buffer afterwards.

        Executed nonblocking with a bounded completion wait so a
        hostile child cannot park a supervisor worker (and its dup of
        the child's socket) forever on a never-completing target. The
        O_NONBLOCK bit is set/restored on the SHARED open file
        description, so a child socket that was already nonblocking
        keeps exact kernel semantics (EINPROGRESS/EAGAIN pass
        through); a blocking child socket waits here — the child
        itself stays blocked in the notified syscall — up to
        ``_CONNECT_DEADLINE_S`` and then sees ETIMEDOUT.
        """
        libc = _get_libc()
        try:
            fl = fcntl.fcntl(dupfd, fcntl.F_GETFL)
        except OSError:
            return -errno.EPERM, 0
        child_nonblocking = bool(fl & os.O_NONBLOCK)
        if not child_nonblocking:
            try:
                fcntl.fcntl(dupfd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            except OSError:
                return -errno.EPERM, 0
        try:
            # Re-assert O_NONBLOCK IMMEDIATELY before the connect: the
            # flag lives on the shared open file description, so a
            # sibling child thread can clear it at any point — this
            # narrows the window to a few instructions but CANNOT
            # close it (kernel fact, no private status flags exist for
            # a dup of the same OFD). A child that wins the race parks
            # this worker in a blocking connect; the per-notification
            # watchdog in serve_forever then answers the child's
            # syscall with ETIMEDOUT at deadline, so the run is never
            # held hostage — see _notif_deadlines for the bounded
            # worker-leak accounting.
            if not child_nonblocking:
                try:
                    fcntl.fcntl(dupfd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                except OSError:
                    return -errno.EPERM, 0
            ctypes.set_errno(0)
            rc = libc.connect(dupfd, addr, len(addr))
            err = ctypes.get_errno() if rc < 0 else 0
            if rc == 0:
                return 0, 0
            if child_nonblocking:
                return -(err or errno.EPERM), 0
            if err == errno.EAGAIN:
                # AF_UNIX stream to a full backlog. Blocking semantics
                # would wait on the listener's (i.e. the attacker's)
                # schedule — exactly the worker-parking DoS. Refuse.
                return -errno.EAGAIN, 0
            if err != errno.EINPROGRESS:
                return -(err or errno.EPERM), 0
            # INET stream handshake in flight: wait, bounded. This is
            # the one legitimate long wait — tell the watchdog.
            if nid is not None:
                self._extend_notif(nid, _CONNECT_DEADLINE_S)
            import select
            poller = select.poll()
            try:
                poller.register(dupfd, select.POLLOUT)
            except OSError:
                return -errno.EPERM, 0
            deadline = time.monotonic() + _CONNECT_DEADLINE_S
            while not self._closed.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return -errno.ETIMEDOUT, 0
                try:
                    events = poller.poll(min(500.0,
                                             remaining * 1000.0))
                except OSError:
                    return -errno.EPERM, 0
                if events:
                    so_error = _getsockopt_int(
                        dupfd, socket.SOL_SOCKET, socket.SO_ERROR)
                    if so_error:
                        return -so_error, 0
                    return 0, 0
            # Supervisor shut down mid-connect: fail the call.
            return -errno.ECONNABORTED, 0
        finally:
            if not child_nonblocking:
                with contextlib.suppress(OSError):
                    fcntl.fcntl(dupfd, fcntl.F_SETFL, fl)

    def _connect_pathname(self, dupfd: int, pid: int,
                          path: bytes,
                          nid: int | None = None) -> tuple[int, int]:
        # Resolve inside the CHILD's mount view, refusing symlinks and
        # magic links wholesale. The O_PATH fd pins the final inode.
        try:
            rootfd = os.open(f"/proc/{pid}/root",
                             os.O_PATH | os.O_CLOEXEC)
        except OSError:
            return -errno.EPERM, 0
        target_fd = None
        try:
            try:
                target_fd = _openat2(
                    rootfd, path.lstrip(b"/"),
                    os.O_PATH | os.O_CLOEXEC,
                    _RESOLVE_IN_ROOT | _RESOLVE_NO_SYMLINKS
                    | _RESOLVE_NO_MAGICLINKS,
                )
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.EXDEV):
                    logger.warning(
                        "unix-scope[%s]: denied symlinked AF_UNIX "
                        "connect path %r from pid %d", self._label,
                        path[:96].decode("utf-8", "replace"), pid)
                    return -errno.EPERM, 0
                return -(e.errno or errno.EPERM), 0
            st = os.fstat(target_fd)
            if not stat_mod.S_ISSOCK(st.st_mode):
                return -errno.ECONNREFUSED, 0
            if not self._target_allowed(rootfd, st):
                logger.warning(
                    "unix-scope[%s]: denied AF_UNIX connect to %r from "
                    "pid %d — target is outside the sandbox's private "
                    "tmpfs and not an allowlisted instance socket",
                    self._label, path[:96].decode("utf-8", "replace"),
                    pid)
                return -errno.EPERM, 0
            # Connect through OUR pinned O_PATH fd — the inode the
            # policy just validated, regardless of later path games.
            proxied = f"/proc/self/fd/{target_fd}".encode()
            addr = struct.pack("=H", socket.AF_UNIX) + proxied + b"\x00"
            return self._connect_raw(dupfd, addr, nid=nid)
        finally:
            if target_fd is not None:
                os.close(target_fd)
            os.close(rootfd)

    def _target_allowed(self, rootfd: int, st) -> bool:
        if (st.st_dev, st.st_ino) in self._allowed_inodes:
            return True
        # Private tmpfs devices of the CHILD's mount view. On the
        # mount-ns path /tmp, /run and /dev/shm are per-sandbox tmpfs
        # by construction (setup_mount_ns steps 5/7) — anything the
        # child can reach there, it (or its descendants) created.
        for sub in (b"tmp", b"run", b"dev/shm"):
            try:
                dfd = _openat2(rootfd, sub, os.O_PATH | os.O_CLOEXEC,
                               _RESOLVE_IN_ROOT | _RESOLVE_NO_SYMLINKS)
            except OSError:
                continue
            try:
                if os.fstat(dfd).st_dev == st.st_dev:
                    return True
            finally:
                os.close(dfd)
        return False

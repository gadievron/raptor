"""Private-network-namespace supervisor for the Joern server.

Stdlib-only, run as a standalone script by ``JoernServer.start()``::

    python3 netns_forwarder.py --socket <path> --port <port> -- <joern cmd...>

It unshares into a fresh user+network namespace (identity uid/gid
mapping, loopback brought up), binds a unix-domain listener at
``--socket`` (owner-only permissions, created BEFORE the server can
accept any traffic), spawns the wrapped command inside the namespace,
and splices byte streams between unix-socket clients and
``127.0.0.1:<port>`` inside the namespace.

Why: ``joern --server`` only accepts its HTTP Basic credential via
``--server-auth-password`` on argv, which any local user can read in
``/proc/<pid>/cmdline``. With the TCP listener confined to a private
network namespace, that credential stops being a load-bearing secret:
other local users can neither reach the port (netns) nor open the
socket (0700 directory). Same-uid processes retain access — that is
the intended trust boundary (same as the CPG files and the lifecycle
state file).

The supervisor's lifetime tracks the wrapped command: when the child
exits, the supervisor exits with the child's status, so the parent's
``Popen.poll()`` liveness checks keep working. SIGTERM/SIGINT are
forwarded to the child; the parent's process-group SIGKILL escalation
covers a child that ignores them. The handlers install before any
externally observable boot milestone (the group-tier ready report,
the socket appearing on disk), and a terminal signal that arrives
while the child does not exist yet is honoured — prompt teardown
instead of the spawn, or delivery right after it — never dropped.

``--self-probe`` exercises the full mechanism (unshare, uid map,
loopback up, TCP round-trip, unix-socket bind) and exits 0/1 — the
parent uses it for tier selection, mirroring the sandbox's
probe-then-degrade convention.

``--pidns`` additionally includes ``CLONE_NEWPID`` in the same single
unshare call and interposes an ns-init waiter (PID 1 of the fresh pid
namespace) between the forwarder and the wrapped command, so killing
the forwarder collapses the whole namespace via the waiter's
PDEATHSIG and killing the waiter collapses it directly — one verified
kill replaces process-group enumeration. ``--self-probe-pidns``
probes that stronger mechanism the same 0/1 way. A refused ``--pidns``
fails closed with a distinct exit code (never a silent downgrade);
the parent relaunches once without the flag and stamps the run
Degraded. The tier the forwarder ACTUALLY established — never the
requested flag — is reported on ``--ready-fd``.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import fcntl
import math
import os
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from types import FrameType

_CLONE_NEWUSER = getattr(os, "CLONE_NEWUSER", 0x10000000)
_CLONE_NEWNET = getattr(os, "CLONE_NEWNET", 0x40000000)
_CLONE_NEWPID = getattr(os, "CLONE_NEWPID", 0x20000000)

# <sys/prctl.h>
_PR_SET_PDEATHSIG = 1

# libc handle loaded at import time (before any fork) so the ns-init
# waiter never dlopens inside a bare-forked child.
_LIBC = ctypes.CDLL(None, use_errno=True)

# Distinct exit codes for the fail-closed --pidns contract (kept out
# of the 128+signum band and below it, so they cannot collide with
# the waiter's signal mirroring). The parent treats either as "the
# requested pid-ns tier was refused at runtime": it invalidates its
# cached probe verdict and relaunches once without --pidns, stamped
# Degraded. Never proceed on a silently weaker tier than the flag
# demanded.
EXIT_PIDNS_UNSHARE_REFUSED = 97
EXIT_PIDNS_WAITER_UNARMED = 96
#: Waiter-internal: PR_SET_PDEATHSIG failed — the pidns tier would be
#: established with its safety net unarmed, silently re-creating the
#: forwarder-dead-JVM-alive orphan class the tier exists to eliminate.
#: Fail closed (never warn-and-continue).
_WAITER_EXIT_PRCTL_FAILED = 96
#: Waiter-internal: the forwarder died in the fork→prctl window, so
#: PDEATHSIG missed it. getppid() cannot detect this — a pid-ns init
#: sees 0 whether its parent is alive or dead (pid_namespaces(7));
#: the parent-liveness pipe probe is the honest check.
_WAITER_EXIT_PARENT_DIED = 95
#: How long the forwarder waits for the waiter's arm byte before
#: declaring the boot failed. Generous: arming is a handful of
#: syscalls, but a loaded host should never convert slow into broken.
_ARM_TIMEOUT_S = 30.0

# <linux/sockios.h> / <net/if.h>
_SIOCGIFFLAGS = 0x8913
_SIOCSIFFLAGS = 0x8914
_IFF_UP = 0x1
# struct ifreq: 16-byte name + 24-byte union (40 bytes on 64-bit).
_IFREQ_FMT = "16sH22s"

_CHUNK = 65536
_BACKLOG = 32
_UPSTREAM_CONNECT_TIMEOUT_S = 10.0


def enter_private_netns(include_pid: bool = False) -> None:
    """Unshare into a fresh user+network namespace, identity-mapped.

    The identity uid/gid mapping (uid -> uid, gid -> gid) keeps
    ``getuid()``, passwd lookups, and file ownership exactly as on the
    host — the JVM never notices the namespace. Writing our own single-
    entry map needs no ``newuidmap`` helper and no extra privileges.

    ``include_pid`` adds ``CLONE_NEWPID`` to the SAME single unshare
    call — never a second staged ``unshare(CLONE_NEWPID)``, which some
    restricted hosts deny even where the combined call succeeds (the
    staged-refusal class core/sandbox/probes.py probes for).
    ``unshare(CLONE_NEWPID)`` does not move the caller — only children
    forked afterwards join the new pid namespace — so the
    ``/proc/self/*`` map writes below still address the host procfs
    entry unchanged.
    """
    if not hasattr(os, "unshare"):
        raise RuntimeError("os.unshare unavailable on this Python")
    uid, gid = os.getuid(), os.getgid()
    flags = _CLONE_NEWUSER | _CLONE_NEWNET
    if include_pid:
        flags |= _CLONE_NEWPID
    os.unshare(flags)
    # setgroups must be denied before an unprivileged gid_map write.
    _write_proc("/proc/self/setgroups", "deny")
    _write_proc("/proc/self/gid_map", f"{gid} {gid} 1")
    _write_proc("/proc/self/uid_map", f"{uid} {uid} 1")


def _write_proc(path: str, value: str) -> None:
    with open(path, "w", encoding="ascii") as f:
        f.write(value)


def bring_loopback_up() -> None:
    """Set IFF_UP on ``lo`` — a fresh netns boots with loopback down.

    Plain ioctls on an AF_INET socket: no ``ip`` binary dependency.
    Requires CAP_NET_ADMIN over the netns, which the creator of the
    user namespace holds.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        req = struct.pack(_IFREQ_FMT, b"lo", 0, b"")
        got = fcntl.ioctl(s.fileno(), _SIOCGIFFLAGS, req)
        flags = struct.unpack(_IFREQ_FMT, got)[1]
        fcntl.ioctl(
            s.fileno(),
            _SIOCSIFFLAGS,
            struct.pack(_IFREQ_FMT, b"lo", flags | _IFF_UP, b""),
        )


def create_listener(socket_path: str) -> socket.socket:
    """Bind and listen on a unix socket with owner-only permissions.

    Refuses a group/world-accessible parent directory — directory
    permissions are the access-control layer for pathname sockets, so
    a lax parent would let other local users connect. The socket inode
    itself is created 0700 via umask (no window where it is looser)
    and re-asserted with chmod.
    """
    parent = os.path.dirname(socket_path) or "."
    st = os.stat(parent)
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"socket parent {parent!r} is not a directory")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise RuntimeError(
            f"socket parent {parent!r} is group/world accessible "
            f"(mode {stat.S_IMODE(st.st_mode):04o}, need 0700)"
        )
    if st.st_uid != os.getuid():
        raise RuntimeError(f"socket parent {parent!r} not owned by us")
    with contextlib.suppress(FileNotFoundError):
        os.unlink(socket_path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o077)
    try:
        listener.bind(socket_path)
    except BaseException:
        listener.close()
        raise
    finally:
        os.umask(old_umask)
    os.chmod(socket_path, 0o700)
    listener.listen(_BACKLOG)
    return listener


def _pump(src: socket.socket, dst: socket.socket) -> None:
    """Copy bytes src -> dst until EOF, then propagate the half-close.

    Shutting down only the write side of ``dst`` (not closing it) lets
    the opposite pump keep draining the response — required for HTTP
    clients that half-close after sending a request, and for chunked /
    keep-alive responses that outlive the request body.
    """
    try:
        while True:
            data = src.recv(_CHUNK)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    with contextlib.suppress(OSError):
        dst.shutdown(socket.SHUT_WR)


#: The two terminal signals ``main()`` installs Python-level handlers
#: for. Worker threads must BLOCK exactly these: a process-directed
#: signal is delivered to any one thread whose mask allows it, and a
#: handled signal consumed by a worker only trips CPython's C-level
#: flag — the Python handler runs on the main thread, which sits in an
#: uninterrupted ``child.wait()`` (waitpid never sees EINTR when the
#: signal landed elsewhere), so the handler is deferred until the child
#: dies on its own: the stop request is silently absorbed. Blocking
#: them in every worker forces kernel delivery onto the main thread,
#: whose waitpid then returns EINTR and runs the handler promptly.
#: Only these two: unhandled terminal signals (HUP, QUIT) take the
#: whole-process default disposition from any thread, so masking them
#: would change nothing — and masking more than we handle would turn a
#: future handler bug into a silent no-delivery hang.
_HANDLED_TERMINAL_SIGNALS = (signal.SIGTERM, signal.SIGINT)


def _start_signal_shielded(t: threading.Thread) -> None:
    """Start ``t`` with the handled terminal signals blocked in it.

    The mask is applied on the CREATING thread and restored right
    after ``start()`` — a new thread inherits its creator's mask
    atomically at creation, so there is no window where the worker
    runs unmasked, and the creator's own delivery eligibility is
    unchanged outside this call.
    """
    old_mask = signal.pthread_sigmask(
        signal.SIG_BLOCK, _HANDLED_TERMINAL_SIGNALS,
    )
    try:
        t.start()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


class Forwarder:
    """Splices unix-socket client connections to a TCP upstream.

    Thread-per-direction: each accepted connection gets an upstream
    dial plus two pump threads (client->upstream, upstream->client),
    so concurrent clients and full-duplex streams both work. ``stop()``
    closes the listener, unlinks the socket path, and closes any
    in-flight connections.
    """

    def __init__(
        self,
        listener: socket.socket,
        upstream: tuple[str, int],
        *,
        socket_path: str | None = None,
    ) -> None:
        self._listener = listener
        self._upstream = upstream
        self._socket_path = socket_path
        self._stopping = threading.Event()
        self._active: set[socket.socket] = set()
        self._active_lock = threading.Lock()
        self._accept_thread: threading.Thread | None = None
        # Client-activity clock for the orphan watchdog: refreshed at
        # every connection open/close, and "an open connection exists"
        # itself reads as active (a long joern query holds one for its
        # whole duration).
        self._last_activity = time.monotonic()

    def idle_seconds(self) -> float | None:
        """Seconds since the last client activity, or ``None`` while
        any client connection is open (open == active)."""
        with self._active_lock:
            if self._active:
                return None
            return time.monotonic() - self._last_activity

    def start(self) -> None:
        t = threading.Thread(
            target=self._accept_loop, name="joern-uds-accept", daemon=True,
        )
        _start_signal_shielded(t)
        self._accept_thread = t

    def stop(self) -> None:
        self._stopping.set()
        # Wake a blocked accept(): on Linux closing the fd does not
        # interrupt an accept() already parked in the kernel. A dummy
        # connection makes it return; the loop then observes
        # ``_stopping`` and exits promptly instead of the join below
        # timing out.
        if self._socket_path is not None:
            with contextlib.suppress(OSError):
                waker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                waker.settimeout(1)
                waker.connect(self._socket_path)
                waker.close()
        with contextlib.suppress(OSError):
            self._listener.close()
        if self._socket_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(self._socket_path)
        with self._active_lock:
            live = list(self._active)
            self._active.clear()
        for sock in live:
            # shutdown (unlike close) wakes any pump thread blocked in
            # recv() on this socket.
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                sock.close()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=5)
            self._accept_thread = None

    def _track(self, sock: socket.socket) -> None:
        # Registration and stop()'s sweep share one lock, and stop()
        # sets ``_stopping`` before it sweeps: a socket registering
        # here either lands before the sweep (and gets shut down) or
        # observes ``_stopping`` and refuses. Without the check, a
        # connection accepted just before stop() but tracked just
        # after its sweep joins a set nobody sweeps again — the peer
        # then hangs until its own timeout instead of seeing EOF.
        with self._active_lock:
            self._last_activity = time.monotonic()
            if self._stopping.is_set():
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(OSError):
                    sock.close()
                raise OSError(errno.EPIPE, "forwarder is stopping")
            self._active.add(sock)

    def _untrack(self, sock: socket.socket) -> None:
        with self._active_lock:
            self._last_activity = time.monotonic()
            self._active.discard(sock)

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return  # listener closed (stop) or unrecoverable
            if self._stopping.is_set():
                with contextlib.suppress(OSError):
                    conn.close()
                return
            _start_signal_shielded(threading.Thread(
                target=self._handle, args=(conn,), daemon=True,
            ))

    def _handle(self, conn: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            # Inside the try: _track deliberately raises when a racing
            # stop() already swept the active set (the socket is closed
            # and refused). Pre-fix that raise escaped this thread as
            # an unhandled exception — the refusal is a clean outcome,
            # the same "racing stop() closed a socket under us" class
            # the except below already documents.
            self._track(conn)
            upstream = socket.create_connection(
                self._upstream, timeout=_UPSTREAM_CONNECT_TIMEOUT_S,
            )
            self._track(upstream)
            upstream.settimeout(None)
            conn.settimeout(None)
            back = threading.Thread(
                target=_pump, args=(upstream, conn), daemon=True,
            )
            _start_signal_shielded(back)
            _pump(conn, upstream)
            back.join()
        except OSError:
            # Upstream not accepting yet (e.g. the JVM still booting)
            # or a racing stop() closed a socket under us: drop the
            # client; it retries on its own poll cadence.
            pass
        finally:
            for sock in (conn, upstream):
                if sock is None:
                    continue
                self._untrack(sock)
                with contextlib.suppress(OSError):
                    sock.close()


# ── pid-namespace supervision (--pidns) ───────────────────────────────────
#
# Topology (--pidns):
#
#   RAPTOR
#    └─ P: this script's original process. Performs the single
#        combined unshare(USER|NET|PID) and immediately forks; from
#        then on it is a THIN supervisor — wait, forward signals,
#        mirror — because a process that has unshared CLONE_NEWPID
#        can NEVER create threads again (a new thread would share its
#        thread group across pid namespaces; the kernel refuses), so
#        everything threaded must live below the fork.
#        └─ B: ns-init waiter, PID 1 of the fresh pid namespace — a
#            local stdlib mirror of the sandbox's canonical waiter
#            (core/sandbox/_spawn.py — _pid1_split_for_waiter; keep
#            the two in sight of each other). PDEATHSIG keyed to P.
#            └─ C: PID 2 — the working forwarder: unix-socket
#                listener, splice threads, orphan watchdog, and the
#                wrapped command as a plain Popen child (PID 3).
#
# Killing P collapses everything (PDEATHSIG SIGKILLs B; init death
# makes the kernel SIGKILL every namespace member and blocks B's exit
# until all of them are reaped). Killing B collapses the namespace
# directly. P's only exit paths are mirroring B's exit — that
# invariant is what makes "wait(P) returned ⇒ namespace empty" sound.


def _ns_init_split(live_r: int, arm_w: int) -> None:
    """(B) Fork so the working forwarder becomes PID 2 of the pid-ns;
    PID 1 (this process) stays as a minimal in-process init.

    A deliberately LOCAL, stdlib-only mirror of the sandbox's
    canonical waiter (``core/sandbox/_spawn.py`` —
    ``_pid1_split_for_waiter``; keep the two in sight of each other):
    the forwarder is a standalone long-lived script whose behavior
    must pin at launch, so it imports nothing from the repo. The
    shared contract battery in the tests is what keeps the twins from
    drifting apart.

    Why a waiter at all: a working process running as pid-ns PID 1
    has kill(2)-delivered signals silently filtered by the kernel —
    no graceful SIGTERM. So PID 1 stays behind as a minimal init that
    reaps orphans, forwards SIGTERM/SIGINT/SIGHUP/SIGQUIT to the
    child, and mirrors a signalled child as ``128+signum``.

    Contract, in order:

    1. ``PR_SET_PDEATHSIG(SIGKILL)`` keyed to P — set post-fork,
       post-unshare, so nothing later clears it. Failure fails CLOSED
       (``_exit`` with a distinct code before the arm byte, so P
       refuses the boot): a pidns tier without an armed PDEATHSIG
       would re-create the supervisor-dead-JVM-alive orphan class
       while every consumer believes it impossible.
    2. Parent-liveness probe: poll ``live_r`` (a pipe whose SOLE
       write end lives in P) for POLLHUP. HUP means P died before the
       prctl armed — exit. ``getppid()`` is vacuous here: a pid-ns
       init reads 0 whether its parent is alive or dead
       (pid_namespaces(7)).
    3. Write the arm byte on ``arm_w`` — P does not proceed until
       supervision is actually armed.
    4. Raw ``os.fork()`` — never ``subprocess.Popen``, whose
       machinery has no place inside a bare-forked init. This
       function RETURNS in the child (C, PID 2), which carries on
       with the working-forwarder body of ``main()``; the PID 1 side
       never returns (``os._exit``).
    5. Reap until C's status arrives (orphans reaped and discarded),
       then ``_exit`` mirroring it — exit status for a normal exit,
       ``128+signum`` for a signalled child. If this init dies
       instead, the kernel SIGKILLs every namespace member and blocks
       this process's exit until all of them are reaped — init death
       IS namespace collapse.
    """
    if _LIBC.prctl(_PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0) != 0:
        os.write(2, b"netns_forwarder ns-init: PR_SET_PDEATHSIG failed; "
                    b"refusing to run the pidns tier unarmed\n")
        os._exit(_WAITER_EXIT_PRCTL_FAILED)
    poller = select.poll()
    poller.register(live_r, select.POLLIN)
    for _fd, events in poller.poll(0):
        if events & (select.POLLHUP | select.POLLERR):
            # P died in the fork→prctl window; PDEATHSIG missed it.
            # Collapse now instead of orphaning a tree.
            os._exit(_WAITER_EXIT_PARENT_DIED)
    try:
        os.write(arm_w, b"A")
        os.close(arm_w)
    except OSError:
        os._exit(_WAITER_EXIT_PARENT_DIED)

    try:
        child = os.fork()
    except OSError:
        os.write(2, b"netns_forwarder ns-init: fork of the working "
                    b"forwarder failed\n")
        os._exit(127)
    if child == 0:
        # C (PID 2): the liveness pipe belongs to the init's window
        # probe; the working forwarder holds no read end of it.
        with contextlib.suppress(OSError):
            os.close(live_r)
        return  # working-forwarder path continues in main()

    def _forward(signum: int, _frame: FrameType | None,
                 _child: int = child) -> None:
        with contextlib.suppress(OSError):
            os.kill(_child, signum)

    for _sig in (signal.SIGTERM, signal.SIGINT,
                 signal.SIGHUP, signal.SIGQUIT):
        with contextlib.suppress(OSError, ValueError):
            signal.signal(_sig, _forward)

    while True:
        try:
            pid_, status = os.wait()
        except InterruptedError:
            continue
        except ChildProcessError:
            os._exit(0)
        if pid_ != child:
            continue  # reap orphans; only C's status mirrors
        if os.WIFEXITED(status):
            os._exit(os.WEXITSTATUS(status))
        if os.WIFSIGNALED(status):
            os._exit(128 + os.WTERMSIG(status))
        # stopped/continued — keep waiting


def _supervise_ns_init(
    ns_init_pid: int,
    arm_r: int,
    raptor_gone_w: int,
    ready_fd: int | None,
    *,
    poll_s: float = 1.0,
    arm_timeout_s: float = _ARM_TIMEOUT_S,
) -> int:
    """(P) Supervise the ns-init: arm-gate, forward, watch, mirror.

    Runs in the process that performed the ``CLONE_NEWPID`` unshare,
    which can never create threads again — everything here is a
    single-threaded poll loop. Never returns until the ns-init is
    dead; its return value is ``main()``'s exit code.

    Duties:

    * Wait for B's arm byte; a timeout or an unarmed death fails the
      boot CLOSED with :data:`EXIT_PIDNS_WAITER_UNARMED` (B is
      SIGKILLed and reaped first — our own unreaped child, so the
      pid cannot have been recycled).
    * Report the ACHIEVED tier on ``ready_fd`` only after the arm
      byte — never before supervision is real.
    * Forward SIGTERM/SIGINT to B (which forwards on to C, which
      forwards to the wrapped command).
    * Watch ``getppid()``; when RAPTOR dies, write one byte on
      ``raptor_gone_w`` so C's orphan watchdog (whose own
      ``getppid()`` is vacuous — its parent is the in-namespace
      init) learns about it.
    * Reap B and mirror its status (``128+signum`` for a signalled
      death). B's exit is namespace-empty proof: the kernel blocks a
      pid-ns init's exit until every member is reaped.
    """
    reaped = False

    def _forward(signum: int, _frame: FrameType | None) -> None:
        # Same narrow status-then-kill race as Popen.send_signal;
        # while unreaped the pid is at worst a zombie, so this cannot
        # signal a recycled pid.
        if not reaped:
            with contextlib.suppress(OSError):
                os.kill(ns_init_pid, signum)

    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, _forward)

    armed = False
    poller = select.poll()
    poller.register(arm_r, select.POLLIN)
    deadline = time.monotonic() + arm_timeout_s
    try:
        while True:
            remaining_ms = (deadline - time.monotonic()) * 1000
            if remaining_ms <= 0:
                break
            if poller.poll(remaining_ms):
                # One byte = armed; EOF = the waiter died unarmed.
                armed = os.read(arm_r, 1) != b""
                break
    finally:
        os.close(arm_r)
    if not armed:
        with contextlib.suppress(OSError):
            os.kill(ns_init_pid, signal.SIGKILL)
        with contextlib.suppress(OSError):
            os.waitpid(ns_init_pid, 0)
        reaped = True
        print(
            "netns_forwarder: ns-init waiter never armed PDEATHSIG; "
            "refusing to boot the pidns tier without its safety net",
            file=sys.stderr,
        )
        return EXIT_PIDNS_WAITER_UNARMED
    _report_tier(ready_fd, "pidns")

    raptor = os.getppid()
    raptor_reported = False
    while True:
        try:
            pid_, status = os.waitpid(ns_init_pid, os.WNOHANG)
        except ChildProcessError:
            # Only external interference can reap our child out from
            # under us; report an unknowable-but-dead status.
            reaped = True
            return 255
        if pid_ == ns_init_pid:
            reaped = True
            if os.WIFSIGNALED(status):
                return 128 + os.WTERMSIG(status)
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            continue  # stopped/continued — keep waiting
        if not raptor_reported and os.getppid() != raptor:
            raptor_reported = True
            with contextlib.suppress(OSError):
                os.write(raptor_gone_w, b"G")
            with contextlib.suppress(OSError):
                os.close(raptor_gone_w)
        time.sleep(poll_s)


def _report_tier(ready_fd: int | None, tier: str) -> None:
    """Report the ACHIEVED supervision tier to the parent.

    The parent records only what this reports — never the flag it
    passed. A misstamped ``pidns`` on a group boot would route later
    kills down the short path with the safety net absent (a leaked
    JVM presented as impossible), so the flag is never the source of
    the stamp. A missing/garbled report reads as the weaker tier on
    the parent side (safe direction).
    """
    if ready_fd is None:
        return
    with contextlib.suppress(OSError):
        os.write(ready_fd, f"supervision_tier={tier}\n".encode("ascii"))
    with contextlib.suppress(OSError):
        os.close(ready_fd)


#: Orphan-watchdog cadence / SIGTERM→SIGKILL escalation grace.
_PARENT_POLL_S = 5.0
_PARENT_KILL_GRACE_S = 10.0
#: DEFAULT for how long an ORPHANED server may sit with no client
#: activity before the watchdog reaps the pair. Parent death alone is
#: NORMAL here — the lifecycle layer keeps warm servers alive across
#: RAPTOR runs precisely so later acquires skip the 30-120s JVM boot —
#: so this mirrors the acquire-side recycle horizon for unreferenced
#: servers (packages/joern/lifecycle.py ``_STALE_THRESHOLD_S``; keep
#: in sync): a warm server the next run would still reuse survives,
#: one nothing touched for the same horizon is reaped instead of
#: squatting on multi-GB of RAM forever. Spawners whose server is NOT
#: lifecycle-recorded (no state file, so no later run can ever
#: re-acquire it) pass a much shorter horizon via ``--orphan-idle-ttl``
#: — for them the full default is pure squatting time.
_ORPHAN_IDLE_TTL_S = 3600 * 8


def _start_orphan_watchdog(
    get_child: Callable[[], subprocess.Popen | None],
    forwarder: Forwarder,
    *,
    poll_s: float = _PARENT_POLL_S,
    grace_s: float = _PARENT_KILL_GRACE_S,
    idle_ttl_s: float = _ORPHAN_IDLE_TTL_S,
    parent_gone_fd: int | None = None,
) -> threading.Thread:
    """Reap the supervised group once it is orphaned AND idle.

    No spawn-side parent-death signal can work for this pair:
    PR_SET_PDEATHSIG is cleared by :func:`enter_private_netns`'s
    ``unshare(CLONE_NEWUSER)`` and would bind to the spawning THREAD
    besides — and parent death is not even sufficient grounds to die,
    because the lifecycle layer deliberately hands warm servers to
    later runs. But with the parent gone AND no client activity for
    the lifecycle's own staleness horizon, nobody is coming back: the
    pair used to live forever (each stranded JVM ~2 GB RSS — the
    boot-time workspace sweep reclaims a dead server's *directories*,
    but nothing reaped its *processes*).

    A daemon thread polls ``os.getppid()`` (robust under subreapers:
    any change means the recorded parent is gone), then waits out the
    idle horizon — any client connection resets it, and an OPEN
    connection blocks it outright. To reap, it SIGTERMs the wrapped
    child — the JVM exits, ``main()``'s ``wait`` unblocks, and the
    normal socket/dir cleanup runs — escalating to SIGKILL of the
    forwarder's own process group (we lead it, so the JVM and any
    launcher-shell stragglers go too) if the child ignores the grace.

    Pidns tier: this thread runs in the in-namespace working
    forwarder, whose ``getppid()`` is vacuous — its parent is the
    namespace's own init, not RAPTOR. ``parent_gone_fd`` replaces the
    poll: the host-side supervisor (whose ``getppid()`` does watch
    RAPTOR) writes a byte there when RAPTOR dies, and its own death
    reads as HUP — either way this fd turning readable means the
    parent is gone. The idle horizon and the escalation are
    unchanged. The escalation's ``killpg(0, SIGKILL)`` DOES cross
    the pid-namespace boundary: namespaces virtualise pid numbers
    (an ancestor-namespace process cannot be signalled *by pid*
    from here), but a process group is one kernel object spanning
    namespaces, so signal-by-group reaches every member wherever it
    lives — including the host-side supervisor, which shares this
    group and dies with it rather than mirroring. Acceptable by
    construction: this branch fires only after the supervisor has
    already reported the real parent gone, total teardown is the
    goal, and the blast radius ends at the group — which the
    supervisor leads in its own session under a server boot.
    """
    parent = os.getppid()

    def _watch() -> None:
        if parent_gone_fd is not None:
            poller = select.poll()
            poller.register(parent_gone_fd, select.POLLIN)
            while not poller.poll(int(poll_s * 1000)):
                pass
        else:
            while os.getppid() == parent:
                time.sleep(poll_s)
        while True:
            idle = forwarder.idle_seconds()
            if idle is not None and idle >= idle_ttl_s:
                break
            time.sleep(poll_s)
        with contextlib.suppress(OSError):
            os.write(
                2,
                b"netns_forwarder: parent gone and no client activity "
                b"within the idle horizon; reaping the supervised "
                b"group\n",
            )
        child = get_child()
        if child is not None:
            with contextlib.suppress(OSError):
                child.terminate()
            deadline = time.monotonic() + grace_s
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    # main()'s wait() unblocks; normal cleanup runs.
                    return
                time.sleep(0.2)
        with contextlib.suppress(OSError):
            os.killpg(0, signal.SIGKILL)
        os._exit(1)  # unreachable when the killpg landed

    t = threading.Thread(
        target=_watch, name="orphan-watchdog", daemon=True,
    )
    _start_signal_shielded(t)
    return t


_UID_MAP_PATH = "/proc/self/uid_map"

# Operator-authored constant (no interpolated values): printed verbatim on
# the probe's stderr, which callers may quote into logs and prompts unescaped.
_UNMAPPED_EUID_HINT = (
    "self-probe hint: the euid has no entry in /proc/self/uid_map (a bare"
    " `unshare -Up` leaves it unmapped) and the kernel refuses"
    " user-namespace operations from an unmapped euid; map the uid first"
    " (e.g. unshare --map-current-user)"
)


def _euid_unmapped() -> bool:
    """True when the uid_map of the calling namespace is empty.

    An empty map only occurs inside a user namespace whose creator never
    wrote a uid mapping — the initial namespace reads ``0 0 4294967295``.
    The kernel refuses ``unshare(CLONE_NEWUSER)`` (and the map writes)
    from an unmapped euid with EPERM, so this discriminates "missing uid
    map" from "namespaces denied by host policy". Best-effort: any read
    failure returns False and the hint simply stays silent.
    """
    try:
        with open(_UID_MAP_PATH, "rb") as f:
            return f.read(1) == b""
    except OSError:
        return False


def self_probe(include_pid: bool = False) -> int:
    """Exercise the full isolation mechanism; 0 = strong tier works.

    ``include_pid`` (the ``--self-probe-pidns`` arm) additionally
    proves the pid-ns supervision mechanism end to end: the SINGLE
    combined unshare engages AND a forked child really is PID 1 of
    the new namespace AND ``PR_SET_PDEATHSIG`` arms there AND a full
    namespace member can still create threads (the in-namespace
    working forwarder is the process that runs the splice threads) —
    the exact preconditions of the ``--pidns`` boot, probed the same
    probe-then-degrade way as the netns tier.
    """
    try:
        enter_private_netns(include_pid=include_pid)
        bring_loopback_up()
        if include_pid:
            pid = os.fork()
            if pid == 0:
                ok = (
                    os.getpid() == 1
                    and _LIBC.prctl(
                        _PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0,
                    ) == 0
                )
                if ok:
                    try:
                        t = threading.Thread(target=lambda: None)
                        t.start()
                        t.join()
                    except RuntimeError:
                        ok = False
                os._exit(0 if ok else 1)
            _, status = os.waitpid(pid, 0)
            if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
                raise RuntimeError(
                    "pid-ns init check failed (child not PID 1, "
                    "PR_SET_PDEATHSIG refused, or in-namespace "
                    "thread creation refused)"
                )
        # In-namespace loopback TCP round-trip (what joern will need).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ls:
            ls.bind(("127.0.0.1", 0))
            ls.listen(1)
            port = ls.getsockname()[1]
            with socket.create_connection(("127.0.0.1", port), timeout=5):
                pass
        # Unix-socket bind under a private directory (what clients need).
        probe_dir = tempfile.mkdtemp(prefix="raptor-joern-uds-probe-")
        try:
            create_listener(os.path.join(probe_dir, "probe.sock")).close()
        finally:
            shutil.rmtree(probe_dir, ignore_errors=True)
    except Exception as e:  # noqa: BLE001 — any failure means fallback tier
        kind = "pidns" if include_pid else "netns"
        print(f"{kind} self-probe failed: {e}", file=sys.stderr)
        if isinstance(e, PermissionError) and _euid_unmapped():
            print(_UNMAPPED_EUID_HINT, file=sys.stderr)
        return 1
    return 0


def _positive_float(text: str) -> float:
    """argparse type for ``--orphan-idle-ttl``: a finite value > 0.

    0 or a negative would make the watchdog reap the pair the moment
    the parent dies mid-handoff; NaN would make the ``>=`` comparison
    always false and disable the watchdog silently. Both are
    misconfigurations worth a parse-time error, not a runtime surprise.
    """
    value = float(text)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(
            f"expected a finite value > 0, got {text!r}",
        )
    return value


#: Test-only pre-spawn gate (see :func:`_hold_prespawn_gate`): the
#: variable names a directory through which a test holds the boot open
#: in the handlers-installed/child-not-yet-spawned window. Never set on
#: real boots — the name is not on the spawn-side env allowlist
#: (``RaptorConfig.SAFE_ENV_ALLOWLIST``), so ``get_safe_env()``-spawned
#: supervisors can never see it.
_TEST_PRESPAWN_GATE_ENV = "RAPTOR_NETNS_FORWARDER_TEST_PRESPAWN_GATE"
#: Upper bound on the gate hold, in both directions: shorter and the
#: boot-window tests cannot finish their held → signal → release
#: handshake before the hold lapses (the deterministic window collapses
#: back into a timing lottery — the tests need tens of milliseconds,
#: plus xdist-load headroom); longer and a stray gate variable reaching
#: a real boot would delay the wrapped server's spawn by the full bound
#: (already a misconfiguration — see the allowlist note above — so it
#: gets a bounded delay, never a wedge).
_TEST_PRESPAWN_GATE_TIMEOUT_S = 10.0
_TEST_PRESPAWN_GATE_POLL_S = 0.05


def _hold_prespawn_gate(gate_dir: str | None) -> None:
    """Test-only seam: park the boot between handler install and spawn.

    The absorbed-signal defect lived exactly here — handlers installed,
    ``child`` still ``None`` — a window microseconds wide in a real
    boot and therefore untestable without a hold point the test
    controls. When *gate_dir* is set, write ``held`` (our pid) so the
    test knows the boot is parked, then wait for ``release`` to appear,
    bounded by :data:`_TEST_PRESPAWN_GATE_TIMEOUT_S`. Signals arriving
    during the hold take the normal recorded-pending path; the hold
    itself never touches signal state. Best-effort: if ``held`` cannot
    be written (bogus directory), skip the hold entirely rather than
    waiting on a release nobody can key off the missing marker.
    """
    if not gate_dir:
        return
    try:
        with open(os.path.join(gate_dir, "held"), "w",
                  encoding="ascii") as f:
            f.write(str(os.getpid()))
    except OSError:
        return
    release = os.path.join(gate_dir, "release")
    deadline = time.monotonic() + _TEST_PRESPAWN_GATE_TIMEOUT_S
    while time.monotonic() < deadline and not os.path.exists(release):
        time.sleep(_TEST_PRESPAWN_GATE_POLL_S)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a command in a private netns behind a unix socket",
    )
    parser.add_argument("--self-probe", action="store_true")
    parser.add_argument(
        "--self-probe-pidns", action="store_true",
        help="probe the pid-namespace supervision tier (0/1 exit)",
    )
    parser.add_argument(
        "--pidns", action="store_true",
        help="include CLONE_NEWPID in the unshare and supervise the "
             "command under an ns-init waiter; a runtime refusal fails "
             "closed with a distinct exit code (never a silent "
             "downgrade)",
    )
    parser.add_argument(
        "--ready-fd", type=int, default=None, metavar="FD",
        help="inherited fd on which to report the ACHIEVED supervision "
             "tier (supervision_tier=pidns|group)",
    )
    parser.add_argument("--socket", help="unix socket path to listen on")
    parser.add_argument("--port", type=int, help="in-namespace TCP port")
    parser.add_argument(
        "--orphan-idle-ttl", type=_positive_float,
        default=_ORPHAN_IDLE_TTL_S, metavar="SECONDS",
        help="orphaned-and-idle horizon before the watchdog reaps the "
             "supervised group (default matches the lifecycle warm-"
             "handoff staleness horizon; run-private spawners pass a "
             "short value)",
    )
    parser.add_argument("cmd", nargs=argparse.REMAINDER,
                        help="-- command to supervise inside the namespace")
    args = parser.parse_args(argv)

    if args.self_probe:
        return self_probe()
    if args.self_probe_pidns:
        return self_probe(include_pid=True)

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not args.socket or not args.port or not cmd:
        parser.error("--socket, --port, and a command are required")

    if args.pidns:
        # ONE unshare call carrying all three flags — never a staged
        # second unshare(CLONE_NEWPID), which restricted hosts can
        # refuse even where the combined call succeeds. A runtime
        # refusal after a positive probe (host policy raced us) fails
        # closed: distinct exit code, loud line, no listener and no
        # child ever created — the parent relaunches once without
        # --pidns and stamps the run Degraded.
        try:
            enter_private_netns(include_pid=True)
        except (OSError, RuntimeError) as e:
            print(
                "netns_forwarder: --pidns requested but the combined "
                f"unshare was refused at runtime: {e}",
                file=sys.stderr,
            )
            return EXIT_PIDNS_UNSHARE_REFUSED
    else:
        enter_private_netns()
    bring_loopback_up()

    parent_gone_fd: int | None = None
    if args.pidns:
        # The P/B/C split happens HERE by structural necessity: from
        # the sole thread, before Forwarder.start()/watchdog threads
        # exist — the post-unshare(CLONE_NEWPID) process (P) can never
        # create threads again, so everything threaded must move below
        # the fork — after bring_loopback_up() (the whole tree
        # inherits the netns; the JVM's 127.0.0.1 bind cannot precede
        # the loopback-up syscall), and before create_listener (only
        # C, the working forwarder, ever holds the listener fd). The
        # 0700 permission gate below survives this reorder
        # structurally: the UDS listener is the namespace's sole
        # ingress — the JVM never dials it, the forwarder connects out
        # per client — so no traffic can reach the JVM before
        # create_listener runs.
        #
        # Three pipes wire the split (all O_CLOEXEC; forks inherit
        # them, the exec'd JVM never does):
        #   live:  P's write end stays open for P's whole life; B's
        #          pre-arm liveness probe keys on its HUP.
        #   arm:   B writes one byte once PDEATHSIG is armed; P
        #          refuses the boot without it.
        #   gone:  P writes one byte when RAPTOR dies; C's orphan
        #          watchdog polls the read end (in-namespace
        #          getppid() never sees RAPTOR).
        live_r, live_w = os.pipe2(os.O_CLOEXEC)
        arm_r, arm_w = os.pipe2(os.O_CLOEXEC)
        gone_r, gone_w = os.pipe2(os.O_CLOEXEC)
        ns_init_pid = os.fork()
        if ns_init_pid != 0:
            # P: thin single-threaded supervisor from here on; never
            # reaches the listener/forwarder body. live_w is
            # deliberately NOT closed — its closure at P's death is
            # B's pre-arm death signal. _supervise_ns_init reports
            # the achieved tier itself, after the arm byte.
            for fd in (live_r, arm_w, gone_r):
                os.close(fd)
            return _supervise_ns_init(
                ns_init_pid, arm_r, gone_w, args.ready_fd,
            )
        # B: PID 1 of the fresh pid namespace. Only P may report a
        # tier, and only P holds the raptor-gone write end — drop the
        # inherited copies so HUP/EOF semantics track P alone.
        for fd in (live_w, arm_r, gone_w):
            os.close(fd)
        if args.ready_fd is not None:
            with contextlib.suppress(OSError):
                os.close(args.ready_fd)
        _ns_init_split(live_r, arm_w)  # returns only in C (PID 2)
        parent_gone_fd = gone_r

    # Terminal-signal handling installs FIRST — before the group-tier
    # ready report and before the listener binds — so no consumer
    # keying on either observable boot milestone can beat the handlers
    # and hit the default disposition (supervisor death, socket left
    # behind). A signal that arrives while the child does not exist
    # yet is RECORDED, never dropped: the pre-spawn check below exits
    # promptly on it, and the post-spawn drain covers one landing
    # mid-``Popen``. (Pidns tier: a signal reaching C even earlier —
    # before these lines — kills C, and B mirrors the death into a
    # clean namespace collapse; P and B install their own forwarders,
    # untouched by this ordering.)
    child: subprocess.Popen | None = None
    pending_signals: list[int] = []

    def _forward_signal(signum: int, _frame: FrameType | None) -> None:
        if child is not None:
            with contextlib.suppress(OSError):
                child.send_signal(signum)
        else:
            pending_signals.append(signum)

    signal.signal(signal.SIGTERM, _forward_signal)
    signal.signal(signal.SIGINT, _forward_signal)

    if not args.pidns:
        # Reported only after the handlers above: "ready" promises the
        # consumer may signal the supervisor from the instant it reads
        # the tier line without racing the default disposition. (The
        # pidns tier's report lives in P, gated on the arm byte.)
        _report_tier(args.ready_fd, "group")

    # Listener bound (and 0700) BEFORE the server can be reached:
    # the unix socket is the namespace's sole ingress, so there is no
    # window where the server accepts traffic without the socket-path
    # permission gate in place.
    listener = create_listener(args.socket)
    forwarder = Forwarder(
        listener, ("127.0.0.1", args.port), socket_path=args.socket,
    )
    forwarder.start()

    # Armed BEFORE the child exists so a parent death inside the
    # spawn window is covered; the closure reads main()'s current
    # binding.
    _start_orphan_watchdog(
        lambda: child, forwarder, idle_ttl_s=args.orphan_idle_ttl,
        parent_gone_fd=parent_gone_fd,
    )

    _hold_prespawn_gate(os.environ.get(_TEST_PRESPAWN_GATE_ENV))

    if pending_signals:
        # A terminal signal arrived before the child existed. Honour
        # the same observable contract a forwarded signal produces —
        # socket unlinked, socket dir removed, shell-convention
        # 128+signum exit — WITHOUT spawning the command: the consumer
        # asked the supervisor to die while there was no child, so
        # booting a server only to kill it would waste the boot and
        # reopen the window this block closes.
        forwarder.stop()
        with contextlib.suppress(OSError):
            os.rmdir(os.path.dirname(args.socket))
        return 128 + pending_signals[0]

    # stdio, env, cwd, and the namespace are inherited: the wrapped
    # server's stderr keeps flowing to the parent's boot-failure pipe.
    child = subprocess.Popen(cmd)
    # A terminal signal can land while ``Popen`` is mid-spawn — the
    # handler still sees ``child is None`` and records it. The child
    # exists now: deliver, and let the normal wait/teardown below
    # finish the contract. Between handler install and this line no
    # terminal signal is ever dropped.
    for signum in pending_signals:
        with contextlib.suppress(OSError):
            child.send_signal(signum)

    try:
        rc = child.wait()
    finally:
        forwarder.stop()
        # Parent-owned directory; removing it here covers the
        # lifecycle-reuse case where the parent process is long gone.
        with contextlib.suppress(OSError):
            os.rmdir(os.path.dirname(args.socket))
    # Popen encodes signal death as a negative value; exit with the
    # shell convention (128+N) instead of letting sys.exit truncate.
    return 128 - rc if rc < 0 else rc


if __name__ == "__main__":
    sys.exit(main())

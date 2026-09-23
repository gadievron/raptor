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
covers a child that ignores them.

``--self-probe`` exercises the full mechanism (unshare, uid map,
loopback up, TCP round-trip, unix-socket bind) and exits 0/1 — the
parent uses it for tier selection, mirroring the sandbox's
probe-then-degrade convention.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import os
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

# <linux/sockios.h> / <net/if.h>
_SIOCGIFFLAGS = 0x8913
_SIOCSIFFLAGS = 0x8914
_IFF_UP = 0x1
# struct ifreq: 16-byte name + 24-byte union (40 bytes on 64-bit).
_IFREQ_FMT = "16sH22s"

_CHUNK = 65536
_BACKLOG = 32
_UPSTREAM_CONNECT_TIMEOUT_S = 10.0


def enter_private_netns() -> None:
    """Unshare into a fresh user+network namespace, identity-mapped.

    The identity uid/gid mapping (uid -> uid, gid -> gid) keeps
    ``getuid()``, passwd lookups, and file ownership exactly as on the
    host — the JVM never notices the namespace. Writing our own single-
    entry map needs no ``newuidmap`` helper and no extra privileges.
    """
    if not hasattr(os, "unshare"):
        raise RuntimeError("os.unshare unavailable on this Python")
    uid, gid = os.getuid(), os.getgid()
    os.unshare(_CLONE_NEWUSER | _CLONE_NEWNET)
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
        t.start()
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
            threading.Thread(
                target=self._handle, args=(conn,), daemon=True,
            ).start()

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
            back.start()
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


#: Orphan-watchdog cadence / SIGTERM→SIGKILL escalation grace.
_PARENT_POLL_S = 5.0
_PARENT_KILL_GRACE_S = 10.0
#: How long an ORPHANED server may sit with no client activity before
#: the watchdog reaps the pair. Parent death alone is NORMAL here —
#: the lifecycle layer keeps warm servers alive across RAPTOR runs
#: precisely so later acquires skip the 30-120s JVM boot — so this
#: mirrors the acquire-side recycle horizon for unreferenced servers
#: (packages/joern/lifecycle.py ``_STALE_THRESHOLD_S``; keep in sync):
#: a warm server the next run would still reuse survives, one nothing
#: touched for the same horizon is reaped instead of squatting on
#: multi-GB of RAM forever.
_ORPHAN_IDLE_TTL_S = 3600 * 8


def _start_orphan_watchdog(
    get_child: Callable[[], subprocess.Popen | None],
    forwarder: Forwarder,
    *,
    poll_s: float = _PARENT_POLL_S,
    grace_s: float = _PARENT_KILL_GRACE_S,
    idle_ttl_s: float = _ORPHAN_IDLE_TTL_S,
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
    """
    parent = os.getppid()

    def _watch() -> None:
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
    t.start()
    return t


def self_probe() -> int:
    """Exercise the full isolation mechanism; 0 = strong tier works."""
    try:
        enter_private_netns()
        bring_loopback_up()
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
        print(f"netns self-probe failed: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a command in a private netns behind a unix socket",
    )
    parser.add_argument("--self-probe", action="store_true")
    parser.add_argument("--socket", help="unix socket path to listen on")
    parser.add_argument("--port", type=int, help="in-namespace TCP port")
    parser.add_argument("cmd", nargs=argparse.REMAINDER,
                        help="-- command to supervise inside the namespace")
    args = parser.parse_args(argv)

    if args.self_probe:
        return self_probe()

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not args.socket or not args.port or not cmd:
        parser.error("--socket, --port, and a command are required")

    enter_private_netns()
    bring_loopback_up()

    # Listener bound (and 0700) BEFORE the server exists: there is no
    # window where the server accepts traffic without the socket-path
    # permission gate in place.
    listener = create_listener(args.socket)
    forwarder = Forwarder(
        listener, ("127.0.0.1", args.port), socket_path=args.socket,
    )
    forwarder.start()

    # Handlers installed BEFORE the child exists so a signal landing
    # in the spawn window is forwarded (or absorbed) instead of taking
    # the supervisor down with the default action and skipping socket
    # cleanup.
    child: subprocess.Popen | None = None

    def _forward_signal(signum: int, _frame: FrameType | None) -> None:
        if child is not None:
            with contextlib.suppress(OSError):
                child.send_signal(signum)

    signal.signal(signal.SIGTERM, _forward_signal)
    signal.signal(signal.SIGINT, _forward_signal)

    # Armed BEFORE the child exists so a parent death inside the spawn
    # window is covered; the closure reads main()'s current binding.
    _start_orphan_watchdog(lambda: child, forwarder)

    # stdio, env, cwd, and the namespace are inherited: the wrapped
    # server's stderr keeps flowing to the parent's boot-failure pipe.
    child = subprocess.Popen(cmd)

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

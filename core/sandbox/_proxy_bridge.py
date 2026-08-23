"""TCP-to-Unix-socket relay for network-namespace proxy enforcement.

Runs inside the sandboxed child's empty network namespace, forked off
before Landlock/seccomp are applied. Listens on 127.0.0.1:<port> (TCP)
inside the netns and relays every inbound connection to a Unix socket
in the parent namespace (visible via the pre-pivot host mount view).
One relay process can serve several (port, unix_path) bridges — the
egress proxy's socket plus any extra loopback services the caller
declared (e.g. the LLM dispatcher for credential-proxy CLI children).

Fork-safe: uses only errno, fcntl, os-level I/O, socket, struct,
select (all imported pre-fork at module load) plus a post-fork
``import time`` of the compiled-in builtin. No Python logging, no
threading, no post-fork imports that trigger C-extension init.
"""

import errno
import fcntl
import os
import select
import socket
import struct

_BUF_SIZE = 65536
_SELECT_TIMEOUT = 1.0

# Relay-pair bounds. The forwarder serves every proxy and credential
# bridge of its run from ONE select loop, so an unbounded pairs dict
# consumed forwarder fds and a single stalled peer used to
# head-of-line-block every other pair (the old synchronous _write_all
# parked the loop up to 60s per stalled write). Bounds:
#
# - _MAX_PAIRS: concurrent relay pairs; connections beyond it are
#   accepted and immediately closed (the child sees EOF and fails
#   fast, like the dead-upstream case). 128 is far above the
#   handful of bridges x connection bursts a sandboxed child
#   legitimately drives, and caps the forwarder at ~256 relay fds.
# - _PAIR_IDLE_TIMEOUT_S: a pair with no traffic in either direction
#   for this long is swept (the egress proxy's own 300s idle bound
#   applied at this hop too, so parked connections release fds).
# - _WRITE_STALL_TIMEOUT_S / _MAX_PENDING_BYTES: writes are now
#   non-blocking with a per-fd bounded pending buffer drained via
#   the select loop's writability set; once the buffer is full the
#   pair's OTHER side stops being read (backpressure), and a peer
#   that makes no drain progress for the stall timeout gets its pair
#   dropped — instead of one os.write parking the whole loop.
_MAX_PAIRS = 128
_PAIR_IDLE_TIMEOUT_S = 300.0
_WRITE_STALL_TIMEOUT_S = 60.0
_MAX_PENDING_BYTES = 256 * 1024


def _bring_up_loopback() -> None:
    """SIOCSIFFLAGS to set IFF_UP on lo inside the current netns."""
    SIOCSIFFLAGS = 0x8914
    IFF_UP, IFF_LOOPBACK, IFF_RUNNING = 0x1, 0x8, 0x40
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = b"lo".ljust(16, b"\x00") + struct.pack(
            "h", IFF_UP | IFF_LOOPBACK | IFF_RUNNING
        )
        fcntl.ioctl(s, SIOCSIFFLAGS, ifr)
    finally:
        s.close()


def _run_forwarder(listen_port, unix_socket_path, death_r) -> None:
    """Single-bridge compatibility wrapper over :func:`_run_bridges`."""
    _run_bridges(((listen_port, unix_socket_path),), death_r)


def _run_bridges(bridges, death_r) -> None:
    """Relay TCP connections on 127.0.0.1:<port> to each bridge's
    Unix socket.

    ``bridges`` is a sequence of ``(listen_port, unix_socket_path)``
    pairs; each gets its own loopback listener, all served by the one
    select loop. Exits when *death_r* becomes readable (parent closed
    write end) or if select() itself fails; individual relays that
    drain are torn down but the loop keeps serving new connections
    until death_r fires. Designed to run post-fork before
    Landlock/seccomp — the forwarder itself is unrestricted.

    Never blocks on a single peer: writes go through per-fd bounded
    pending buffers drained via the select loop's writability set,
    pairs are capped at ``_MAX_PAIRS``, idle pairs are swept, and a
    peer that stalls its drain past ``_WRITE_STALL_TIMEOUT_S`` gets
    its pair dropped (see the constants above for the rationale).

    Uses only fork-safe primitives.
    """
    import time

    # listener fd -> (listener socket, unix socket path).
    listeners = {}
    for listen_port, unix_socket_path in bridges:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # SO_REUSEADDR: without it, a connection closed within the last
        # ~60s leaves the port in TIME_WAIT and bind fails EADDRINUSE — a
        # bridge restarted on the same port (sandbox re-spawn, back-to-back
        # test runs) refused to come up. REUSEADDR only permits binding
        # over TIME_WAIT remnants, not hijacking a live listener.
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", listen_port))
        listener.listen(128)
        listener.setblocking(False)
        listeners[listener.fileno()] = (listener, unix_socket_path)

    # pairs maps every relay fd -> its partner fd.
    pairs: dict[int, int] = {}
    # fd -> bytearray of bytes accepted from the partner but not yet
    # written to fd (only grows while fd's kernel send buffer is
    # full; bounded by _MAX_PENDING_BYTES via read backpressure).
    pending: dict[int, bytearray] = {}
    # fd -> monotonic instant its pending buffer last FAILED to fully
    # drain (reset on progress, cleared when empty). Present only
    # while pending[fd] is non-empty.
    stall_since: dict[int, float] = {}
    # fd -> monotonic instant of the pair's last byte movement in
    # either direction (both fds of a pair carry the same value).
    last_activity: dict[int, float] = {}
    # fds whose pair must close once their pending buffer drains: the
    # SOURCE side hit EOF with bytes still owed to this fd. Preserves
    # the old synchronous semantics where an EOF was only processed
    # after every previously read byte had been written through.
    closing = set()

    def _close_pair(fd) -> None:
        for f in (pairs.pop(fd, None), fd):
            if f is None:
                continue
            pairs.pop(f, None)
            pending.pop(f, None)
            stall_since.pop(f, None)
            last_activity.pop(f, None)
            closing.discard(f)
            try:
                os.close(f)
            except OSError:
                pass

    def _mark_activity(fd):
        now = time.monotonic()
        last_activity[fd] = now
        partner = pairs.get(fd)
        if partner is not None:
            last_activity[partner] = now

    try:
        while True:
            now = time.monotonic()
            # Sweep idle and write-stalled pairs. Runs once per loop
            # wake (<= _SELECT_TIMEOUT apart), so enforcement lags the
            # nominal deadline by at most one select interval.
            for fd in list(pairs):
                if fd not in pairs:
                    continue  # partner side already swept it
                if now - last_activity.get(fd, now) > _PAIR_IDLE_TIMEOUT_S:
                    _close_pair(fd)
                elif (fd in stall_since
                        and now - stall_since[fd] > _WRITE_STALL_TIMEOUT_S):
                    _close_pair(fd)

            read_fds = [death_r]
            read_fds.extend(listeners)
            for fd in pairs:
                partner = pairs[fd]
                if fd in closing or partner in closing:
                    continue  # draining a dying pair; no more reads
                if len(pending.get(partner, b"")) >= _MAX_PENDING_BYTES:
                    continue  # backpressure: partner's buffer is full
                read_fds.append(fd)
            write_fds = [fd for fd in pairs if pending.get(fd)]

            try:
                readable, writable, _ = select.select(
                    read_fds, write_fds, [], _SELECT_TIMEOUT,
                )
            except (ValueError, OSError):
                break

            if death_r in readable:
                # Parent died or signalled shutdown.
                return

            # Drain pending writes FIRST so this iteration's reads see
            # the freed buffer space. `writable` is a snapshot — the
            # sweep above may already have closed an entry; `fd not in
            # pairs` guards every stale case (no new fds exist yet:
            # accepts are deferred to the end of the iteration).
            for fd in writable:
                if fd not in pairs:
                    continue
                buf = pending.get(fd)
                if not buf:
                    continue
                try:
                    n = os.write(fd, buf)
                except OSError as e:
                    if e.errno == errno.EAGAIN:
                        continue
                    _close_pair(fd)
                    continue
                if n <= 0:
                    _close_pair(fd)
                    continue
                del buf[:n]
                _mark_activity(fd)
                if buf:
                    # Partial drain still counts as progress —
                    # restart the stall clock.
                    stall_since[fd] = time.monotonic()
                else:
                    stall_since.pop(fd, None)
                    if fd in closing:
                        # Last owed byte delivered after the source's
                        # EOF — now the pair can go.
                        _close_pair(fd)

            accept_ready = []
            for fd in readable:
                if fd in listeners:
                    accept_ready.append(fd)
                    continue

                # `readable` is a snapshot: an entry whose relay was
                # torn down earlier in THIS iteration (its partner hit
                # EOF/error first, or a sweep took it) is stale.
                # Without this guard the stale fd would be read from /
                # closed again — and if the fd number had been reused
                # by a fresh connection, that unrelated connection
                # would be corrupted or killed.
                if fd not in pairs:
                    continue

                partner = pairs.get(fd)
                if partner is None:
                    _close_pair(fd)
                    continue
                try:
                    data = os.read(fd, _BUF_SIZE)
                except OSError as e:
                    if e.errno == errno.EAGAIN:
                        continue
                    _close_pair(fd)
                    continue
                if not data:
                    # EOF. If bytes are still owed to the partner,
                    # keep the pair draining (bounded by the stall
                    # and idle sweeps); otherwise tear down now.
                    if pending.get(partner):
                        closing.add(partner)
                        stall_since.setdefault(partner, time.monotonic())
                    else:
                        _close_pair(fd)
                    continue
                buf = pending[partner]
                if not buf:
                    # Fast path: partner's buffer is empty, try the
                    # write inline; only the unwritten tail is queued.
                    try:
                        n = os.write(partner, data)
                    except OSError as e:
                        if e.errno != errno.EAGAIN:
                            _close_pair(fd)
                            continue
                        n = 0
                    if n < len(data):
                        buf += data[n:]
                        stall_since.setdefault(partner, time.monotonic())
                else:
                    buf += data
                _mark_activity(fd)

            # Accept LAST: fds created here (accept + unix connect)
            # can reuse numbers closed by _close_pair above. Deferring
            # the accept until every relay entry from this snapshot is
            # processed means no stale `readable` entry can alias a
            # fresh connection's fd number.
            for lfd in accept_ready:
                listener, unix_socket_path = listeners[lfd]
                try:
                    client_sock, _ = listener.accept()
                except OSError:
                    continue
                if len(pairs) // 2 >= _MAX_PAIRS:
                    # Pair cap: refuse by immediate close — the child
                    # sees EOF and fails fast (same shape as the
                    # dead-upstream case) instead of the forwarder
                    # accumulating unbounded fds.
                    client_sock.close()
                    continue
                client_sock.setblocking(False)

                unix_sock = socket.socket(
                    socket.AF_UNIX, socket.SOCK_STREAM,
                )
                try:
                    unix_sock.connect(unix_socket_path)
                except OSError:
                    client_sock.close()
                    unix_sock.close()
                    continue
                unix_sock.setblocking(False)

                c_fd = client_sock.detach()
                u_fd = unix_sock.detach()
                pairs[c_fd] = u_fd
                pairs[u_fd] = c_fd
                pending[c_fd] = bytearray()
                pending[u_fd] = bytearray()
                now = time.monotonic()
                last_activity[c_fd] = now
                last_activity[u_fd] = now
    finally:
        for fd in set(listeners) | set(pairs):
            try:
                os.close(fd)
            except OSError:
                pass

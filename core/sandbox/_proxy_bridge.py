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


def _bring_up_loopback():
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


def _run_forwarder(listen_port, unix_socket_path, death_r):
    """Single-bridge compatibility wrapper over :func:`_run_bridges`."""
    _run_bridges(((listen_port, unix_socket_path),), death_r)


def _run_bridges(bridges, death_r):
    """Relay TCP connections on 127.0.0.1:<port> to each bridge's
    Unix socket.

    ``bridges`` is a sequence of ``(listen_port, unix_socket_path)``
    pairs; each gets its own loopback listener, all served by the one
    select loop. Exits when *death_r* becomes readable (parent closed
    write end) or if select() itself fails; individual relays that
    drain are torn down but the loop keeps serving new connections
    until death_r fires. Designed to run post-fork before
    Landlock/seccomp — the forwarder itself is unrestricted.

    Uses only fork-safe primitives.
    """
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
    pairs = {}
    all_fds = set(listeners) | {death_r}

    def _close_pair(fd):
        partner = pairs.pop(fd, None)
        if partner is not None:
            pairs.pop(partner, None)
            all_fds.discard(partner)
            try:
                os.close(partner)
            except OSError:
                pass
        all_fds.discard(fd)
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        while True:
            try:
                readable, _, _ = select.select(
                    list(all_fds), [], [], _SELECT_TIMEOUT,
                )
            except (ValueError, OSError):
                break

            if death_r in readable:
                # Parent died or signalled shutdown.
                return

            accept_ready = []
            for fd in readable:
                if fd in listeners:
                    accept_ready.append(fd)
                    continue

                # `readable` is a snapshot: an entry whose relay was
                # torn down earlier in THIS iteration (its partner hit
                # EOF/error first) is stale. Without this guard the
                # stale fd would be read from / closed again — and if
                # the fd number had been reused by a fresh connection,
                # that unrelated connection would be corrupted or
                # killed.
                if fd not in all_fds:
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
                    _close_pair(fd)
                    continue
                try:
                    _write_all(partner, data)
                except OSError:
                    _close_pair(fd)

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
                all_fds.add(c_fd)
                all_fds.add(u_fd)
    finally:
        for fd in all_fds:
            if fd != death_r:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _write_all(fd, data, timeout=60.0):
    """Write all of *data* to *fd*. Raises OSError on failure."""
    import time
    deadline = time.monotonic() + timeout
    mv = memoryview(data)
    while mv:
        try:
            n = os.write(fd, mv)
        except BlockingIOError:
            if time.monotonic() > deadline:
                raise OSError(errno.ETIMEDOUT, "write timed out")
            select.select([], [fd], [], 0.5)
            continue
        if n <= 0:
            raise OSError(errno.EIO, "write returned <= 0")
        mv = mv[n:]

"""TCP-to-Unix-socket relay for network-namespace proxy enforcement.

Runs inside the sandboxed child's empty network namespace, forked off
before Landlock/seccomp are applied. Listens on 127.0.0.1:<port> (TCP)
inside the netns and relays every inbound connection to the egress
proxy's Unix socket in the parent namespace (visible via bind-mount).

Fork-safe: uses only os-level I/O, socket, struct, select. No Python
logging, no threading, no imports that trigger C-extension init.
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
    """Relay TCP connections on 127.0.0.1:<listen_port> to *unix_socket_path*.

    Exits when *death_r* becomes readable (parent closed write end) or
    when all active relays have drained. Designed to run post-fork
    before Landlock/seccomp — the forwarder itself is unrestricted.

    Uses only fork-safe primitives.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", listen_port))
    listener.listen(128)
    listener.setblocking(False)

    # pairs maps every relay fd -> its partner fd.
    pairs = {}
    all_fds = {listener.fileno(), death_r}

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

            for fd in readable:
                if fd == death_r:
                    # Parent died or signalled shutdown.
                    return

                if fd == listener.fileno():
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
    finally:
        for fd in list(all_fds):
            if fd != death_r:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _write_all(fd, data):
    """Write all of *data* to *fd*. Raises OSError on failure."""
    mv = memoryview(data)
    while mv:
        try:
            n = os.write(fd, mv)
        except BlockingIOError:
            select.select([], [fd], [], 0.5)
            continue
        if n <= 0:
            raise OSError(errno.EIO, "write returned <= 0")
        mv = mv[n:]

"""_anon_socketpair_problem — the one admissible pass_fds socket shape.

SECURITY-SENSITIVE surface: the pass_fds gate refuses every socket
except a connected anonymous AF_UNIX SOCK_STREAM socketpair half whose
other half is held by the calling process (pipe-equivalent: a private
byte stream to the trusted parent). Each predicate leg gets a
refusal-direction test — the docker.sock client shape, INET families,
datagram pairs, listeners, and foreign-created pairs must all stay
refused; only the own-pair half qualifies.

Pure predicate tests: no sandbox spawn (the run()-path integration
tests live in test_sandbox.py::TestFdIsolation).
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys

import pytest

from core.sandbox.context import _anon_socketpair_problem

_needs_peercred = pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"),
    reason="SO_PEERCRED unavailable on this platform",
)


class TestQualifyingShape:
    @_needs_peercred
    def test_own_socketpair_half_qualifies(self):
        a, b = socket.socketpair()
        try:
            assert _anon_socketpair_problem(a.fileno()) is None
            assert _anon_socketpair_problem(b.fileno()) is None
            # Inspection is via a dup-wrapped socket — the caller's
            # descriptor keeps its state and stays usable.
            a.send(b"ping")
            assert b.recv(4) == b"ping"
        finally:
            a.close()
            b.close()


class TestRefusedShapes:
    def test_inet_socket_refused(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            problem = _anon_socketpair_problem(s.fileno())
            assert problem is not None
            assert "AF_UNIX" in problem
        finally:
            s.close()

    def test_datagram_pair_refused(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            problem = _anon_socketpair_problem(a.fileno())
            assert problem is not None
            assert "SOCK_STREAM" in problem
        finally:
            a.close()
            b.close()

    def test_unconnected_unix_socket_refused(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            problem = _anon_socketpair_problem(s.fileno())
            assert problem is not None
            assert "connected" in problem
        finally:
            s.close()

    def test_pathname_client_refused(self, tmp_path):
        # The docker.sock escape shape: a client CONNECTED to a
        # pathname server. Its local end is unnamed — the peer name
        # is what betrays (and refuses) it.
        path = str(tmp_path / "srv.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            srv.bind(path)
            srv.listen(1)
            cli.connect(path)
            problem = _anon_socketpair_problem(cli.fileno())
            assert problem is not None
            assert "named" in problem
        finally:
            cli.close()
            srv.close()

    def test_pathname_accepted_side_refused(self, tmp_path):
        # The server-side accepted connection: LOCAL end is named.
        path = str(tmp_path / "srv.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn = None
        try:
            srv.bind(path)
            srv.listen(1)
            cli.connect(path)
            conn, _ = srv.accept()
            problem = _anon_socketpair_problem(conn.fileno())
            assert problem is not None
            assert "named" in problem
        finally:
            if conn is not None:
                conn.close()
            cli.close()
            srv.close()

    @_needs_peercred
    @pytest.mark.skipif(
        not hasattr(socket, "recv_fds"),
        reason="socket.recv_fds requires Python 3.9+",
    )
    def test_foreign_created_pair_refused(self):
        # A pair minted by ANOTHER process and smuggled in over
        # SCM_RIGHTS is anonymous/connected/stream — only SO_PEERCRED
        # (creator pid) tells it apart from an own pair. Static child
        # program text; the transport fd rides as argv.
        child_src = (
            "import socket, sys\n"
            "t = socket.socket(fileno=int(sys.argv[1]))\n"
            "a, b = socket.socketpair()\n"
            "socket.send_fds(t, [b'x'], [a.fileno()])\n"
        )
        t_parent, t_child = socket.socketpair()
        received: list[int] = []
        try:
            proc = subprocess.Popen(
                [sys.executable, "-c", child_src,
                 str(t_child.fileno())],
                pass_fds=(t_child.fileno(),),
            )
            t_child.close()
            _msg, fds, _flags, _addr = socket.recv_fds(t_parent, 1, 1)
            received.extend(fds)
            assert proc.wait(timeout=30) == 0
            assert received, "child sent no fd"
            problem = _anon_socketpair_problem(received[0])
            assert problem is not None
            assert "peer pid" in problem
        finally:
            for fd in received:
                os.close(fd)
            t_parent.close()

    def test_closed_fd_refused(self):
        a, b = socket.socketpair()
        fd = os.dup(a.fileno())
        os.close(fd)
        a.close()
        b.close()
        problem = _anon_socketpair_problem(fd)
        assert problem is not None

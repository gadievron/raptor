"""pass_fds capability gate.

An inherited fd is a kernel capability that bypasses every path-based
sandbox layer: Landlock attached its access rights when the PARENT
opened it (before restrictions), and the mount namespace never sees
it. The battery shape: a caller passes an O_RDONLY fd to a $HOME file
(or a $HOME dirfd) into a restrict_reads sandbox and the child reads
it (or getdents's the home directory) despite the read allowlist.

sandbox().run() now refuses out-of-policy fds unless the caller
explicitly declares the capability grant with pass_fds_declared=True.
In-policy shapes (pipes, ttys, fds under output/target/allowlisted
paths, read fds when reads are unrestricted) pass through unchanged.
"""

import os
import socket
import sys
import tempfile
import unittest

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="sandbox pass_fds gate is Linux-only",
)


class TestPassFdsGate(unittest.TestCase):
    def setUp(self):
        self._out = tempfile.TemporaryDirectory(prefix="raptor-fdgate-")
        self.addCleanup(self._out.cleanup)
        self.out = os.path.realpath(self._out.name)
        # The victim must live OUTSIDE the writable baseline (/tmp is
        # in it) — $HOME is the battery's shape and the canonical
        # out-of-policy location.
        home = os.path.expanduser("~")
        if not os.access(home, os.W_OK):
            self.skipTest("home directory not writable on this host")
        self._victim_dir = tempfile.TemporaryDirectory(
            dir=home, prefix=".raptor-fdgate-victim-")
        self.addCleanup(self._victim_dir.cleanup)
        self.victim = os.path.join(self._victim_dir.name, "secret.txt")
        with open(self.victim, "w") as f:
            f.write("victim\n")

    def _sandbox(self, **kw):
        from core.sandbox import sandbox
        kw.setdefault("output", self.out)
        return sandbox(**kw)

    def _open_victim(self, flags=os.O_RDONLY):
        fd = os.open(self.victim, flags)
        self.addCleanup(os.close, fd)
        return fd

    def test_out_of_allowlist_read_fd_refused_under_restrict_reads(self):
        fd = self._open_victim()
        with self._sandbox(restrict_reads=True) as run:
            with self.assertRaisesRegex(TypeError, "out-of-policy"):
                run(["/bin/true"], pass_fds=[fd])

    def test_out_of_allowlist_dirfd_refused_under_restrict_reads(self):
        fd = os.open(self._victim_dir.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with self._sandbox(restrict_reads=True) as run:
            with self.assertRaisesRegex(TypeError, "out-of-policy"):
                run(["/bin/true"], pass_fds=[fd])

    def test_write_capable_fd_outside_writable_paths_refused(self):
        """Write fds are gated even when reads are unrestricted."""
        fd = self._open_victim(os.O_WRONLY)
        with self._sandbox() as run:
            with self.assertRaisesRegex(TypeError, "write-capable"):
                run(["/bin/true"], pass_fds=[fd])

    def test_anonymous_memfd_refused(self):
        fd = os.memfd_create("raptor-fdgate-test")
        self.addCleanup(os.close, fd)
        with self._sandbox() as run:
            with self.assertRaisesRegex(TypeError, "anonymous"):
                run(["/bin/true"], pass_fds=[fd])

    def test_declared_grant_is_allowed_and_logged(self):
        fd = self._open_victim()
        with self._sandbox(restrict_reads=True) as run:
            r = run(["/bin/true"], pass_fds=[fd], pass_fds_declared=True,
                    capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_socket_refused_even_when_declared(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        with self._sandbox() as run:
            with self.assertRaisesRegex(TypeError, "socket"):
                run(["/bin/true"], pass_fds=[a.fileno()],
                    pass_fds_declared=True)

    def test_read_fd_allowed_when_reads_unrestricted(self):
        fd = self._open_victim()
        with self._sandbox() as run:
            r = run(["/bin/true"], pass_fds=[fd],
                    capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_pipe_allowed(self):
        r_fd, w_fd = os.pipe()
        self.addCleanup(os.close, r_fd)
        self.addCleanup(os.close, w_fd)
        os.set_inheritable(r_fd, True)
        with self._sandbox(restrict_reads=True) as run:
            r = run(["/bin/true"], pass_fds=[r_fd],
                    capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_fd_under_output_allowed(self):
        path = os.path.join(self.out, "artifact.bin")
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        self.addCleanup(os.close, fd)
        with self._sandbox() as run:
            r = run(["/bin/true"], pass_fds=[fd],
                    capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()

"""fd 1/2 readable-descriptor arm (extension of the tty write-only
reopen).

The tty fix handed the child a write-only reopen of an inherited
terminal, but the policy was tty-only: an O_RDWR NON-tty descriptor on
stdout/stderr (regular file opened rw, a socket, an rw FIFO) passed
unchecked (``isatty → continue``), handing the sandboxed child read
access the filesystem policy never granted — descriptor capabilities
ride past Landlock and the mount namespace.

Contract under test (uncaptured run_untrusted, caller supplies no
stdout=/stderr=):

* O_WRONLY pass-throughs (the normal shell-redirect shape) stay
  untouched;
* readable regular files are replaced with a write-only reopen at the
  inherited offset;
* readable sockets are plugged with DEVNULL (no write-only reopen
  exists) with a loud warning;
* the reopened fd is closed after the run.
"""

from __future__ import annotations

import fcntl
import os
import socket
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


class _Fd1Swap:
    """Temporarily install *fd* as this process's fd 1."""

    def __init__(self, fd: int):
        self.fd = fd

    def __enter__(self):
        self.saved = os.dup(1)
        os.dup2(self.fd, 1)
        return self

    def __exit__(self, *exc):
        os.dup2(self.saved, 1)
        os.close(self.saved)
        return False


class TestFd12ReadableArm(unittest.TestCase):
    def _run_untrusted_capturing(self):
        import core.sandbox.context as ctx

        captured = {}

        def fake_run(cmd, **kw):
            captured.update(kw)
            # Snapshot the access mode NOW — the finally block closes
            # the reopened fd after run() returns.
            std = kw.get("stdout")
            if isinstance(std, int) and std >= 0:
                captured["_stdout_acc"] = (
                    fcntl.fcntl(std, fcntl.F_GETFL) & os.O_ACCMODE
                )
                captured["_stdout_pos"] = os.lseek(
                    std, 0, os.SEEK_CUR)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(ctx, "run", fake_run):
            ctx.run_untrusted(["true"], target="/tmp")
        return captured

    def test_rdwr_regular_file_reopened_write_only_at_offset(self):
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        self.addCleanup(os.unlink, path)
        fd = os.open(path, os.O_RDWR)
        self.addCleanup(os.close, fd)
        os.write(fd, b"parent-output-so-far")

        with _Fd1Swap(fd):
            captured = self._run_untrusted_capturing()

        self.assertIsInstance(captured.get("stdout"), int)
        self.assertEqual(captured.get("_stdout_acc"), os.O_WRONLY)
        self.assertEqual(
            captured.get("_stdout_pos"), len(b"parent-output-so-far"),
        )

    def test_readable_socket_plugged_with_devnull(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)

        with _Fd1Swap(a.fileno()):
            captured = self._run_untrusted_capturing()

        self.assertEqual(captured.get("stdout"), subprocess.DEVNULL)

    def test_wronly_file_untouched(self):
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        self.addCleanup(os.unlink, path)
        fd = os.open(path, os.O_WRONLY)
        self.addCleanup(os.close, fd)

        with _Fd1Swap(fd):
            captured = self._run_untrusted_capturing()

        # No replacement: the shape is already write-only.
        self.assertNotIn("stdout", captured)

    def test_capture_output_skips_the_arm_entirely(self):
        import core.sandbox.context as ctx

        captured = {}

        def fake_run(cmd, **kw):
            captured.update(kw)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        with _Fd1Swap(a.fileno()), patch.object(ctx, "run", fake_run):
            ctx.run_untrusted(
                ["true"], target="/tmp", capture_output=True,
            )
        self.assertNotIn("stdout", captured)


if __name__ == "__main__":
    unittest.main()


import core.sandbox.context as ctx  # noqa: E402


class TestReopenWriteOnlyHelper(unittest.TestCase):
    """The write-only reopen must be VERIFIED, not assumed: BSD
    /dev/fd opens are dup(2)s that ignore flags, so a naive reopen
    silently keeps the descriptor readable."""

    def test_dup_semantics_platform_returns_none_without_getpath(self):
        # Simulate BSD /dev/fd behavior on any platform: the fd-link
        # open returns a dup (original access mode preserved), and no
        # F_GETPATH exists — the helper must refuse rather than hand
        # back a readable descriptor.
        import fcntl
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        self.addCleanup(os.unlink, path)
        fd = os.open(path, os.O_RDWR)
        self.addCleanup(os.close, fd)
        real_open = os.open

        def dup_open(p, flags, *a, **kw):
            if isinstance(p, str) and (
                    p.startswith("/proc/self/fd/")
                    or p.startswith("/dev/fd/")):
                return os.dup(int(p.rsplit("/", 1)[1]))
            return real_open(p, flags, *a, **kw)

        had = hasattr(fcntl, "F_GETPATH")
        saved = getattr(fcntl, "F_GETPATH", None)
        if had:
            delattr(fcntl, "F_GETPATH")
        try:
            with patch.object(os, "open", side_effect=dup_open):
                self.assertIsNone(
                    ctx._reopen_write_only(fd, os.O_WRONLY))
        finally:
            if had:
                fcntl.F_GETPATH = saved

    def test_getpath_fallback_reopens_by_pinned_identity(self):
        # With dup-semantics fd-links but a working F_GETPATH, the
        # helper reopens by real path and pins device/inode identity.
        import fcntl
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        self.addCleanup(os.unlink, path)
        fd = os.open(path, os.O_RDWR)
        self.addCleanup(os.close, fd)
        real_open = os.open
        real_fcntl = fcntl.fcntl
        FAKE_GETPATH = 0x7F001234

        def dup_open(p, flags, *a, **kw):
            if isinstance(p, str) and (
                    p.startswith("/proc/self/fd/")
                    or p.startswith("/dev/fd/")):
                return os.dup(int(p.rsplit("/", 1)[1]))
            return real_open(p, flags, *a, **kw)

        def fake_fcntl(f, cmd, arg=0):
            if cmd == FAKE_GETPATH:
                return path.encode() + b"\x00" * 8
            return real_fcntl(f, cmd, arg)

        had = hasattr(fcntl, "F_GETPATH")
        saved = getattr(fcntl, "F_GETPATH", None)
        fcntl.F_GETPATH = FAKE_GETPATH
        try:
            with patch.object(os, "open", side_effect=dup_open), \
                    patch.object(fcntl, "fcntl", side_effect=fake_fcntl):
                wfd = ctx._reopen_write_only(fd, os.O_WRONLY)
            self.assertIsNotNone(wfd)
            self.addCleanup(os.close, wfd)
            self.assertEqual(
                fcntl.fcntl(wfd, fcntl.F_GETFL) & os.O_ACCMODE,
                os.O_WRONLY)
            self.assertEqual(os.fstat(wfd).st_ino, os.fstat(fd).st_ino)
        finally:
            if had:
                fcntl.F_GETPATH = saved
            else:
                delattr(fcntl, "F_GETPATH")

    def test_getpath_identity_mismatch_refuses(self):
        # A path swapped between F_GETPATH and open must be refused
        # (device/inode pin), not handed to the child.
        import fcntl
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        self.addCleanup(os.unlink, path)
        with tempfile.NamedTemporaryFile(delete=False) as tf2:
            other = tf2.name
        self.addCleanup(os.unlink, other)
        fd = os.open(path, os.O_RDWR)
        self.addCleanup(os.close, fd)
        real_open = os.open
        real_fcntl = fcntl.fcntl
        FAKE_GETPATH = 0x7F001234

        def dup_open(p, flags, *a, **kw):
            if isinstance(p, str) and (
                    p.startswith("/proc/self/fd/")
                    or p.startswith("/dev/fd/")):
                return os.dup(int(p.rsplit("/", 1)[1]))
            return real_open(p, flags, *a, **kw)

        def fake_fcntl(f, cmd, arg=0):
            if cmd == FAKE_GETPATH:
                return other.encode() + b"\x00" * 8  # swapped target
            return real_fcntl(f, cmd, arg)

        had = hasattr(fcntl, "F_GETPATH")
        saved = getattr(fcntl, "F_GETPATH", None)
        fcntl.F_GETPATH = FAKE_GETPATH
        try:
            with patch.object(os, "open", side_effect=dup_open), \
                    patch.object(fcntl, "fcntl", side_effect=fake_fcntl):
                self.assertIsNone(
                    ctx._reopen_write_only(fd, os.O_WRONLY))
        finally:
            if had:
                fcntl.F_GETPATH = saved
            else:
                delattr(fcntl, "F_GETPATH")

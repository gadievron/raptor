"""Descriptor capabilities smuggled through stdio.

- stdin= is dup2'd onto fd 0 by the spawn backends with no policy
  check, so a write-capable file fd, a dirfd, or a socket rode past
  the pass_fds capability gate (whose refusal text even recommended
  "pass stdin= directly").
- run_untrusted passes fd 1/2 through when the caller doesn't
  capture; a PTY slave is opened O_RDWR and setsid() does not revoke
  an already-open descriptor, so the target could read() the
  operator's keystrokes through its own stdout/stderr.
"""

import os
import select
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="spawn backends are Linux-only",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    return not (sysctl.exists() and sysctl.read_text().strip() == "1")


class TestStdinFdPolicy(unittest.TestCase):
    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        self._tgt = tempfile.TemporaryDirectory(prefix="raptor-stdin-")
        self.addCleanup(self._tgt.cleanup)
        self.tgt = os.path.realpath(self._tgt.name)

    def _sandbox(self):
        from core.sandbox import sandbox
        return sandbox(target=self.tgt, output=self.tgt,
                       restrict_reads=True)

    def test_out_of_policy_stdin_fd_refused(self):
        """A $HOME file fd as stdin= is a read capability outside the
        restrict_reads allowlist — same class the pass_fds gate
        refuses."""
        with tempfile.NamedTemporaryFile(
                dir=os.path.expanduser("~"), prefix=".raptor-stdin-",
                delete=False) as f:
            f.write(b"SECRET")
            secret = f.name
        self.addCleanup(os.unlink, secret)
        fd = os.open(secret, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        with self._sandbox() as run:
            with self.assertRaises(TypeError):
                run(["cat"], stdin=fd, capture_output=True,
                    text=True, timeout=30)

    def test_socket_stdin_always_refused(self):
        import socket as socket_mod
        a, b = socket_mod.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        with self._sandbox() as run:
            with self.assertRaises(TypeError):
                run(["cat"], stdin=a.fileno(), capture_output=True,
                    text=True, timeout=30)

    def test_declared_out_of_policy_stdin_allowed_with_warning(self):
        with tempfile.NamedTemporaryFile(
                dir=os.path.expanduser("~"), prefix=".raptor-stdin-",
                delete=False) as f:
            f.write(b"DECLARED\n")
            declared = f.name
        self.addCleanup(os.unlink, declared)
        fd = os.open(declared, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        with self._sandbox() as run:
            r = run(["cat"], stdin=fd, pass_fds_declared=True,
                    capture_output=True, text=True, timeout=30)
        self.assertIn("DECLARED", r.stdout)

    def test_pipe_and_devnull_stdin_unaffected(self):
        with self._sandbox() as run:
            r = run(["cat"], input="piped", capture_output=True,
                    text=True, timeout=30)
            self.assertIn("piped", r.stdout)
            r = run(["cat"], stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0)


class TestPtyReadbackPlugged(unittest.TestCase):
    """End-to-end: a wrapper process whose stdio sits on a real PTY
    calls run_untrusted without capturing; the sandboxed child tries
    to read() its own fd 1. Pre-fix the O_RDWR slave let it harvest
    the byte the test types on the master (the operator's keystroke);
    post-fix the child holds a write-only reopen and the read fails.
    """

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")

    def test_child_cannot_read_operator_terminal(self):
        wt = str(Path(__file__).resolve().parents[3])
        # Markers are CONSTRUCTED at runtime so a traceback echoing
        # the program source can never satisfy the assertions.
        inner = (
            "import os\n"
            "try:\n"
            "    data = os.read(1, 1)\n"
            "    os.write(2, b'RB' + b'=' + data + b'\\n')\n"
            "except OSError:\n"
            "    os.write(2, b'RB' + b'-' + b'DENIED' + b'\\n')\n"
        )
        wrapper = textwrap.dedent(f"""
            import os, sys, tempfile
            sys.path.insert(0, {wt!r})
            os.environ.setdefault("RAPTOR_DIR", {wt!r})
            from core.sandbox.context import run_untrusted
            d = tempfile.mkdtemp(prefix="raptor-pty-")
            try:
                run_untrusted(["/usr/bin/python3", "-c", {inner!r}],
                              target=d, output=d, timeout=40)
            except Exception:
                pass
        """)
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        proc = subprocess.Popen(
            ["/usr/bin/python3", "-c", wrapper],
            stdin=slave, stdout=slave, stderr=slave,
            start_new_session=False, close_fds=True,
        )
        os.close(slave)
        try:
            # the "operator keystroke" (newline included: the pty is
            # in canonical mode, so input is delivered per line)
            os.write(master, b"K\n")
            deadline = time.monotonic() + 90
            buf = b""
            while time.monotonic() < deadline:
                r, _, _ = select.select([master], [], [], 0.5)
                if r:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    buf += chunk
                if b"RB-DENIED" in buf or b"RB=K" in buf:
                    break
                if proc.poll() is not None and not r:
                    break
        finally:
            proc.wait(timeout=30)
        self.assertNotIn(b"RB=K", buf, (
            "sandboxed child read the operator's keystroke through "
            "its own stdout descriptor"
        ))
        self.assertIn(b"RB-DENIED", buf, (
            f"expected the write-only reopen to refuse the read; "
            f"pty transcript tail: {buf[-400:]!r}"
        ))


if __name__ == "__main__":
    unittest.main()

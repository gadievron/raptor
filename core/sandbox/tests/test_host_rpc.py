"""E2E tests for the SandboxHost inherited-pipe-fd RPC transport.

Covers the hostile-peer matrix the transport was rebuilt for, plus
functional round-trips:

(a) rendezvous replacement — impossible by construction: no FIFO /
    socket path is ever created under the target dir across a full
    start/probe/close cycle (the tree is scanned for special inodes).
(b) forged verdict frame — a daemon-spawned child (the position a
    hostile target runs in) has no handle to the daemon→parent
    channel: writes to the RPC fd numbers fail with EBADF, and the
    parent's next real RPC still round-trips.
(c) request-stream read — the same child reading the parent→daemon
    fd numbers also gets EBADF.
(d) create-time swap — N/A by construction; covered by the same
    no-path-artifacts scan as (a).

Plus: start → spawn → probe → conversation round-trips through the
real sandbox, daemon-death detection via EOF on the parent's read
end, and a clean ``close()`` with no leaked fds.

Run: python3 -m pytest -m integration core/sandbox/tests/test_host_rpc.py -v
"""

import sys as _sys

import pytest as _pytest

pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals — the SandboxHost daemon "
           "spawn exercises the Linux subprocess+preexec path",
)


import errno  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import stat  # noqa: E402
import textwrap  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from pathlib import Path  # noqa: E402
from tempfile import TemporaryDirectory  # noqa: E402
from unittest.mock import patch  # noqa: E402

from core.sandbox.host import HostRPCError, SandboxHost  # noqa: E402

# Generous ceiling for CI boxes where the first sandbox spawn pays
# for probe/cache warm-up.
_STARTUP_TIMEOUT = 60.0


def _scan_special_inodes(root: Path) -> list[str]:
    """Return every FIFO / socket path under ``root`` (recursive)."""
    special = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            try:
                mode = p.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
                special.append(str(p))
    return special


# Every test in this class spawns a real sandboxed daemon process.
# Opt-in via ``pytest -m integration``.
@_pytest.mark.integration
class TestHostRPCTransport(unittest.TestCase):
    """Inherited-pipe-fd transport: hostile-peer matrix + round-trips."""

    def _start(self, target: Path) -> SandboxHost:
        return SandboxHost.start(
            target=target, startup_timeout=_STARTUP_TIMEOUT,
        )

    # ------------------------------------------------------------------
    # (a) + (d): no rendezvous path exists to squat or swap
    # ------------------------------------------------------------------

    def test_no_rendezvous_path_artifacts(self):
        """A full start/probe/close cycle creates no FIFO or socket
        anywhere under the target dir — there is no rendezvous name
        for a hostile target to replace (a) or symlink-swap at create
        time (d)."""
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            host = self._start(target)
            try:
                self.assertEqual(_scan_special_inodes(target), [],
                                 "special inode appeared during startup")
                # Exercise a verb so the daemon is actually working
                # while we scan again.
                res = host.probe(
                    target_argv=["/bin/cat"],
                    steps=[{"send_template": "hello\\n",
                            "recv_until": "newline"}],
                )
                self.assertTrue(res.get("ok"), res)
                self.assertEqual(_scan_special_inodes(target), [],
                                 "special inode appeared mid-session")
                # The legacy path-based names specifically must not
                # exist in any form (regular file / symlink either).
                for legacy in ("rpc_in.fifo", "rpc_out.fifo"):
                    self.assertFalse((target / legacy).exists(),
                                     f"{legacy} should never be created")
            finally:
                host.close()
            self.assertEqual(_scan_special_inodes(target), [],
                             "special inode left behind after close")

    # ------------------------------------------------------------------
    # (b) + (c): a daemon-spawned child holds no RPC handle
    # ------------------------------------------------------------------

    def test_daemon_child_cannot_reach_rpc_fds(self):
        """A child the daemon spawns (where a hostile target runs)
        gets EBADF forging frames onto the daemon→parent fd (b) and
        reading the parent→daemon fd (c); the parent's next real RPC
        still round-trips afterwards."""
        with TemporaryDirectory() as tmp:
            host = self._start(Path(tmp))
            try:
                fd_nums = host._daemon_fd_numbers
                self.assertEqual(len(fd_nums), 2)
                probe_script = textwrap.dedent(f"""
                    import fcntl, json, os
                    fds = {list(fd_nums)!r}
                    report = {{"probes": {{}}, "fd_links": {{}}}}
                    for fd in fds:
                        p = {{}}
                        try:
                            os.fstat(fd)
                            p["fstat"] = "open"
                        except OSError as e:
                            p["fstat"] = e.errno
                        try:
                            os.write(fd, b"forged-verdict-frame")
                            p["write"] = "wrote"
                        except OSError as e:
                            p["write"] = e.errno
                        try:
                            fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
                            os.read(fd, 1)
                            p["read"] = "read"
                        except OSError as e:
                            p["read"] = e.errno
                        report["probes"][str(fd)] = p
                    # Enumerate /proc/self/fd AFTER the probes so the
                    # scandir fd can't occupy one of the probed
                    # numbers. Any entry that does match must not be
                    # a pipe (that would be the leaked RPC channel).
                    for n in os.listdir("/proc/self/fd"):
                        if int(n) in fds:
                            try:
                                report["fd_links"][n] = os.readlink(
                                    "/proc/self/fd/" + n)
                            except OSError as e:
                                report["fd_links"][n] = f"errno:{{e.errno}}"
                    print(json.dumps(report))
                """)
                res = host.spawn(["python3", "-c", probe_script],
                                 timeout=30.0)
                self.assertEqual(res["returncode"], 0,
                                 res["stderr"].decode("utf-8", "replace"))
                report = json.loads(res["stdout"].decode("utf-8"))
                for fd in fd_nums:
                    probes = report["probes"][str(fd)]
                    self.assertEqual(probes["fstat"], errno.EBADF,
                                     f"fd {fd} visible to child: {probes}")
                    self.assertEqual(probes["write"], errno.EBADF,
                                     f"fd {fd} writable by child: {probes}")
                    self.assertEqual(probes["read"], errno.EBADF,
                                     f"fd {fd} readable by child: {probes}")
                for n, link in report["fd_links"].items():
                    self.assertFalse(str(link).startswith("pipe:"),
                                     f"child fd {n} is a pipe: {link}")
                # The channel must still be intact for the parent.
                pong = host._rpc({"cmd": "ping"}, timeout=10.0)
                self.assertTrue(pong.get("ok"), pong)
            finally:
                host.close()

    def test_daemon_nondumpable_inside_sandbox(self):
        """The daemon sets PR_SET_DUMPABLE=0 before serving requests
        (and reports it via ping), so a target can't reopen the RPC
        pipe ends through /proc/<daemon>/fd/<n> — the reopen defence
        must survive the real sandbox spawn chain, not just the
        pipe-level harness."""
        with TemporaryDirectory() as tmp:
            host = self._start(Path(tmp))
            try:
                pong = host._rpc({"cmd": "ping"}, timeout=10.0)
                self.assertTrue(pong.get("ok"), pong)
                self.assertEqual(pong.get("dumpable"), 0, pong)
            finally:
                host.close()

    # ------------------------------------------------------------------
    # Functional round-trips
    # ------------------------------------------------------------------

    def test_spawn_probe_conversation_round_trip(self):
        """All three RPC verbs round-trip through the real sandbox on
        one persistent daemon."""
        with TemporaryDirectory() as tmp:
            host = self._start(Path(tmp))
            try:
                res = host.spawn(["/bin/echo", "hello-rpc"])
                self.assertEqual(res["returncode"], 0)
                self.assertEqual(res["stdout"], b"hello-rpc\n")

                probe = host.probe(
                    target_argv=["/bin/cat"],
                    steps=[{"send_template": "ping-line\\n",
                            "recv_until": "newline",
                            "bind_as": "echoed"}],
                    flag_string="ping-line",
                )
                self.assertTrue(probe.get("ok"), probe)
                self.assertTrue(probe.get("flag_captured"), probe)
                self.assertEqual(probe.get("steps_completed"), 1)
                self.assertEqual(probe.get("target_exit"), "clean")

                convo = host.conversation(
                    target_argv=["/bin/cat"],
                    sends=[{"bytes_hex": b"pong\n".hex(),
                            "then_recv_until": "newline"}],
                )
                self.assertTrue(convo.get("ok"), convo)
                self.assertEqual(convo["recvs_hex"], [b"pong\n".hex()])
                self.assertEqual(convo.get("target_exit"), "clean")
            finally:
                host.close()

    def test_daemon_death_surfaces_as_eof(self):
        """When the daemon side goes away the parent's read end sees
        EOF promptly — no path-rendezvous timeout dance involved."""
        with TemporaryDirectory() as tmp:
            host = self._start(Path(tmp))
            try:
                # Closing the parent's write end delivers EOF to the
                # daemon's rpc-in; the daemon exits cleanly, tearing
                # down the sandbox chain and closing the last write
                # handle on rpc-out.
                os.close(host._write_fd)
                # Keep close() from double-closing a possibly-reused
                # fd number.
                host._write_fd = -1
                t0 = time.monotonic()
                with self.assertRaises(HostRPCError) as ctx:
                    host._read_frame(timeout=20.0)
                elapsed = time.monotonic() - t0
                self.assertIn("EOF", str(ctx.exception))
                self.assertLess(elapsed, 15.0,
                                "EOF should arrive from daemon exit, "
                                "not from the read timeout")
            finally:
                host.close()

    def test_close_leaks_no_fds(self):
        """A full start/RPC/close cycle returns the process to its
        prior fd table — nothing from the pipe pairs survives."""
        with TemporaryDirectory() as tmp:
            # Warm-up cycle: one-time module caches (availability
            # probes, logging handlers) may open fds on first use;
            # pay that before measuring.
            warm = self._start(Path(tmp))
            warm.spawn(["/bin/true"])
            warm.close()

            fds_before = set(os.listdir("/proc/self/fd"))
            host = self._start(Path(tmp))
            res = host.spawn(["/bin/echo", "leak-check"])
            self.assertEqual(res["returncode"], 0)
            host.close()
            fds_after = set(os.listdir("/proc/self/fd"))
            leaked = fds_after - fds_before
            self.assertEqual(leaked, set(),
                             f"fds leaked across start/close: {leaked}")


class _DeadDaemonResult:
    returncode = 97
    stderr = b"daemon exploded"


def _fake_run(*args, **kwargs):
    # Simulate the daemon dying instantly: sandbox_run returns without
    # the daemon ever answering the startup ping.
    return _DeadDaemonResult()


class TestDaemonDiedDiagnostic(unittest.TestCase):
    """The daemon-died startup diagnostic must surface the captured
    returncode alongside its sibling keys ``error`` and ``stderr``.
    Mocked spawn — runs in the default (non-integration) suite."""

    def test_returncode_in_startup_failure(self):
        with TemporaryDirectory() as tmp:
            with patch("core.sandbox.run", side_effect=_fake_run):
                with self.assertRaises(HostRPCError) as ctx:
                    SandboxHost.start(
                        target=Path(tmp),
                        startup_timeout=0.5,
                    )
        msg = str(ctx.exception)
        self.assertIn("daemon died during startup", msg)
        # rc= appears alongside err= and stderr= (a diagnostic that
        # captured the returncode but never reported it was a dead
        # store).
        self.assertIn("rc=97", msg)
        self.assertIn("daemon exploded", msg)


if __name__ == "__main__":
    unittest.main()

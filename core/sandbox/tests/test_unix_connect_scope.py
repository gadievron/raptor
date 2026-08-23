"""AF_UNIX connect scoping on the mount-ns spawn path.

Battery shapes pinned here (variant family, not just the exemplar):

- enforcement-mode child connects to a unix socket bound by a HOST
  process inside the rw output bind → must fail (was a live
  bidirectional sandbox<->host channel);
- same via the block_network=False posture (host netns, the
  target_run profile shape);
- symlink bounce: /tmp/link -> output socket → must fail (the
  supervisor refuses symlinked paths wholesale);
- SOCK_DGRAM AF_UNIX creation → EPERM (datagram sendto-with-address
  would bypass the connect chokepoint);
- SOCK_DGRAM AF_UNIX socketpair → EPERM (a dgram socketpair half
  accepts sendto with an explicit destination — same primitive, no
  connect(2) ever reaching the supervisor);
- SOCK_SEQPACKET connect to the output socket → must fail (family
  covers all connection-oriented types);
- the legitimate use stays working: bind + connect a pathname socket
  under the sandbox-private /tmp (the Python >= 3.14 forkserver
  shape), and plain TCP connects still work through the
  execute-on-behalf supervisor;
- fail-closed downgrade: when the supervisor cannot run,
  socket(AF_UNIX) is denied outright.
"""

import os
import shutil
import socket
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns spawn path is Linux-only",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    return not (sysctl.exists() and sysctl.read_text().strip() == "1")


def _scope_usable() -> bool:
    from core.sandbox._unix_scope import probe_unix_scope
    return probe_unix_scope()


_SPAWN_DEFAULTS = dict(
    nproc_limit=1024,
    limits={"memory_mb": 0, "max_file_mb": 10240, "cpu_seconds": 300},
    readable_paths=None,
    allowed_tcp_ports=None,
    seccomp_profile="full",
    seccomp_block_udp=False,
    env=None, cwd=None, timeout=30,
    capture_output=True, text=True,
)


class _Base(unittest.TestCase):
    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        if not _scope_usable():
            self.skipTest("seccomp user-notify connect scoping "
                          "unavailable on this host")
        self._out = tempfile.TemporaryDirectory(prefix="raptor-uscope-")
        self.addCleanup(self._out.cleanup)
        self.out = os.path.realpath(self._out.name)

    def _host_listener(self, name="hostsock"):
        path = os.path.join(self.out, name)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(4)
        srv.settimeout(0.5)
        self.addCleanup(srv.close)
        return path, srv

    def _spawn(self, prog, *, block_network=True, **overrides):
        from core.sandbox._spawn import run_sandboxed
        kw = dict(_SPAWN_DEFAULTS)
        kw.update(overrides)
        return run_sandboxed(
            ["/usr/bin/python3", "-c", prog],
            target=self.out, output=self.out,
            block_network=block_network,
            writable_paths=[self.out, "/tmp"],
            **kw,
        )

    def _accepted(self, srv) -> bool:
        try:
            conn, _ = srv.accept()
            conn.close()
            return True
        except (TimeoutError, OSError):
            return False


class TestHostSocketInOutputDenied(_Base):
    _CONNECT = textwrap.dedent("""
        import errno, socket, sys
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(sys.argv[1] if len(sys.argv) > 1 else {path!r})
            print("CONNECTED")
        except OSError as e:
            print("DENIED", e.errno)
    """)

    def test_enforcement_child_cannot_reach_host_socket_in_output(self):
        """b4-audit-unix-enforce shape."""
        path, srv = self._host_listener()
        r = self._spawn(self._CONNECT.format(path=path))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout,
                      f"child connected to a host socket in the rw "
                      f"output bind: {r.stdout!r}")
        self.assertFalse(self._accepted(srv),
                         "host listener accepted a connection from the "
                         "sandboxed child")

    def test_host_netns_posture_also_denied(self):
        """b10-path-targetrun shape (block_network=False → host netns)."""
        path, srv = self._host_listener("hostsock-tr")
        r = self._spawn(self._CONNECT.format(path=path),
                        block_network=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout, r.stdout)
        self.assertFalse(self._accepted(srv))

    def test_seqpacket_variant_denied(self):
        path, srv = self._host_listener("hostsock-sq")
        srv2path = os.path.join(self.out, "hostsock-sq2")
        srv2 = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        srv2.bind(srv2path)
        srv2.listen(1)
        srv2.settimeout(0.5)
        self.addCleanup(srv2.close)
        prog = textwrap.dedent(f"""
            import socket
            s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                s.connect({srv2path!r})
                print("CONNECTED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout, r.stdout)

    def test_symlink_bounce_from_private_tmp_denied(self):
        """Child plants /tmp/link -> <output>/hostsock and connects the
        link — the supervisor must refuse symlinked paths."""
        path, srv = self._host_listener("hostsock-sym")
        prog = textwrap.dedent(f"""
            import os, socket
            os.symlink({path!r}, "/tmp/bounce")
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect("/tmp/bounce")
                print("CONNECTED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout, r.stdout)
        self.assertFalse(self._accepted(srv))

    def test_unix_dgram_socket_denied(self):
        prog = textwrap.dedent("""
            import socket
            try:
                socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                print("CREATED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout,
                      f"AF_UNIX SOCK_DGRAM must be denied under connect "
                      f"scoping (sendto-with-address bypass): {r.stdout!r}")

    def test_unix_dgram_socketpair_denied(self):
        """socketpair(AF_UNIX, SOCK_DGRAM) yields a
        descriptor that accepts sendto() with an explicit destination —
        the same primitive the socket(AF_UNIX, SOCK_DGRAM) deny removes,
        with no connect(2) ever reaching the supervisor. The pair
        creation must be denied and the host dgram listener must never
        receive the datagram."""
        path = os.path.join(self.out, "hostdgram")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        srv.bind(path)
        srv.settimeout(0.5)
        self.addCleanup(srv.close)
        prog = textwrap.dedent(f"""
            import socket
            try:
                a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            except OSError as e:
                print("DENIED", e.errno)
                raise SystemExit(0)
            try:
                a.sendto(b"pwned", {path!r})
                print("SENT")
            except OSError as e:
                print("SENDTO_DENIED", e.errno)
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout,
                      f"AF_UNIX SOCK_DGRAM socketpair must be denied "
                      f"(sendto-with-explicit-destination bypass): "
                      f"{r.stdout!r}")
        try:
            data = srv.recv(64)
        except (TimeoutError, OSError):
            data = None
        self.assertIsNone(
            data, "host dgram listener received a datagram from the "
                  "sandboxed child via a dgram socketpair half")

    def test_unix_dgram_socketpair_cloexec_flag_bits_still_denied(self):
        """SOCK_CLOEXEC / SOCK_NONBLOCK bits in the type argument must
        not dodge the socketpair dgram rule (masked matching)."""
        prog = textwrap.dedent("""
            import socket
            t = socket.SOCK_DGRAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK
            try:
                socket.socketpair(socket.AF_UNIX, t)
                print("CREATED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout,
                      f"flag bits in the socketpair type argument dodged "
                      f"the dgram deny: {r.stdout!r}")


class TestLegitimateUsesKeepWorking(_Base):
    def test_private_tmp_bind_and_connect(self):
        """Forkserver shape: bind + connect inside the sandbox-private
        /tmp must work."""
        prog = textwrap.dedent("""
            import socket
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind("/tmp/fs-listener")
            srv.listen(1)
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect("/tmp/fs-listener")
            conn, _ = srv.accept()
            c.sendall(b"ping")
            print("OK", conn.recv(4).decode())
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK ping", r.stdout,
                      f"private-tmpfs unix IPC must keep working under "
                      f"connect scoping: {r.stdout!r} {r.stderr!r}")

    def test_loopback_tcp_still_works(self):
        """TCP connects are executed on the child's behalf — semantics
        must be unchanged (netns loopback self-connect)."""
        prog = textwrap.dedent("""
            import socket
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            c = socket.socket()
            c.settimeout(10)
            c.connect(("127.0.0.1", port))
            conn, _ = srv.accept()
            c.sendall(b"tcp!")
            print("OK", conn.recv(4).decode())
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK tcp!", r.stdout, f"{r.stdout!r} {r.stderr!r}")

    def test_socketpair_untouched(self):
        prog = textwrap.dedent("""
            import socket
            a, b = socket.socketpair()
            a.sendall(b"sp")
            print("OK", b.recv(2).decode())
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK sp", r.stdout)


class TestThreadedCallers(_Base):
    """connect(2) from a spawned thread notifies with the THREAD's tid.

    ``pidfd_open(tid, 0)`` only accepts thread-group leaders, so every
    threaded connect used to die in the supervisor with ENOENT before
    any policy ran — allowed targets included. The supervisor must
    serve non-leader tasks (PIDFD_THREAD / tgid resolution) so that
    threads get the SAME policy verdicts as the main thread.
    """

    _THREADED = textwrap.dedent("""
        import socket, threading
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind("/tmp/thr-listener")
        srv.listen(2)
        res = {{}}
        def connect(key, path):
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                c.connect(path)
                res[key] = "CONNECTED"
            except OSError as e:
                res[key] = f"DENIED {{e.errno}}"
            finally:
                c.close()
        t = threading.Thread(target=connect,
                             args=("allowed", "/tmp/thr-listener"))
        t.start(); t.join()
        t = threading.Thread(target=connect, args=("denied", {deny!r}))
        t.start(); t.join()
        print("ALLOWED", res["allowed"])
        print("DENIED", res["denied"])
    """)

    def test_thread_gets_same_policy_as_main_thread(self):
        import errno as errno_mod
        deny_path, srv = self._host_listener("hostsock-thr")
        r = self._spawn(self._THREADED.format(deny=deny_path))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(
            "ALLOWED CONNECTED", r.stdout,
            f"private-tmpfs connect from a spawned thread must work "
            f"like the main thread's: {r.stdout!r} {r.stderr!r}")
        # The denied target must get the POLICY verdict (EPERM), not
        # an ENOENT infrastructure failure from the pidfd acquisition.
        self.assertIn(
            f"DENIED DENIED {errno_mod.EPERM}", r.stdout,
            f"policy verdict for a thread's denied connect must match "
            f"the main thread's EPERM: {r.stdout!r}")
        self.assertFalse(self._accepted(srv))

    def test_thread_served_on_simulated_pre_6_9_kernel(self):
        """Kernels < 6.9 reject PIDFD_THREAD (EINVAL) AND refuse a
        plain pidfd_open of a non-leader tid with EINVAL — ENOENT for
        non-leaders only arrived with the pidfs rework (~6.16). The
        tgid fallback must serve threaded callers under exactly that
        errno shape, so both hops are simulated supervisor-side."""
        import errno as errno_mod

        from core.sandbox import _unix_scope as us

        real = us._pidfd_open

        def old_kernel(pid, flags=0):
            if flags & us._PIDFD_THREAD:
                raise OSError(errno_mod.EINVAL, "Invalid argument")
            if flags == 0 and us._tgid_of(pid) != pid:
                # Non-leader tid: pre-6.16 kernels say EINVAL.
                raise OSError(errno_mod.EINVAL, "Invalid argument")
            return real(pid, flags)

        deny_path, srv = self._host_listener("hostsock-thr2")
        with patch.object(us, "_pidfd_open", side_effect=old_kernel):
            r = self._spawn(self._THREADED.format(deny=deny_path))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ALLOWED CONNECTED", r.stdout,
                      f"{r.stdout!r} {r.stderr!r}")
        self.assertFalse(self._accepted(srv))


class TestSupervisorAppliesChildNetworkPolicy(_Base):
    """The supervisor executes connects in the (unconfined) parent, so
    the child's task-scoped Landlock network rules never evaluate for
    them. The supervisor must re-apply the declared policy itself —
    otherwise a networked mount-ns run (block_network=False) silently
    voids allowed_tcp_ports and reaches host abstract sockets."""

    def _tcp_listener(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        srv.settimeout(0.5)
        self.addCleanup(srv.close)
        return srv.getsockname()[1], srv

    _TCP_CONNECT = textwrap.dedent("""
        import socket
        s = socket.socket()
        s.settimeout(10)
        try:
            s.connect(("127.0.0.1", {port}))
            print("CONNECTED")
        except OSError as e:
            print("DENIED", e.errno)
    """)

    def test_allowed_tcp_ports_enforced_on_shared_netns_run(self):
        """Declared allowed_tcp_ports
        must bind supervisor-executed connects too."""
        import errno as _errno
        port, srv = self._tcp_listener()
        r = self._spawn(self._TCP_CONNECT.format(port=port),
                        block_network=False,
                        allowed_tcp_ports=[443])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"DENIED {_errno.EACCES}", r.stdout,
                      f"child reached 127.0.0.1:{port} despite "
                      f"allowed_tcp_ports=[443]: {r.stdout!r}")
        self.assertFalse(self._accepted(srv),
                         "host TCP listener accepted a connection the "
                         "declared port policy forbids")

    def test_allowed_tcp_ports_declared_port_still_connects(self):
        port, srv = self._tcp_listener()
        r = self._spawn(self._TCP_CONNECT.format(port=port),
                        block_network=False,
                        allowed_tcp_ports=[port])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CONNECTED", r.stdout,
                      f"declared-port connect must keep working: "
                      f"{r.stdout!r} {r.stderr!r}")

    def test_abstract_connect_denied_on_shared_netns_run(self):
        """Abstract names resolve in the HOST's
        abstract namespace when the child shares the host netns."""
        import secrets as _secrets
        name = "\0uscope-test-" + _secrets.token_hex(6)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(name)
        srv.listen(4)
        srv.settimeout(0.5)
        self.addCleanup(srv.close)
        prog = textwrap.dedent(f"""
            import socket
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(10)
            try:
                s.connect({name!r})
                print("CONNECTED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog, block_network=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout,
                      f"shared-netns child reached a HOST abstract "
                      f"socket: {r.stdout!r}")
        self.assertFalse(self._accepted(srv))

    def test_abstract_self_ipc_works_with_fresh_netns(self):
        """block_network=True unshares a netns — the child's own
        abstract sockets must keep working there."""
        prog = textwrap.dedent("""
            import socket
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind("\\0uscope-self-ipc")
            srv.listen(1)
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect("\\0uscope-self-ipc")
            conn, _ = srv.accept()
            c.sendall(b"abst")
            print("OK", conn.recv(4).decode())
        """)
        r = self._spawn(prog, block_network=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK abst", r.stdout,
                      f"netns-scoped abstract IPC must keep working: "
                      f"{r.stdout!r} {r.stderr!r}")

    def test_full_backlog_connect_does_not_park_worker(self):
        """A blocking connect to a full-backlog
        listener must not park a supervisor worker (and the run) on
        the attacker's schedule — the child promptly sees EAGAIN."""
        prog = textwrap.dedent("""
            import errno, socket
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind("/tmp/backlog-full")
            srv.listen(0)
            # occupy the single backlog slot, never accept
            c1 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c1.setblocking(False)
            try:
                c1.connect("/tmp/backlog-full")
            except BlockingIOError:
                pass
            c2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            # BLOCKING connect — pre-fix this parked a supervisor
            # worker until the run timeout
            try:
                c2.connect("/tmp/backlog-full")
                print("CONNECTED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog, timeout=20)
        self.assertEqual(r.returncode, 0,
                         f"blocking full-backlog connect wedged the "
                         f"run: rc={r.returncode} {r.stderr!r}")
        self.assertTrue("DENIED" in r.stdout or "CONNECTED" in r.stdout,
                        r.stdout)


class TestFailClosedDowngrade(unittest.TestCase):
    def test_af_unix_blocked_when_supervisor_unavailable(self):
        if not _mount_ns_usable():
            self.skipTest("mount-ns unusable here")
        out = tempfile.TemporaryDirectory(prefix="raptor-uscope-dg-")
        self.addCleanup(out.cleanup)
        prog = textwrap.dedent("""
            import socket
            try:
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                print("CREATED")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        from core.sandbox._spawn import run_sandboxed
        with patch("core.sandbox._unix_scope.probe_unix_scope",
                   return_value=False):
            r = run_sandboxed(
                ["/usr/bin/python3", "-c", prog],
                target=out.name, output=out.name,
                block_network=True,
                writable_paths=[out.name, "/tmp"],
                **_SPAWN_DEFAULTS,
            )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENIED", r.stdout,
                      "with the supervisor unavailable, AF_UNIX must "
                      "stay blocked (fail-closed)")


if __name__ == "__main__":
    unittest.main()


class TestSendPathConnectSmuggling(_Base):
    """TCP Fast Open performs the connect IN-KERNEL inside
    sendto/sendmsg — no connect(2) is issued, so neither the
    supervisor's port re-check nor Landlock CONNECT_TCP ever fires.
    The MSG_FASTOPEN flag is denied wholesale for sandboxed children
    (nothing in the tool population legitimately uses client TFO)."""

    def test_msg_fastopen_sendto_denied(self):
        try:
            with open("/proc/sys/net/ipv4/tcp_fastopen") as f:
                if not int(f.read().strip()) & 1:
                    self.skipTest("client TFO disabled on this host")
        except (OSError, ValueError):
            self.skipTest("no TFO sysctl on this host")
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.setsockopt(socket.IPPROTO_TCP, 23, 5)  # TCP_FASTOPEN
        srv.listen(4)
        srv.settimeout(0.8)
        self.addCleanup(srv.close)
        port = srv.getsockname()[1]
        prog = textwrap.dedent(f"""
            import socket
            s = socket.socket()
            try:
                s.sendto(b"TFO-PROBE", socket.MSG_FASTOPEN,
                         ("127.0.0.1", {port}))
                print("SENT")
            except OSError as e:
                print("DENIED", e.errno)
        """)
        r = self._spawn(prog, block_network=False,
                        allowed_tcp_ports=[443])
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertIn("DENIED", r.stdout, (
            f"MSG_FASTOPEN sendto smuggled an in-kernel connect past "
            f"the port policy: {r.stdout!r}"
        ))
        self.assertFalse(self._accepted(srv),
                         "listener on a non-allowed port received a "
                         "TFO connection")

    def test_plain_send_flags_unaffected(self):
        """MSG_NOSIGNAL / MSG_DONTWAIT sends must keep working — only
        the FASTOPEN bit is filtered."""
        prog = textwrap.dedent("""
            import socket
            a, b = socket.socketpair()
            a.sendmsg([b"ok"], [], socket.MSG_NOSIGNAL)
            print("OK", b.recv(2).decode())
        """)
        r = self._spawn(prog)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertIn("OK ok", r.stdout)


class TestOfdFlagRaceBounded(_Base):
    """O_NONBLOCK lives on the open file description shared with the
    child; a sibling thread spin-clearing it can park a supervisor
    worker in a fully blocking connect. The per-notification watchdog
    must answer the child's syscall (ETIMEDOUT) at a bounded deadline
    so the run is never held hostage."""

    def test_flag_race_park_is_deadline_bounded(self):
        import core.sandbox._unix_scope as uscope
        with patch.object(uscope, "_PRE_CONNECT_DEADLINE_S", 4.0):
            prog = textwrap.dedent("""
                import fcntl, os, socket, threading, time
                srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                srv.bind("/tmp/park")
                srv.listen(0)
                c1 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                c1.setblocking(False)
                try:
                    c1.connect("/tmp/park")  # occupy the backlog
                except BlockingIOError:
                    pass
                stop = False
                def clearer(fd):
                    while not stop:
                        try:
                            fcntl.fcntl(fd, fcntl.F_SETFL, 0)
                        except OSError:
                            return
                hung = False
                for i in range(120):
                    c = socket.socket(socket.AF_UNIX,
                                      socket.SOCK_STREAM)
                    t = threading.Thread(target=clearer,
                                         args=(c.fileno(),),
                                         daemon=True)
                    t.start()
                    time.sleep(0.001)
                    t0 = time.monotonic()
                    try:
                        c.connect("/tmp/park")
                        outcome = "CONNECTED"
                    except OSError as e:
                        outcome = "errno=%d" % (e.errno or 0)
                    dt = time.monotonic() - t0
                    c.close()
                    if dt > 2:
                        print("RACED dt=%.1f outcome=%s"
                              % (dt, outcome), flush=True)
                        hung = dt > 15
                        break
                stop = True
                print("UNBOUNDED" if hung else "BOUNDED", flush=True)
            """)
            r = self._spawn(prog, timeout=90)
        self.assertEqual(r.returncode, 0, (
            f"flag-race park held the run to its timeout: "
            f"rc={r.returncode} {r.stderr[-300:]!r}"
        ))
        self.assertIn("BOUNDED", r.stdout, (
            f"parked connect was not answered within the watchdog "
            f"deadline: {r.stdout!r}"
        ))
        self.assertNotIn("UNBOUNDED", r.stdout)

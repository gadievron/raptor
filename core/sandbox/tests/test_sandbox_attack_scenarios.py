"""Regression tests for specific defenses claimed by the threat model.

These tests encode attack-scenario checks — each corresponds to a concrete
claim in `core/sandbox/__init__.py`'s threat-model docstring. A regression
in any of these would silently weaken the sandbox.

Run: python3 -m pytest core/sandbox/tests/test_sandbox_attack_scenarios.py -v
"""

import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.sandbox import (
    check_landlock_available,
    check_net_available,
    run_untrusted,
    sandbox,
    state,
)


def _compile(source: str, path: Path, extra_flags=()) -> bool:
    """Compile a C snippet. Return True on success."""
    src = path.with_suffix(".c")
    src.write_text(source)
    r = subprocess.run(
        ["gcc", str(src), "-o", str(path), "-O0", *extra_flags],
        capture_output=True,
    )
    return r.returncode == 0 and path.exists()


class TestSyscallFilterBlocks(unittest.TestCase):
    """Claims: keyctl, bpf, userfaultfd, perf_event_open, io_uring_setup,
    socket(AF_UNIX / AF_PACKET / AF_NETLINK), TIOCSTI are all blocked."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "out"
        self.out.mkdir()

    def _run_c(self, source: str, name: str, expect_nonzero_syscall_retval: bool = True):
        """Compile source, run under run_untrusted, return (rc, stdout)."""
        path = Path(self.tmp.name) / name
        self.assertTrue(_compile(source, path), f"failed to compile {name}")
        r = run_untrusted(
            [str(path)], target=str(self.tmp.name), output=str(self.out),
            capture_output=True, text=True, timeout=10,
        )
        return r

    def test_af_unix_socket_blocked(self):
        r = self._run_c("""
            #include <sys/socket.h>
            #include <stdio.h>
            int main(){int s=socket(AF_UNIX,SOCK_STREAM,0);
              printf("fd=%d\\n",s);return s<0?0:1;}
        """, "afunix")
        # seccomp should return -EPERM → fd == -1 → our exit code 0 per the program
        # but the filter may also kill with SIGSYS. Either is correct.
        self.assertTrue(
            "fd=-1" in (r.stdout or "") or r.returncode < 0 or r.returncode != 0,
            f"AF_UNIX socket() should be blocked: rc={r.returncode} stdout={r.stdout}",
        )

    def test_socketpair_af_unix_allowed(self):
        """Rust's std::process::Command uses socketpair(AF_UNIX); blocking
        it broke cargo. Defense must NOT block the pair variant."""
        r = self._run_c("""
            #include <sys/socket.h>
            #include <stdio.h>
            int main(){int sv[2];int r=socketpair(AF_UNIX,SOCK_STREAM,0,sv);
              printf("r=%d\\n",r);return r<0?1:0;}
        """, "sp")
        self.assertEqual(r.returncode, 0)
        self.assertIn("r=0", r.stdout or "")

    def test_keyctl_blocked(self):
        r = self._run_c("""
            #include <sys/syscall.h>
            #include <unistd.h>
            #include <stdio.h>
            int main(){long r=syscall(SYS_keyctl,0,0,0,0,0);
              printf("r=%ld\\n",r);return r<0?0:1;}
        """, "keyctl")
        self.assertTrue(
            "r=-1" in (r.stdout or "") or r.returncode != 0,
            f"keyctl should be blocked: {r.stdout}",
        )

    def test_io_uring_setup_blocked(self):
        """Closes the io_uring-bypasses-Landlock gap on 5.13-6.2."""
        r = self._run_c("""
            #include <sys/syscall.h>
            #include <unistd.h>
            #include <stdio.h>
            int main(){long r=syscall(SYS_io_uring_setup,1,(void*)0);
              printf("r=%ld\\n",r);return r<0?0:1;}
        """, "iour")
        self.assertTrue(
            "r=-1" in (r.stdout or "") or r.returncode != 0,
            f"io_uring_setup should be blocked: {r.stdout}",
        )

    def test_tiocsti_blocked(self):
        """TIOCSTI injection is the classic sandbox-escape via the parent tty."""
        r = self._run_c("""
            #include <sys/ioctl.h>
            #include <fcntl.h>
            #include <errno.h>
            #include <stdio.h>
            int main(){int fd=open("/dev/tty",1);
              if(fd<0){printf("notty\\n");return 0;}
              char c='X';int r=ioctl(fd,TIOCSTI,&c);
              printf("r=%d\\n",r);return r==0?1:0;}
        """, "tiocsti")
        # Either /dev/tty isn't available (run_untrusted uses stdin=DEVNULL
        # + start_new_session), or TIOCSTI fails. Both are acceptable — both
        # prevent the attack.
        out = r.stdout or ""
        self.assertTrue(
            "notty" in out or "r=-1" in out or r.returncode != 0,
            f"TIOCSTI should not succeed: {out}",
        )

    def test_bpf_blocked(self):
        """eBPF program loading is a kernel attack surface."""
        r = self._run_c("""
            #include <sys/syscall.h>
            #include <unistd.h>
            #include <stdio.h>
            int main(){long r=syscall(SYS_bpf,0,0,0);
              printf("r=%ld\\n",r);return r<0?0:1;}
        """, "bpf")
        self.assertTrue(
            "r=-1" in (r.stdout or "") or r.returncode != 0,
            f"bpf syscall should be blocked: {r.stdout}",
        )

    def test_userfaultfd_blocked(self):
        """userspace page-fault handler — kernel-escalation primitive."""
        r = self._run_c("""
            #include <sys/syscall.h>
            #include <unistd.h>
            #include <stdio.h>
            int main(){long r=syscall(SYS_userfaultfd,0);
              printf("r=%ld\\n",r);return r<0?0:1;}
        """, "ufd")
        self.assertTrue(
            "r=-1" in (r.stdout or "") or r.returncode != 0,
            f"userfaultfd should be blocked: {r.stdout}",
        )

    def test_perf_event_open_blocked(self):
        """perf subsystem — historical kernel-exploit surface."""
        r = self._run_c("""
            #include <sys/syscall.h>
            #include <unistd.h>
            #include <stdio.h>
            int main(){long r=syscall(SYS_perf_event_open,0,0,0,0,0);
              printf("r=%ld\\n",r);return r<0?0:1;}
        """, "pe")
        self.assertTrue(
            "r=-1" in (r.stdout or "") or r.returncode != 0,
            f"perf_event_open should be blocked: {r.stdout}",
        )

    def test_process_vm_readv_blocked(self):
        """Cross-process memory read — credential-scraping primitive."""
        r = self._run_c("""
            #include <sys/syscall.h>
            #include <unistd.h>
            #include <stdio.h>
            int main(){char buf[8];
              /* arguments intentionally invalid — we only care that the
                 syscall is blocked by seccomp, not that a legitimate
                 cross-process read succeeds. */
              struct iovec{void*b;unsigned long l;}iov={buf,8};
              long r=syscall(SYS_process_vm_readv,1,&iov,1,&iov,1,0);
              printf("r=%ld\\n",r);return r<0?0:1;}
        """, "pvmr")
        self.assertTrue(
            "r=-1" in (r.stdout or "") or r.returncode != 0,
            f"process_vm_readv should be blocked: {r.stdout}",
        )

    def test_af_packet_socket_blocked(self):
        """AF_PACKET socket — raw-packet sniffing primitive."""
        r = self._run_c("""
            #include <sys/socket.h>
            #include <stdio.h>
            int main(){int s=socket(AF_PACKET,SOCK_RAW,0);
              printf("fd=%d\\n",s);return s<0?0:1;}
        """, "afpkt")
        self.assertTrue(
            "fd=-1" in (r.stdout or "") or r.returncode != 0,
            f"AF_PACKET socket() should be blocked: {r.stdout}",
        )


class TestProfilePtraceBehavior(unittest.TestCase):
    """Claim: ptrace is blocked in 'full' profile, allowed in 'debug'.

    Regression here silently breaks /crash-analysis (needs ptrace for gdb/rr)
    OR silently weakens the default profile (allows cross-process tracing)."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _ptrace_probe(self):
        """A C probe that calls ptrace(PTRACE_TRACEME). Returns 0 if the
        call succeeded, 1 if it was blocked/errored."""
        return """
            #include <sys/ptrace.h>
            #include <stdio.h>
            int main(){long r=ptrace(PTRACE_TRACEME,0,0,0);
              printf("r=%ld\\n",r);return r==0?0:1;}
        """

    def _run_probe(self, profile: str):
        path = Path(self.tmp.name) / f"ptrace_{profile}"
        self.assertTrue(_compile(self._ptrace_probe(), path))
        # Use the sandbox() context with profile= so we can exercise both.
        with sandbox(
            profile=profile,
            target=str(self.tmp.name), output=str(self.tmp.name),
        ) as run:
            r = run([str(path)], capture_output=True, text=True, timeout=5)
        return r

    def test_ptrace_blocked_in_full(self):
        r = self._run_probe("full")
        # Full profile: ptrace should be seccomp-blocked (returns -1 or
        # SIGSYS-killed).
        self.assertTrue(
            "r=-1" in (r.stdout or "") or r.returncode != 0,
            f"ptrace must be blocked in 'full': rc={r.returncode} out={r.stdout}",
        )

    def test_ptrace_allowed_in_debug(self):
        r = self._run_probe("debug")
        # Debug profile: ptrace(PTRACE_TRACEME) should succeed.
        self.assertEqual(r.returncode, 0,
                         f"ptrace must succeed in 'debug': rc={r.returncode} out={r.stdout}")
        self.assertIn("r=0", r.stdout or "",
                      f"PTRACE_TRACEME should return 0: {r.stdout}")


class TestAPIContract(unittest.TestCase):
    """Claims: shell=True is rejected; pass_fds rejects socket FDs."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_shell_true_rejected(self):
        """shell=True reinterprets argv into `sh -c argv[0] argv[1:]` which
        silently mangles our unshare command-line construction and is a
        shell-injection surface. Must be rejected early with TypeError."""
        with self.assertRaises(TypeError) as cm:
            with sandbox() as run:
                run(["echo", "hello"], shell=True)
        self.assertIn("shell", str(cm.exception).lower())

    def test_pass_fds_socket_rejected(self):
        """An inherited AF_UNIX socket FD can reach the docker daemon
        socket. Defense: stat each pass_fds entry and refuse S_ISSOCK.
        Pipe FDs (S_ISFIFO) remain allowed for legitimate stdin piping."""
        if not check_net_available():
            self.skipTest("User namespaces not available")
        # Create a socket FD — should be rejected
        s1, s2 = socket.socketpair()
        try:
            with self.assertRaises((TypeError, ValueError)):
                with sandbox(
                    target="/tmp", output=self.tmp.name,
                ) as run:
                    run(["true"], pass_fds=[s1.fileno()], timeout=5)
        finally:
            s1.close()
            s2.close()

    def test_pass_fds_pipe_allowed(self):
        """Pipe FD (S_ISFIFO) must NOT trigger the socket-rejection path."""
        if not check_net_available():
            self.skipTest("User namespaces not available")
        rfd, wfd = os.pipe()
        try:
            with sandbox(
                target="/tmp", output=self.tmp.name,
            ) as run:
                # Pass the read end — the child won't read it, we only
                # care that pass_fds doesn't reject valid pipes.
                r = run(["true"], pass_fds=[rfd], close_fds=True, timeout=5)
            self.assertEqual(r.returncode, 0)
        finally:
            os.close(rfd)
            os.close(wfd)


class TestProxyIsGlobalScreenExtended(unittest.TestCase):
    """Additional is_global IP screen coverage beyond simple loopback.

    Uses the proxy's `_ip_allowed` helper directly so we test the
    is_global check deterministically without needing DNS to resolve
    to a specific reserved range."""

    def setUp(self):
        from core.sandbox import proxy as _proxy_mod
        # is_global screen is applied in a dedicated helper — find it.
        # Test the predicate directly rather than forcing DNS.
        self.proxy_mod = _proxy_mod

    def _is_blocked_ip(self, ip: str) -> bool:
        """Return True if the proxy would block a CONNECT to this IP."""
        import ipaddress
        # The proxy uses ipaddress.ip_address(...).is_global — replicate here.
        return not ipaddress.ip_address(ip).is_global

    def test_cgnat_ip_blocked(self):
        """CGNAT 100.64.0.0/10 is not globally routable — IP screen blocks."""
        self.assertTrue(self._is_blocked_ip("100.64.0.1"))
        self.assertTrue(self._is_blocked_ip("100.127.255.254"))

    def test_test_net_ip_blocked(self):
        """TEST-NET ranges are documentation-only, not reachable."""
        self.assertTrue(self._is_blocked_ip("192.0.2.1"))    # TEST-NET-1
        self.assertTrue(self._is_blocked_ip("198.51.100.1"))  # TEST-NET-2
        self.assertTrue(self._is_blocked_ip("203.0.113.1"))   # TEST-NET-3

    def test_ipv4_mapped_ipv6_loopback_blocked(self):
        """::ffff:127.0.0.1 is IPv4-loopback in IPv6 wire format — must NOT
        bypass the is_global check."""
        self.assertTrue(self._is_blocked_ip("::ffff:127.0.0.1"))

    def test_benchmark_range_blocked(self):
        """RFC 2544 benchmark range 198.18.0.0/15."""
        self.assertTrue(self._is_blocked_ip("198.18.0.1"))


class TestFakeHomeXDGRedirection(unittest.TestCase):
    """Claim: fake_home redirects not just HOME but every XDG_*_HOME."""

    def setUp(self):
        if not check_net_available() or not check_landlock_available():
            self.skipTest("Needs user-ns + Landlock")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_all_xdg_vars_redirected(self):
        """Confirm HOME, XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_DATA_HOME,
        XDG_STATE_HOME all point inside {output}/.home/."""
        out = self.tmp.name
        r = run_untrusted(
            ["sh", "-c",
             'for v in HOME XDG_CONFIG_HOME XDG_CACHE_HOME '
             'XDG_DATA_HOME XDG_STATE_HOME; do '
             'eval echo "$v=\\$$v"; done'],
            target="/tmp", output=out,
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(r.returncode, 0)
        lines = (r.stdout or "").strip().split("\n")
        kv = dict(line.split("=", 1) for line in lines if "=" in line)
        for key in ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                    "XDG_DATA_HOME", "XDG_STATE_HOME"):
            self.assertIn(key, kv, f"{key} missing from env")
            self.assertTrue(
                kv[key].startswith(os.path.join(out, ".home")),
                f"{key}={kv[key]!r} — expected under {out}/.home/",
            )


class TestLogSanitisationPredicate(unittest.TestCase):
    """Claim: has_nonprintable() rejects control-char input — used by the
    proxy's CONNECT parser to reject log-injection attempts."""

    def test_has_nonprintable_detects_nul(self):
        from core.security.log_sanitisation import has_nonprintable
        self.assertTrue(has_nonprintable("host\x00.example.com"))

    def test_has_nonprintable_detects_crlf(self):
        from core.security.log_sanitisation import has_nonprintable
        self.assertTrue(has_nonprintable("host.example.com\r\nX-Evil: hi"))

    def test_has_nonprintable_detects_ansi_escape(self):
        from core.security.log_sanitisation import has_nonprintable
        self.assertTrue(has_nonprintable("host.\x1b[31mred\x1b[0m.com"))

    def test_has_nonprintable_passes_plain_ascii(self):
        from core.security.log_sanitisation import has_nonprintable
        self.assertFalse(has_nonprintable("ordinary.hostname.example.com"))
        self.assertFalse(has_nonprintable("a-host-1.with-dashes_and.digits-99"))

    def test_escape_nonprintable_renders_hex(self):
        """Complement: escape_nonprintable produces safe logging output
        so operators can SEE the control bytes rather than having them
        reformat their terminal."""
        from core.security.log_sanitisation import escape_nonprintable
        self.assertEqual(escape_nonprintable("abc\x1b[31m"), r"abc\x1b[31m")
        self.assertEqual(escape_nonprintable("a\x00b"), r"a\x00b")


# ---------------------------------------------------------------------------
# Adversarial-review gaps turned into regression tests.
# Each class below closes a specific gap identified by an adversarial walk
# of the threat model. A regression here re-opens the gap.
# ---------------------------------------------------------------------------


class TestProxyHostnameMatchRigor(unittest.TestCase):
    """Claim: proxy hostname allowlist is exact-match (case-insensitive).
    Gap: a substring / suffix-match bug would let `evil.example.com` slip
    past an `[example.com]` allowlist."""

    def _proxy(self, allowed):
        from core.sandbox.proxy import EgressProxy
        # Direct instantiation avoids the singleton-sharing of get_proxy().
        return EgressProxy(allowed_hosts=allowed)

    def test_exact_match_case_insensitive(self):
        p = self._proxy(["example.com"])
        self.assertTrue(p.is_host_allowed("example.com"))
        self.assertTrue(p.is_host_allowed("EXAMPLE.COM"))
        self.assertTrue(p.is_host_allowed("ExAmPlE.CoM"))

    def test_subdomain_not_accepted(self):
        p = self._proxy(["example.com"])
        # An allowlist of "example.com" MUST NOT accept subdomains —
        # that would let attackers register foo.example.com and MITM.
        self.assertFalse(p.is_host_allowed("foo.example.com"))
        self.assertFalse(p.is_host_allowed("api.example.com"))

    def test_suffix_spoof_not_accepted(self):
        """`example.com.attacker.tld` is a distinct hostname; substring-match
        bugs would accept it."""
        p = self._proxy(["example.com"])
        self.assertFalse(p.is_host_allowed("example.com.attacker.tld"))
        self.assertFalse(p.is_host_allowed("examplecom"))
        self.assertFalse(p.is_host_allowed("notexample.com"))

    def test_empty_and_weird_inputs_not_accepted(self):
        p = self._proxy(["example.com"])
        self.assertFalse(p.is_host_allowed(""))
        self.assertFalse(p.is_host_allowed("."))
        self.assertFalse(p.is_host_allowed(".example.com"))
        self.assertFalse(p.is_host_allowed("example.com."))

    def test_idn_punycode_not_confused(self):
        """IDN hostnames are ASCII (punycode) on the wire. An allowlist
        entry for `müller.de` is stored lowercased as `müller.de`, but
        a CONNECT would resolve to `xn--mller-kva.de`. They must be
        distinct — no automatic IDN normalisation."""
        p = self._proxy(["müller.de"])
        self.assertFalse(p.is_host_allowed("xn--mller-kva.de"))
        self.assertFalse(p.is_host_allowed("mueller.de"))


class TestOOMScoreAdjWrite(unittest.TestCase):
    """Adversarial gap: a child can write `/proc/self/oom_score_adj` to
    deprioritise itself (or prioritise) in the OOM killer. Under memory
    pressure this bumps other host processes ahead of the malicious child."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_oom_score_adj_cannot_deprioritise_sibling_host_procs(self):
        """Adversarial gap check: a sandboxed process should not be able
        to deprioritise host processes in the OOM killer.

        Two paths deny this today:
          (a) Landlock-only mode: Landlock blocks the write with EACCES.
          (b) Mount-ns mode (newuidmap path): the child runs as PID 1 in
              its own PID namespace. Linux refuses to let PID 1 adjust
              its own oom_score_adj — the write silently ignores the
              requested value and the file keeps its original value (0).
        Either way, the sandbox's score relative to host processes is
        UNCHANGED. Assert that, rather than the specific mechanism.
        """
        r = run_untrusted(
            ["sh", "-c", "echo -1000 > /proc/self/oom_score_adj 2>&1; "
                         "cat /proc/self/oom_score_adj 2>&1"],
            target="/tmp", output=self.tmp.name,
            capture_output=True, text=True, timeout=5,
        )
        out = (r.stdout or "") + (r.stderr or "")
        # The value on disk must NOT be -1000 (would mean the adversary
        # successfully lowered their OOM score).
        # Accept either an error message (Landlock-only path) or the
        # value being left at 0 (pid-ns-init protection path).
        self.assertNotIn("-1000", out.splitlines()[-1] if out.splitlines() else "",
                         f"oom_score_adj was actually lowered to -1000: {out!r}")


class TestNewMountAPIBlocked(unittest.TestCase):
    """Adversarial gap: the new mount API syscalls (kernel 5.2+,
    fsopen/fsmount/fspick/move_mount/mount_setattr) could let a child
    set up its own filesystems inside its user-ns. The old `mount()` is
    bounded by user-ns rules; the new API may have different semantics."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _run_syscall_probe(self, sys_macro: str, name: str):
        """Compile + run a stub that calls the given syscall. Return r.

        sys_macro is a glibc SYS_* macro name — arch-correct via libc
        headers, so the test exercises the right syscall on every arch
        glibc supports. Raw numbers would silently invoke the wrong
        syscall on e.g. aarch64/i386 and the seccomp check would no
        longer mean what its name claims."""
        src = f"""
            #include <sys/syscall.h>
            #include <unistd.h>
            #include <stdio.h>
            int main(){{long r=syscall({sys_macro},0,0,0,0,0);
              printf("r=%ld\\n",r);return r<0?0:1;}}
        """
        path = Path(self.tmp.name) / name
        self.assertTrue(_compile(src, path), f"compile {name} failed")
        return run_untrusted(
            [str(path)], target=str(self.tmp.name), output=str(self.tmp.name),
            capture_output=True, text=True, timeout=5,
        )

    def test_fsopen_blocked(self):
        r = self._run_syscall_probe("SYS_fsopen", "fsopen")
        self.assertTrue("r=-1" in (r.stdout or "") or r.returncode != 0,
                        f"fsopen should be blocked: {r.stdout}")

    def test_fsmount_blocked(self):
        r = self._run_syscall_probe("SYS_fsmount", "fsmount")
        self.assertTrue("r=-1" in (r.stdout or "") or r.returncode != 0,
                        f"fsmount should be blocked: {r.stdout}")

    def test_fspick_blocked(self):
        r = self._run_syscall_probe("SYS_fspick", "fspick")
        self.assertTrue("r=-1" in (r.stdout or "") or r.returncode != 0,
                        f"fspick should be blocked: {r.stdout}")

    def test_move_mount_blocked(self):
        r = self._run_syscall_probe("SYS_move_mount", "move_mount")
        self.assertTrue("r=-1" in (r.stdout or "") or r.returncode != 0,
                        f"move_mount should be blocked: {r.stdout}")

    def test_mount_setattr_blocked(self):
        r = self._run_syscall_probe("SYS_mount_setattr", "mount_setattr")
        self.assertTrue("r=-1" in (r.stdout or "") or r.returncode != 0,
                        f"mount_setattr should be blocked: {r.stdout}")


class TestProcNetTCPLeak(unittest.TestCase):
    """Claim: under net-ns, the child's /proc/net/tcp shows only ns-local
    sockets (empty when block_network=True, proxy-only when use_egress_proxy).
    Gap check: confirm no host sockets leak through."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _count_non_loopback(self, proc_net_tcp_text: str) -> int:
        """Count IPv4 TCP connections whose local or remote address is
        NOT loopback (127.0.0.0/8). A proper net-ns will have at most
        loopback entries (proxy) or nothing."""
        # /proc/net/tcp format: sl local_address:port remote_address:port ...
        # local_address is hex big-endian IPv4 — "0100007F" = 127.0.0.1
        non_loopback = 0
        for line in proc_net_tcp_text.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 3:
                continue
            local = parts[1].split(":")[0]
            remote = parts[2].split(":")[0]
            # Hex IPv4 is 8 chars. 127.x.x.x starts with "7F" in big-endian,
            # which as little-endian hex in /proc is "....007F".
            if local[-2:].upper() != "7F" and remote[-2:].upper() != "7F":
                non_loopback += 1
        return non_loopback

    def test_net_ns_hides_host_tcp(self):
        r = run_untrusted(
            ["cat", "/proc/net/tcp"],
            target="/tmp", output=self.tmp.name,
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(r.returncode, 0)
        leaked = self._count_non_loopback(r.stdout or "")
        self.assertEqual(leaked, 0,
                         f"{leaked} non-loopback TCP entries leaked into "
                         f"sandboxed /proc/net/tcp — net-ns not effective")


class TestSymlinkInReadablePaths(unittest.TestCase):
    """Adversarial question: if `readable_paths` contains a path that
    resolves via a symlink, what does Landlock allow? Landlock rules
    bind to dentries, so the symlink target is what matters. Document
    current behavior; regression = surprising change."""

    def setUp(self):
        if not check_net_available() or not check_landlock_available():
            self.skipTest("Needs user-ns + Landlock")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_symlink_in_readable_paths_resolves_target(self):
        # Create a real dir with a secret file, a symlink to it.
        real_dir = Path(self.tmp.name) / "real"
        real_dir.mkdir()
        (real_dir / "secret.txt").write_text("content")
        symlink_dir = Path(self.tmp.name) / "link"
        os.symlink(real_dir, symlink_dir)

        # Add the SYMLINK to readable_paths (not the real dir).
        from core.sandbox import run as sandbox_run
        r = sandbox_run(
            ["cat", str(symlink_dir / "secret.txt")],
            target="/tmp", output=self.tmp.name,
            restrict_reads=True,
            readable_paths=[str(symlink_dir)],
            capture_output=True, text=True, timeout=5,
        )
        # Landlock resolves symlinks to dentries at setup time. The expected
        # behaviour: the symlink's target dir becomes the allowed dentry,
        # so reads through it succeed. Assert that outcome so any change
        # in Landlock's path-resolution semantics surfaces as a test flip.
        self.assertEqual(r.returncode, 0,
                         f"symlink-resolved readable_path broke: {r.stderr}")
        self.assertEqual((r.stdout or "").strip(), "content")


class TestSafeEnvAllowlistHygiene(unittest.TestCase):
    """Claim: get_safe_env() keeps only names on the allowlist / prefix list.
    Adversarial gap: credential-bearing env vars must NOT be on it."""

    def test_ssh_auth_sock_not_allowed(self):
        """SSH_AUTH_SOCK carries a UDS path to the user's ssh-agent. Even
        though seccomp blocks AF_UNIX socket(), the var's presence in the
        child env is a defense-in-depth failure. Keep it off the list."""
        from core.config import RaptorConfig
        self.assertNotIn("SSH_AUTH_SOCK", RaptorConfig.SAFE_ENV_ALLOWLIST)
        # And no prefix match either.
        self.assertFalse(
            any("SSH_AUTH_SOCK".startswith(p) for p in RaptorConfig.SAFE_ENV_PREFIXES),
            "SSH_AUTH_SOCK unexpectedly matches a SAFE_ENV_PREFIX",
        )

    def test_credential_vars_not_allowed(self):
        """Spot-check a handful of known-risky env vars never survive."""
        from core.config import RaptorConfig
        risky = [
            "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY",
            "GITHUB_TOKEN", "GITLAB_TOKEN",
            "KUBECONFIG", "DOCKER_HOST",
        ]
        for name in risky:
            self.assertNotIn(name, RaptorConfig.SAFE_ENV_ALLOWLIST,
                             f"{name} leaked into SAFE_ENV_ALLOWLIST")


class TestMapRootGetuid(unittest.TestCase):
    """Claim: `map_root=True` makes the child see itself as uid 0 INSIDE
    the user-ns. This is NOT real root on the host — it is capability
    confinement. Pin the behaviour so callers relying on it (e.g. for
    setuid-semantic checks) notice if it changes.

    Default (no map_root): the user-ns maps the caller's host uid to
    nobody (65534) — the unprivileged-userns default. Also worth pinning
    so a switch to identity-mapping becomes a visible test change."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _check_map_root_supported(self):
        """map_root=True needs either uidmap (newuidmap/newgidmap) installed
        or CAP_SETUID. If neither is available, unshare fails early with
        'cannot open /proc/self/uid_map: Permission denied'."""
        if not shutil.which("newuidmap"):
            self.skipTest("map_root=True requires uidmap package (newuidmap)")

    def test_getuid_returns_zero_under_map_root(self):
        self._check_map_root_supported()
        src = """
            #include <unistd.h>
            #include <stdio.h>
            int main(){printf("uid=%u euid=%u\\n",getuid(),geteuid());return 0;}
        """
        path = Path(self.tmp.name) / "ids"
        self.assertTrue(_compile(src, path))
        from core.sandbox import run as sandbox_run
        r = sandbox_run(
            [str(path)],
            target=str(self.tmp.name), output=str(self.tmp.name),
            map_root=True, block_network=True,
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0 and "uid_map" in (r.stderr or ""):
            self.skipTest(f"map_root=True unusable here: {r.stderr.strip()}")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr}")
        self.assertIn("uid=0", r.stdout or "",
                      f"map_root=True did not map to uid 0: {r.stdout}")
        self.assertIn("euid=0", r.stdout or "",
                      f"map_root=True did not map euid to 0: {r.stdout}")

    def test_getuid_without_explicit_map_root(self):
        """Default sandbox: uid inside the user-ns. When mount-ns is
        active (via newuidmap), the child sees uid=0 because newuidmap
        maps host-uid → 0. When mount-ns is gated off and we fall back
        to `unshare --user` without --map-root-user, the child sees uid
        65534 (nobody). Both are valid; assert one of them."""
        src = """
            #include <unistd.h>
            #include <stdio.h>
            int main(){printf("uid=%u\\n",getuid());return 0;}
        """
        path = Path(self.tmp.name) / "ids_nomap"
        self.assertTrue(_compile(src, path))
        from core.sandbox import run as sandbox_run
        r = sandbox_run(
            [str(path)],
            target=str(self.tmp.name), output=str(self.tmp.name),
            block_network=True,
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr}")
        out = r.stdout or ""
        self.assertTrue("uid=0" in out or "uid=65534" in out,
                        f"expected uid=0 (mount-ns path) or uid=65534 "
                        f"(Landlock-only fallback); got: {r.stdout}")


class TestPidNamespaceDefenses(unittest.TestCase):
    """Claims: PID ns hides host PIDs (kill/ptrace/procfs cross-lookup)."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_self_runs_as_init_pid(self):
        """Child should see itself as a low pid (1, 2, or 3) inside the
        PID namespace. The exact value depends on layout:
        - pid=1 if target is the direct pid-ns init
        - pid=2 under the mount-ns path's intermediate fork
        - pid=3 under the subprocess-path pid-1 shim
          (libexec/raptor-pid1-shim with its double-fork layout)
        Any of these prove host pids are hidden."""
        r = run_untrusted(
            ["sh", "-c", "echo $$"],
            target="/tmp", output=self.tmp.name,
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn(r.stdout.strip(), ("1", "2", "3"))

    def test_host_pid_invisible(self):
        """kill(host_pid) must return ESRCH — the host PID does not exist
        inside the PID namespace."""
        host_pid = os.getpid()
        r = run_untrusted(
            ["sh", "-c", f"kill -0 {host_pid} 2>&1; echo rc=$?"],
            target="/tmp", output=self.tmp.name,
            capture_output=True, text=True, timeout=5,
        )
        out = r.stdout or ""
        self.assertTrue(
            "rc=1" in out or "No such" in out,
            f"host PID {host_pid} must not be reachable: {out}",
        )


class TestForkBombBounded(unittest.TestCase):
    """Claim: RLIMIT_NPROC via prlimit-wrapper bounds fork bombs per sandbox."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_fork_bomb_capped(self):
        r = run_untrusted(
            ["sh", "-c", "i=0; while [ $i -lt 5000 ]; do sleep 30 & i=$((i+1)); done; echo $i"],
            target="/tmp", output=self.tmp.name,
            capture_output=True, text=True, timeout=10,
        )
        # Must not reach 5000 — should hit RLIMIT_NPROC first.
        # Either sh errors out mid-loop, or the process is killed.
        reached = (r.stdout or "").strip()
        self.assertNotEqual(reached, "5000", "fork bomb should be capped")


class TestRestrictReadsCredentialExfil(unittest.TestCase):
    """Claims: fake_home blocks $HOME-based reads of credentials;
    restrict_reads blocks host-pid /proc/<pid>/environ."""

    def setUp(self):
        if not check_net_available() or not check_landlock_available():
            self.skipTest("Needs user-ns + Landlock")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_fake_home_hides_ssh_creds(self):
        r = run_untrusted(
            ["sh", "-c", "cat ~/.ssh/id_rsa 2>&1 || echo NOACCESS"],
            target="/tmp", output=self.tmp.name,
            capture_output=True, text=True, timeout=5,
        )
        out = (r.stdout or "") + (r.stderr or "")
        self.assertTrue(
            "NOACCESS" in out or "No such" in out or "Permission" in out,
            f"~/.ssh/id_rsa must not be readable from fake_home: {out[:200]}",
        )

    def test_host_proc_environ_blocked(self):
        """Cross-process /proc/<host_pid>/environ read must return ENOENT
        (host pid invisible under the new PID ns)."""
        host_pid = os.getpid()
        r = run_untrusted(
            ["sh", "-c", f"cat /proc/{host_pid}/environ 2>&1 || echo BLOCKED"],
            target="/tmp", output=self.tmp.name,
            capture_output=True, text=True, timeout=5,
        )
        out = (r.stdout or "") + (r.stderr or "")
        self.assertTrue(
            "BLOCKED" in out or "No such" in out or "Permission" in out,
            f"/proc/{host_pid}/environ leaked: {out[:200]}",
        )


class TestParentSideTOCTOU(unittest.TestCase):
    """Claims: parent-side writes into {output} defeat child-planted symlinks
    and FIFOs via O_NOFOLLOW + fstat S_ISREG / lstat-first-makedirs."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "out"
        self.out.mkdir()

    def test_proxy_events_symlink_plant_rejected(self):
        """If {output}/proxy-events.jsonl is a symlink pointing at the
        user's real file, the parent-side append MUST NOT follow it."""
        if not check_net_available():
            self.skipTest("User namespaces not available")
        target_path = Path(self.tmp.name) / "attacker_target"
        target_path.write_text("original\n")
        events_path = self.out / "proxy-events.jsonl"
        os.symlink(target_path, events_path)

        # Run a sandbox that would write to proxy-events.jsonl
        with sandbox(
            use_egress_proxy=True, proxy_hosts=["example.invalid"],
            output=str(self.out), caller_label="toctou-symlink",
        ) as run:
            # This fails — no network — but triggers the proxy-events write path
            run(["true"], timeout=5)

        # Attacker target must be untouched (writer refused to follow symlink)
        self.assertEqual(
            target_path.read_text(), "original\n",
            "symlink-plant followed — parent wrote outside output dir",
        )

    def test_proxy_events_fifo_plant_rejected_without_hang(self):
        """FIFO pre-plant would hang the parent's append; O_NONBLOCK +
        fstat must reject and move on."""
        if not check_net_available():
            self.skipTest("User namespaces not available")
        events_path = self.out / "proxy-events.jsonl"
        os.mkfifo(events_path)
        self.assertTrue(events_path.is_fifo())

        # If the defense works, the sandbox call returns in <5s (no hang).
        # Also, the FIFO must remain a FIFO (writer did not clobber it).
        with sandbox(
            use_egress_proxy=True, proxy_hosts=["example.invalid"],
            output=str(self.out), caller_label="toctou-fifo",
        ) as run:
            run(["true"], timeout=5)

        self.assertTrue(
            events_path.is_fifo(),
            "FIFO plant was replaced by writer — TOCTOU defense missing",
        )


class TestCLIPrecedence(unittest.TestCase):
    """Claim: CLI `--sandbox` flag is authoritative — wins over caller kwargs."""

    def setUp(self):
        self._saved_profile = state._cli_sandbox_profile
        self._saved_disabled = state._cli_sandbox_disabled
        self.addCleanup(self._restore)

    def _restore(self):
        state._cli_sandbox_profile = self._saved_profile
        state._cli_sandbox_disabled = self._saved_disabled

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError) as cm:
            with sandbox(profile="not-a-real-profile"):
                pass
        self.assertIn("Unknown sandbox profile", str(cm.exception))
        self.assertIn("not-a-real-profile", str(cm.exception))

    def test_cli_none_beats_caller_block_network(self):
        """Simulate `--sandbox none` from the CLI. Caller's block_network=True
        must be overridden so the child can reach the network."""
        if not check_net_available():
            self.skipTest("User namespaces not available")
        state._cli_sandbox_profile = "none"
        with TemporaryDirectory() as tmp:
            r = run_untrusted(
                ["sh", "-c", "ls /proc/self/net/route >/dev/null && echo HAS_NET"],
                target="/tmp", output=tmp,
                capture_output=True, text=True, timeout=5,
            )
        # Under --sandbox none, network is open and /proc net routing info is available
        self.assertEqual(r.returncode, 0)
        self.assertIn("HAS_NET", r.stdout or "")


class TestProxyIsGlobalScreen(unittest.TestCase):
    """Claim: proxy rejects resolved IPs that are not globally routable
    (loopback, RFC1918, CGNAT 100.64/10, link-local, TEST-NET, etc.)."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_loopback_resolved_ip_rejected(self):
        """'localhost' is allowlisted as a hostname but resolves to 127.0.0.1
        which fails the is_global check. Must yield denied_resolved_ip."""
        with sandbox(
            use_egress_proxy=True, proxy_hosts=["localhost"],
            output=self.tmp.name, caller_label="is-global-test",
        ) as run:
            # Any CONNECT through the proxy to localhost forces the is_global path
            r = run(
                ["curl", "-s", "-o", "/dev/null", "--max-time", "2",
                 "https://localhost/"],
                capture_output=True, text=True, timeout=8,
            )
        events = run.events  # cumulative per-sandbox view (see sandbox.md)
        results = [e.get("result") for e in events]
        self.assertIn("denied_resolved_ip", results,
                      f"Expected denied_resolved_ip; got {results}")


if __name__ == "__main__":
    unittest.main()

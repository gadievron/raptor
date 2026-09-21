"""Exotic socket-family denial: AF_VSOCK, AF_ALG and kin are not
creatable by sandboxed children in any profile.

The gap: the socket-family blocklist covered AF_UNIX / AF_NETLINK /
AF_PACKET only, so ``socket(AF_VSOCK, SOCK_STREAM)`` and
``socket(AF_ALG, SOCK_SEQPACKET)`` were creatable inside a
network-blocked sandbox — and vsock is NOT netns-scoped the way INET
is (the transport is per-VM), so a connect() from an empty netns still
reaches the live transport and any host-side vsock services. AF_ALG /
AF_KEY / AF_BLUETOOTH / AF_RDS / AF_TIPC are historically CVE-rich
kernel surfaces reachable with no capability from socket(2).

Post-fix contract, two directions:
- socket creation for the exotic families fails EPERM under every
  seccomp-filtered posture (the seccomp rule fires before the kernel's
  own family-support lookup, so the refusal is deterministic even for
  families the kernel has no module for);
- the workhorse families are unaffected (AF_INET TCP control).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import check_seccomp_available  # noqa: E402
from core.sandbox.tests.capability import requires_landlock

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp"),
    pytest.mark.skipif(
        not check_seccomp_available(),
        reason="libseccomp / seccomp filter unavailable on this host",
    ),
    pytest.mark.skipif(
        shutil.which("python3") is None, reason="python3 required",
    ),
]


_CHILD = textwrap.dedent("""
    import errno, socket, sys
    AF_KEY, AF_RDS, AF_TIPC, AF_BLUETOOTH = 15, 21, 30, 31
    AF_RXRPC = 33
    AF_ALG, AF_VSOCK, AF_SMC, AF_XDP = 38, 40, 43, 44
    probes = [
        ("vsock-stream", AF_VSOCK, socket.SOCK_STREAM, 0),
        ("vsock-dgram", AF_VSOCK, socket.SOCK_DGRAM, 0),
        ("alg-seqpacket", AF_ALG, socket.SOCK_SEQPACKET, 0),
        ("key-raw", AF_KEY, socket.SOCK_RAW, 2),
        ("rds-seqpacket", AF_RDS, socket.SOCK_SEQPACKET, 0),
        ("tipc-stream", AF_TIPC, socket.SOCK_STREAM, 0),
        # AF_RXRPC rides a kernel-internal UDP transport past the
        # block_udp rule (which matches caller-created INET DGRAM
        # sockets only) — both transport-family protos.
        ("rxrpc-dgram-inet", AF_RXRPC, socket.SOCK_DGRAM, 2),
        ("rxrpc-dgram-inet6", AF_RXRPC, socket.SOCK_DGRAM, 10),
        ("bluetooth-stream", AF_BLUETOOTH, socket.SOCK_STREAM, 1),
        # AF_SMC: kernel TCP-fallback stream egress that Landlock's
        # TCP-only connect hook never evaluates (SMCPROTO_SMC=0 /
        # SMCPROTO_SMC6=1) — reachable unprivileged via net-pf-43
        # module autoload on CONFIG_SMC=m kernels.
        ("smc-stream", AF_SMC, socket.SOCK_STREAM, 0),
        ("smc6-stream", AF_SMC, socket.SOCK_STREAM, 1),
        # The IPPROTO_SMC (256, kernel >= 6.4) spelling creates the
        # same SMC socket through the INET families — must be denied
        # by the protocol rule, not the family rule.
        ("inet-ipproto-smc", socket.AF_INET, socket.SOCK_STREAM, 256),
        ("inet6-ipproto-smc", socket.AF_INET6, socket.SOCK_STREAM, 256),
        ("xdp-raw", AF_XDP, socket.SOCK_RAW, 0),
    ]
    failed = []
    for name, fam, typ, proto in probes:
        try:
            s = socket.socket(fam, typ, proto)
        except OSError as e:
            code = "EPERM" if e.errno == errno.EPERM else (
                "errno=%d" % (e.errno or -1))
            print("%s DENIED %s" % (name, code), flush=True)
            if e.errno != errno.EPERM:
                failed.append(name)
        else:
            s.close()
            print("%s CREATED" % name, flush=True)
            failed.append(name)
    # Control: plain TCP socket creation must still work.
    try:
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.close()
        print("tcp-control OK", flush=True)
    except OSError as e:
        print("tcp-control FAILED errno=%d" % (e.errno or -1), flush=True)
        failed.append("tcp-control")
    sys.exit(1 if failed else 0)
""")


def _run_probes(**run_kwargs) -> subprocess.CompletedProcess:
    from core.sandbox import run

    return run(
        [sys.executable, "-c", _CHILD],
        capture_output=True,
        text=True,
        timeout=60,
        **run_kwargs,
    )


@requires_landlock
class TestExoticFamiliesDenied:
    def test_denied_under_default_posture(self):
        r = _run_probes(block_network=True)
        assert "CREATED" not in r.stdout, r.stdout + r.stderr
        assert "tcp-control OK" in r.stdout, r.stdout + r.stderr
        assert r.returncode == 0, r.stdout + r.stderr

    def test_denied_under_port_pin_posture(self):
        # block_network=False + allowed_tcp_ports (Landlock port pin /
        # proxy tier 2 shape) — the posture where the netns provides no
        # cover at all, so the family rules are the only control.
        r = _run_probes(block_network=False, allowed_tcp_ports=[443])
        assert "CREATED" not in r.stdout, r.stdout + r.stderr
        assert "tcp-control OK" in r.stdout, r.stdout + r.stderr
        assert r.returncode == 0, r.stdout + r.stderr


@requires_landlock
class TestWorkhorseFamiliesUnaffected:
    def test_unix_socketpair_still_works(self):
        # The family-rule extension must not disturb the AF_UNIX
        # story: socketpair (the documented legit shape everywhere)
        # keeps working under the default posture.
        child = (
            "import socket\n"
            "a, b = socket.socketpair(socket.AF_UNIX,"
            " socket.SOCK_STREAM)\n"
            "a.send(b'x'); assert b.recv(1) == b'x'\n"
            "print('UNIX-PAIR OK')\n"
        )
        from core.sandbox import run

        r = run(
            [sys.executable, "-c", child],
            block_network=True,
            capture_output=True, text=True, timeout=60,
        )
        assert "UNIX-PAIR OK" in r.stdout, r.stdout + r.stderr

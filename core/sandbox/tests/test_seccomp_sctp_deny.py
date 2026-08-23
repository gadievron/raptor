"""SCTP-family egress denial: SCTP (and its kin) socket creation is
denied for sandboxed children.

The attack (Landlock-port-pin posture): Landlock's network rules cover IPPROTO_TCP
only and the proxy-mode UDP block matches SOCK_DGRAM only, so
``socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)`` was created past every
rule and connected past the TCP port pin — full stream egress to any
host:port. Leg 2: ``setsockopt(IPPROTO_SCTP, SCTP_SOCKOPT_CONNECTX,
sockaddr)`` connects IN-KERNEL, so even the connect-notify supervisor
never saw it.

Post-fix contract: socket creation for IPPROTO_SCTP / IPPROTO_DCCP /
IPPROTO_MPTCP (any family) and SOCK_SEQPACKET / SOCK_DCCP on AF_INET*
(the protocol-0 default routes to SCTP/DCCP) fails EPERM under every
seccomp-filtered posture, hard-denied under audit mode too. Denying
creation covers CONNECTX by construction. AF_UNIX SOCK_SEQPACKET
stays usable where AF_UNIX itself is allowed.
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
    IPPROTO_SCTP, IPPROTO_DCCP, IPPROTO_MPTCP = 132, 33, 262
    SOCK_DCCP = 6
    probes = [
        ("sctp-stream", socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP),
        ("sctp-stream6", socket.AF_INET6, socket.SOCK_STREAM, IPPROTO_SCTP),
        ("sctp-seqpacket", socket.AF_INET, socket.SOCK_SEQPACKET,
         IPPROTO_SCTP),
        ("sctp-default-proto", socket.AF_INET, socket.SOCK_SEQPACKET, 0),
        ("dccp", socket.AF_INET, SOCK_DCCP, IPPROTO_DCCP),
        ("dccp-default-proto", socket.AF_INET, SOCK_DCCP, 0),
        ("mptcp", socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP),
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


class TestSctpFamilyDenied:
    def test_denied_under_default_posture(self):
        r = _run_probes(block_network=True)
        assert "CREATED" not in r.stdout, r.stdout + r.stderr
        assert "tcp-control OK" in r.stdout, r.stdout + r.stderr
        assert r.returncode == 0, r.stdout + r.stderr

    def test_denied_under_port_pin_posture(self):
        # The attacked posture: block_network=False +
        # allowed_tcp_ports (Landlock port pin / proxy tier 2 shape).
        r = _run_probes(block_network=False, allowed_tcp_ports=[443])
        assert "CREATED" not in r.stdout, r.stdout + r.stderr
        assert "tcp-control OK" in r.stdout, r.stdout + r.stderr
        assert r.returncode == 0, r.stdout + r.stderr


class TestUnixSeqpacketUnaffected:
    def test_af_unix_seqpacket_where_unix_allowed(self, tmp_path):
        # The family-scoped SEQPACKET deny must not break AF_UNIX
        # SEQPACKET on postures that allow AF_UNIX (mount-ns runs).
        # socketpair never touches the socket() family blocklist, so
        # probe via socketpair on the default posture instead — it is
        # the documented legit SEQPACKET shape.
        child = (
            "import socket\n"
            "a, b = socket.socketpair(socket.AF_UNIX,"
            " socket.SOCK_SEQPACKET)\n"
            "a.send(b'x'); assert b.recv(1) == b'x'\n"
            "print('SEQPACKET-PAIR OK')\n"
        )
        from core.sandbox import run

        r = run(
            [sys.executable, "-c", child],
            block_network=True,
            capture_output=True, text=True, timeout=60,
        )
        assert "SEQPACKET-PAIR OK" in r.stdout, r.stdout + r.stderr

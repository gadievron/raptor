"""Socket-family allowlist: socket(2)/socketpair(2) are deny-by-default
on the family axis for sandboxed children in every profile.

The gap history, in order: the family DENYLIST covered AF_UNIX /
AF_NETLINK / AF_PACKET only, so ``socket(AF_VSOCK, SOCK_STREAM)`` and
``socket(AF_ALG, SOCK_SEQPACKET)`` were creatable inside a
network-blocked sandbox — and vsock is NOT netns-scoped the way INET
is. The exotic-family extension then enumerated VSOCK/ALG/KEY/
BLUETOOTH/RDS/TIPC, missed AF_SMC (kernel-internal TCP clcsock that
Landlock's sk_is_tcp()-only connect hook never evaluates), the SMC fix
missed the IPPROTO_SMC spelling, and the re-seal missed AF_RXRPC (a
kernel-internal UDP transport past block_udp) — a live member at every
iteration. The allowlist inversion ends the enumeration game: families
outside {AF_INET, AF_INET6, AF_UNIX-per-profile} get EPERM by
construction, including families this kernel has no module for and
families future kernels grow.

The TYPE axis is inverted too — and the family iteration lesson
repeated there before the inversion: the kernel remaps
``socket(AF_INET, SOCK_PACKET, proto)`` to AF_PACKET *after* seccomp
evaluated the registers, so a live packet-capture socket rode in
behind the allowlist's most innocuous family while this file's sweep
pinned the type axis to {STREAM, DGRAM} and stayed green. Types
outside {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET} get EPERM by
construction now, and the sweep below covers the whole masked axis so
a value-level regression cannot hide again.

Contract, both directions:
- socket creation outside the family allowlist fails EPERM under
  every seccomp-filtered posture (the seccomp rule fires before the
  kernel's own family-support lookup, so the refusal is deterministic
  even for families the kernel has no module for — and for family
  numbers no kernel knows yet);
- socket creation outside the type allowlist fails EPERM on EVERY
  family — allowlisted families included (the SOCK_PACKET remap, raw
  sockets, and unassigned type values are refused before the kernel
  sees them);
- the workhorse families are unaffected (AF_INET/AF_INET6 TCP
  controls, AF_UNIX socketpair);
- socketpair(2) carries its own AF_UNIX-only family allowlist (the
  kernel implements socketpair for AF_TIPC too, and a connected
  non-UNIX pair half takes destination-bearing sendto — a same-class
  bypass of the socket(2) family rules) plus the same type allowlist.
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
    AF_APPLETALK, AF_KEY, AF_NETLINK, AF_PACKET = 5, 15, 16, 17
    AF_PPPOX, AF_RDS, AF_TIPC, AF_BLUETOOTH = 24, 21, 30, 31
    AF_RXRPC = 33
    AF_ALG, AF_NFC, AF_VSOCK, AF_KCM = 38, 39, 40, 41
    AF_QIPCRTR, AF_SMC, AF_XDP, AF_MCTP = 42, 43, 44, 45
    probes = [
        # The original exotic-denylist members — every judgment that
        # put them on the old list still holds under the allowlist.
        ("vsock-stream", AF_VSOCK, socket.SOCK_STREAM, 0),
        ("vsock-dgram", AF_VSOCK, socket.SOCK_DGRAM, 0),
        ("alg-seqpacket", AF_ALG, socket.SOCK_SEQPACKET, 0),
        ("key-raw", AF_KEY, socket.SOCK_RAW, 2),
        ("rds-seqpacket", AF_RDS, socket.SOCK_SEQPACKET, 0),
        ("tipc-stream", AF_TIPC, socket.SOCK_STREAM, 0),
        ("netlink-route", AF_NETLINK, socket.SOCK_RAW, 0),
        ("packet-dgram", AF_PACKET, socket.SOCK_DGRAM, 0),
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
        # Families the DENYLIST left creatable (live-verified before
        # the inversion: pppox/kcm/qipcrtr/mctp probes printed CREATED
        # inside a network-blocked sandbox) — the allowlist denies
        # them by construction, not by enumeration.
        ("appletalk-dgram", AF_APPLETALK, socket.SOCK_DGRAM, 0),
        ("pppox-stream", AF_PPPOX, socket.SOCK_STREAM, 0),
        ("nfc-seqpacket", AF_NFC, socket.SOCK_SEQPACKET, 0),
        ("kcm-seqpacket", AF_KCM, socket.SOCK_SEQPACKET, 0),
        ("qipcrtr-dgram", AF_QIPCRTR, socket.SOCK_DGRAM, 0),
        ("mctp-dgram", AF_MCTP, socket.SOCK_DGRAM, 0),
        # SOCK_PACKET (type 10, pre-Linux-2.2 legacy): the kernel
        # remaps AF_INET+SOCK_PACKET to AF_PACKET AFTER seccomp
        # evaluated the registers, so the family allowlist alone
        # admitted a live packet-capture socket through its most
        # innocuous member. Must be EPERM via the TYPE allowlist
        # (the filter's verdict, before the remap can run).
        ("inet-sock-packet", socket.AF_INET, 10, 0x0300),
        ("inet6-sock-packet", socket.AF_INET6, 10, 0x0300),
        # SOCK_RDM on an allowlisted family — same class one value
        # over; no INET handler exists, but the verdict must be the
        # filter's deterministic EPERM, not the kernel's
        # ESOCKTNOSUPPORT.
        ("inet-rdm", socket.AF_INET, socket.SOCK_RDM, 0),
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


# Deny-by-default sweep over BOTH filtered socket() axes.
#
# Family axis: EVERY value 0..63 must be EPERM except the allowlisted
# workhorses — including values above the kernel's AF_MAX (no kernel
# handler exists; the filter must still answer EPERM, not
# EAFNOSUPPORT, so the verdict is the filter's, made before the
# kernel's family lookup) and high-bit-garnished spellings of ALLOWED
# families (the kernel would truncate to the allowed family; the GE
# ceiling rule refuses the garnish fail-closed). AF_UNIX is expected
# EPERM here because this child runs on the preexec-only lane, where
# AF_UNIX stays outside the allowlist.
#
# Type axis: for every family, EVERY type value 0..15 must be EPERM
# except SOCK_STREAM/SOCK_DGRAM on an allowed family — with and
# without SOCK_CLOEXEC / SOCK_NONBLOCK flag garnish (the rules mask
# to SOCK_TYPE_MASK, so garnish must change nothing in either
# direction). The full-axis sweep exists because a VALUE-pinned
# oracle (STREAM/DGRAM only) was blind by construction to the
# AF_INET+SOCK_PACKET kernel remap that resurrected packet capture
# behind the family allowlist: a whole-axis complement is the only
# shape that kills the class, not the instance. SOCK_SEQPACKET (5)
# is deliberately NOT expected creatable here: on AF_INET* it
# defaults to SCTP and the family-scoped type rules refuse it; on
# every other family the family axis refuses it first.
_SWEEP_CHILD = textwrap.dedent("""
    import ctypes, errno, os, socket, sys
    libc = ctypes.CDLL(None, use_errno=True)
    ALLOWED_FAM = {2, 10}
    ALLOWED_TYPE = {socket.SOCK_STREAM, socket.SOCK_DGRAM}
    CLO = 0x80000   # SOCK_CLOEXEC
    NB = 0x800      # SOCK_NONBLOCK
    types = list(range(16)) + [
        socket.SOCK_STREAM | CLO, socket.SOCK_DGRAM | CLO | NB,
        socket.SOCK_RAW | CLO, 10 | CLO, 10 | NB, 5 | CLO,
    ]
    failed = []
    for fam in list(range(64)) + [2 | (1 << 32), 10 | (1 << 32)]:
        for typ in types:
            fd = libc.syscall(ctypes.c_long(41),
                              ctypes.c_ulong(fam),
                              ctypes.c_ulong(typ), ctypes.c_ulong(0))
            if fd >= 0:
                os.close(fd)
                created = True
                err = 0
            else:
                created = False
                err = ctypes.get_errno()
            expect_ok = fam in ALLOWED_FAM and (typ & 0xf) in ALLOWED_TYPE
            if expect_ok:
                # Workhorse family+type: creation must succeed.
                if not created:
                    failed.append("fam=%d typ=%d errno=%d" % (fam, typ, err))
            elif created or err != errno.EPERM:
                failed.append("fam=%d typ=%d %s" % (
                    fam, typ, "CREATED" if created else "errno=%d" % err))
    if failed:
        print("SWEEP FAILED: " + "; ".join(failed[:20]), flush=True)
        sys.exit(1)
    print("SWEEP OK", flush=True)
""")


def _run_probes(child: str = _CHILD, **run_kwargs) -> subprocess.CompletedProcess:
    from core.sandbox import run

    return run(
        [sys.executable, "-c", child],
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
class TestFamilyAllowlistInversion:
    """The deny-by-default contract itself — not a list of known-bad
    families but the complement: nothing outside the allowlist is
    creatable, whatever its number."""

    def test_full_family_sweep_denied_by_default(self):
        # x86_64 syscall numbers baked into the sweep child.
        import platform
        if platform.machine() != "x86_64":
            pytest.skip("sweep child uses the x86_64 SYS_socket number")
        r = _run_probes(child=_SWEEP_CHILD, block_network=True)
        assert "SWEEP OK" in r.stdout, r.stdout + r.stderr
        assert r.returncode == 0, r.stdout + r.stderr

    def test_socketpair_family_allowlist(self):
        # socketpair(AF_TIPC, SOCK_SEQPACKET) is the kernel's other
        # ops->socketpair implementation — must be EPERM (the filter's
        # verdict, before any module lookup), while the AF_UNIX
        # STREAM shape keeps working.
        child = textwrap.dedent("""
            import ctypes, errno, socket, sys
            libc = ctypes.CDLL(None, use_errno=True)
            sv = (ctypes.c_int * 2)()
            r = libc.socketpair(30, socket.SOCK_SEQPACKET, 0, sv)
            e = ctypes.get_errno() if r != 0 else 0
            if r == 0 or e != errno.EPERM:
                print("tipc-socketpair %s" % (
                    "CREATED" if r == 0 else "errno=%d" % e), flush=True)
                sys.exit(1)
            print("tipc-socketpair DENIED EPERM", flush=True)
            # Type axis on socketpair: SOCK_PACKET (10) on the
            # allowlisted AF_UNIX family must be the filter's EPERM,
            # not the kernel's ESOCKTNOSUPPORT — symmetry with the
            # socket(2) type allowlist.
            r = libc.socketpair(socket.AF_UNIX, 10, 0, sv)
            e = ctypes.get_errno() if r != 0 else 0
            if r == 0 or e != errno.EPERM:
                print("unix-packet-socketpair %s" % (
                    "CREATED" if r == 0 else "errno=%d" % e), flush=True)
                sys.exit(1)
            print("unix-packet-socketpair DENIED EPERM", flush=True)
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            a.send(b"x"); assert b.recv(1) == b"x"
            print("UNIX-PAIR OK", flush=True)
        """)
        r = _run_probes(child=child, block_network=True)
        assert "tipc-socketpair DENIED EPERM" in r.stdout, (
            r.stdout + r.stderr)
        assert "unix-packet-socketpair DENIED EPERM" in r.stdout, (
            r.stdout + r.stderr)
        assert "UNIX-PAIR OK" in r.stdout, r.stdout + r.stderr
        assert r.returncode == 0, r.stdout + r.stderr


@requires_landlock
class TestWorkhorseFamiliesUnaffected:
    def test_unix_socketpair_still_works(self):
        # The family-rule inversion must not disturb the AF_UNIX
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

    def test_inet6_control_still_works(self):
        child = (
            "import socket\n"
            "for fam in (socket.AF_INET, socket.AF_INET6):\n"
            "    s = socket.socket(fam, socket.SOCK_STREAM)\n"
            "    s.close()\n"
            "print('INET-CONTROLS OK')\n"
        )
        from core.sandbox import run

        r = run(
            [sys.executable, "-c", child],
            block_network=True,
            capture_output=True, text=True, timeout=60,
        )
        assert "INET-CONTROLS OK" in r.stdout, r.stdout + r.stderr

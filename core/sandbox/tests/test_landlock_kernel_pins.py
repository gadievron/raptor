"""Landlock kernel pins: the availability probe against an independent
oracle, and a per-access-right denial matrix on the real kernel.

The probe-vs-oracle test closes a structural blind spot: every
Landlock-exercising test skips when ``check_landlock_available()``
says no, so a regression INSIDE the probe (wrong syscall number,
drifted self-test bit, inverted enforcement check) converts the whole
enforcement suite into skips instead of failures. The kernel's own
LSM list (``/sys/kernel/security/lsm``) is the independent truth: when
the kernel says Landlock is active, the probe must agree.

The denial matrix runs real children under ``_make_landlock_preexec``
and probes one operation per handled access right, in both directions
(denied outside the grants, allowed inside them).
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import landlock as ll  # noqa: E402
from core.sandbox import state  # noqa: E402

pytestmark = [
    pytest.mark.linux_native,
    pytest.mark.skipif(sys.platform != "linux",
                       reason="Landlock is Linux-only"),
]

_LSM_LIST = Path("/sys/kernel/security/lsm")


def _kernel_has_landlock() -> bool | None:
    """Independent oracle: is the Landlock LSM active in this kernel?
    None when the oracle itself is unavailable (securityfs unmounted /
    unreadable)."""
    try:
        return "landlock" in _LSM_LIST.read_text().split(",")
    except OSError:
        return None


def test_probe_agrees_with_kernel_lsm_oracle() -> None:
    """When the kernel's own LSM list says Landlock is active (and the
    arch is supported), the availability probe must return True from a
    cold cache. A probe that fails here silently downgrades every
    sandboxed run on a fully capable host — and flips every
    availability-gated enforcement test into a skip."""
    oracle = _kernel_has_landlock()
    if oracle is None:
        pytest.skip("LSM oracle unavailable (securityfs not readable)")
    if not oracle:
        pytest.skip("kernel built without the Landlock LSM")
    if not ll._LANDLOCK_ARCH_OK:
        pytest.skip("unsupported syscall table on this arch")
    with state._cache_lock:
        old = state._landlock_cache
        state._landlock_cache = None
    try:
        assert ll.check_landlock_available() is True, (
            "kernel LSM list includes landlock but the availability "
            "probe reports unavailable — probe or functional self-test "
            "regression"
        )
        assert ll._get_landlock_abi() >= 1
    finally:
        with state._cache_lock:
            state._landlock_cache = old


def _abi() -> int:
    if not ll.check_landlock_available():
        pytest.skip("Landlock unavailable on this host")
    return ll._get_landlock_abi()


def _run_probe(script: str, preexec, timeout: int = 60):
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        preexec_fn=preexec, capture_output=True, text=True,
        timeout=timeout,
    )


def test_write_class_denial_matrix(tmp_path: Path) -> None:
    """One probe per handled write-class right, both directions:
    inside the writable grant each operation succeeds; outside it each
    is denied with EACCES. A single drifted access bit fails exactly
    one row of this matrix."""
    abi = _abi()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("x")
    (outside / "sub").mkdir()
    fn = ll._make_landlock_preexec([str(allowed)])
    script = f"""
    import errno, os, sys
    allowed = {str(allowed)!r}
    outside = {str(outside)!r}
    abi = {abi}
    failures = []

    def expect_ok(name, op):
        try:
            op()
        except OSError as e:
            failures.append("%s unexpectedly failed errno=%s" % (name, e.errno))

    def expect_eacces(name, op):
        try:
            op()
        except OSError as e:
            if e.errno != errno.EACCES:
                failures.append("%s wrong errno=%s" % (name, e.errno))
        else:
            failures.append("%s unexpectedly ALLOWED" % name)

    # inside the grant: the full write class works
    expect_ok("write-in", lambda: open(allowed + "/f", "w").close())
    expect_ok("mkdir-in", lambda: os.mkdir(allowed + "/d"))
    expect_ok("symlink-in", lambda: os.symlink("t", allowed + "/s"))
    expect_ok("fifo-in", lambda: os.mkfifo(allowed + "/p"))
    expect_ok("unlink-in", lambda: os.unlink(allowed + "/f"))
    expect_ok("rmdir-in", lambda: os.rmdir(allowed + "/d"))
    # outside: each write-class right is individually denied
    expect_eacces("write-out",
                  lambda: open(outside + "/new", "w").close())
    expect_eacces("mkdir-out", lambda: os.mkdir(outside + "/d2"))
    expect_eacces("symlink-out",
                  lambda: os.symlink("t", outside + "/s2"))
    expect_eacces("fifo-out", lambda: os.mkfifo(outside + "/p2"))
    expect_eacces("unlink-out",
                  lambda: os.unlink(outside + "/victim.txt"))
    expect_eacces("rmdir-out", lambda: os.rmdir(outside + "/sub"))
    if abi >= 3:
        expect_eacces("truncate-out",
                      lambda: os.truncate(outside + "/victim.txt", 0))
    # reads stay unrestricted in this posture
    expect_ok("read-out",
              lambda: open(outside + "/victim.txt", "rb").close())
    # the /dev/null bit-bucket keeps working (shell `>/dev/null`
    # opens O_WRONLY|O_TRUNC — the device rule must carry TRUNCATE
    # where the kernel supports it)
    expect_ok("devnull",
              lambda: os.close(os.open("/dev/null",
                                       os.O_WRONLY | os.O_TRUNC)))
    if failures:
        print("; ".join(failures))
        sys.exit(1)
    print("MATRIX-OK")
    """
    r = _run_probe(script, fn)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "MATRIX-OK" in r.stdout


def test_refer_cross_directory_rename_matrix(tmp_path: Path) -> None:
    """REFER, both directions. When a Landlock domain handles fs
    accesses, cross-directory re-parenting is denied BY DEFAULT unless
    the REFER right is handled and granted (kernel-documented
    historical semantics) — so a drifted/omitted REFER bit shows up as
    a rename failure between two fully granted directories. And
    re-parenting INTO an ungranted tree must stay denied."""
    abi = _abi()
    if abi < 2:
        pytest.skip("REFER needs ABI >= 2")
    a = tmp_path / "a"
    b = tmp_path / "b"
    outside = tmp_path / "outside"
    a.mkdir()
    b.mkdir()
    outside.mkdir()
    (a / "f").write_text("x")
    (a / "g").write_text("x")
    fn = ll._make_landlock_preexec([str(a), str(b)])
    script = f"""
    import errno, os, sys
    # granted -> granted: REFER is in the write mask, so this works
    try:
        os.rename({str(a / "f")!r}, {str(b / "f")!r})
    except OSError as e:
        print("granted-rename DENIED errno=%d" % e.errno)
        sys.exit(2)
    # granted -> ungranted tree: denied
    try:
        os.rename({str(a / "g")!r}, {str(outside / "g")!r})
    except OSError as e:
        sys.exit(0 if e.errno in (errno.EACCES, errno.EXDEV) else 3)
    print("escape-rename ALLOWED")
    sys.exit(4)
    """
    r = _run_probe(script, fn)
    assert r.returncode == 0, (
        f"REFER rename matrix failed (rc={r.returncode}): "
        + r.stdout + r.stderr
    )


def test_read_restriction_matrix(tmp_path: Path) -> None:
    _abi()
    readable = tmp_path / "readable"
    readable.mkdir()
    (readable / "ok.txt").write_text("ok")
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "cred.txt").write_text("hunter2")
    out = tmp_path / "out"
    out.mkdir()
    # Interpreter + libs (incl. a venv prefix) must stay readable for
    # the child interpreter to start.
    fn = ll._make_landlock_preexec(
        [str(out)],
        readable_paths=[str(readable), "/usr", "/lib", "/lib64", "/etc",
                        "/proc", "/dev/urandom",
                        sys.prefix, sys.base_prefix],
    )
    script = f"""
    import errno, sys
    try:
        open({str(secret / "cred.txt")!r})
    except OSError as e:
        denied = e.errno == errno.EACCES
    else:
        denied = False
    open({str(readable / "ok.txt")!r}).close()
    open({str(out)!r} + "/w", "w").close()
    sys.exit(0 if denied else 1)
    """
    r = _run_probe(script, fn)
    assert r.returncode == 0, (
        "read outside the allowlist was not denied: "
        + r.stdout + r.stderr
    )


def _listener() -> tuple[socket.socket, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    return s, s.getsockname()[1]


_CONNECT = """
import errno, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(("127.0.0.1", {port}))
except OSError as e:
    print("DENIED errno=%d" % (e.errno or -1))
    sys.exit(2 if e.errno == errno.EACCES else 3)
print("CONNECTED")
sys.exit(0)
"""


def test_tcp_connect_policy_matrix(tmp_path: Path) -> None:
    """The three net postures of the preexec builder, on the wire:

    * plain write policy — TCP connect UNTOUCHED (the deny is opt-in,
      never a side effect);
    * deny_all_tcp_connect — every connect EACCES, loopback included;
    * allowed_tcp_ports — the listed port connects, others EACCES.
    """
    if _abi() < 4:
        pytest.skip("CONNECT_TCP needs ABI >= 4")
    srv, port = _listener()
    srv2, port2 = _listener()
    try:
        wdir = tmp_path / "w"
        wdir.mkdir()
        # default: no net handling
        r = _run_probe(_CONNECT.format(port=port),
                       ll._make_landlock_preexec([str(wdir)]))
        assert r.returncode == 0, (
            "plain write policy blocked TCP connect: "
            + r.stdout + r.stderr
        )
        # deny-all
        r = _run_probe(
            _CONNECT.format(port=port),
            ll._make_landlock_preexec([str(wdir)],
                                      deny_all_tcp_connect=True))
        assert r.returncode == 2, (
            "deny_all_tcp_connect did not EACCES the connect: "
            + r.stdout + r.stderr
        )
        # port allowlist: listed port connects...
        fn = ll._make_landlock_preexec([str(wdir)],
                                       allowed_tcp_ports=[port])
        r = _run_probe(_CONNECT.format(port=port), fn)
        assert r.returncode == 0, (
            "allowlisted port was denied: " + r.stdout + r.stderr
        )
        assert "TCP port allow-rule failed" not in r.stderr, (
            "clean net-rule install must not warn: " + r.stderr
        )
        # ...and an unlisted one is denied.
        fn = ll._make_landlock_preexec([str(wdir)],
                                       allowed_tcp_ports=[port])
        r = _run_probe(_CONNECT.format(port=port2), fn)
        assert r.returncode == 2, (
            "non-allowlisted port connected: " + r.stdout + r.stderr
        )
    finally:
        srv.close()
        srv2.close()


def test_abstract_unix_socket_scoping(tmp_path: Path) -> None:
    """ABI >= 6 scoping: a scoped child cannot connect an ABSTRACT
    unix socket owned by a process outside its Landlock domain. This
    pins the abstract-unix scope bit specifically — signal scoping is
    a different bit; a swap would leave the abstract-socket channel
    open while this test's connect suddenly succeeds."""
    if _abi() < 6:
        pytest.skip("scoping needs ABI >= 6")
    name = f"\0raptor-mutgaps-{os.getpid()}"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(name)
    srv.listen(2)
    try:
        wdir = tmp_path / "w"
        wdir.mkdir()
        fn = ll._make_landlock_preexec([str(wdir)])
        script = f"""
        import errno, socket, sys
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect("\\0" + {name[1:]!r})
        except OSError as e:
            sys.exit(2 if e.errno == errno.EPERM else 3)
        sys.exit(0)
        """
        r = _run_probe(script, fn)
        assert r.returncode == 2, (
            "abstract unix connect outside the Landlock domain was not "
            f"EPERM-scoped (rc={r.returncode}): " + r.stdout + r.stderr
        )
    finally:
        srv.close()


def test_unopenable_writable_grant_is_nonfatal_on_kernel(
        tmp_path: Path) -> None:
    """A grant path that vanishes between validation and the child's
    pinned open is skipped with a named stderr diagnostic — the child
    still runs (the path just falls under the global deny)."""
    _abi()
    wdir = tmp_path / "w"
    wdir.mkdir()
    ghost = tmp_path / "ghost"  # never created
    fn = ll._make_landlock_preexec([str(wdir), str(ghost)])
    r = _run_probe("print('ALIVE')", fn)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ALIVE" in r.stdout
    assert "could not be opened" in r.stderr
    assert str(ghost) in r.stderr

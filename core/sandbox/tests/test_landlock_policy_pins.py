"""Landlock policy pins: UAPI constants, availability-probe direction,
ABI-gated masks, and every fail-closed branch of the install closure.

Three layers, no real Landlock enforcement in any of them:

* **UAPI pins** — the access-right bits, scope bits, and syscall
  numbers the module hardcodes are compared against the kernel's OWN
  headers (``/usr/include/linux/landlock.h``, asm-generic unistd),
  parsed by name. A drifted bit restricts a different operation than
  intended; a drifted syscall number makes the availability probe fail
  and every consumer silently degrade. Values are read out of the
  preexec closure's cells — the exact numbers the forked child will
  hand the kernel.

* **Probe direction** — ``check_landlock_available()`` must fail
  CLOSED (report unavailable) on every probe-failure shape: negative
  ABI, zero ABI, a raising libc, a failing functional self-test. A
  fail-open probe overstates the delivered posture on hosts where the
  kernel would reject the ruleset.

* **Install-closure branches** — ``_apply_landlock`` runs in a forked
  child where its only allowed reporting channels are byte-writes to
  stderr (fd 2) and the documented exit codes. The closure's captured
  cells (libc handle, os.write/close, the pinned grant opener) are
  swapped for recorders so every branch — create failure, per-rule
  add failures, prctl/restrict failure, unexpected exception — is
  driven in-process and asserted against BOTH lanes (fail_raise
  raising vs the async-signal-safe exit-126 convention).
"""

from __future__ import annotations

import contextlib
import ctypes
import re
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import landlock as ll  # noqa: E402
from core.sandbox import state  # noqa: E402
from core.sandbox.exit_codes import SANDBOX_EXIT_LANDLOCK_DOWNGRADE  # noqa: E402

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock is Linux-only")

_LANDLOCK_H = Path("/usr/include/linux/landlock.h")
_UNISTD_CANDIDATES = (
    Path("/usr/include/asm/unistd_64.h"),
    Path("/usr/include/asm-generic/unistd.h"),
)


# UAPI bits frozen at introduction, backfilled ONLY when the installed
# header PREDATES them: distro headers track the distro kernel, not the
# newest ABI — e.g. 6.8-era headers lack the ABI-5 IOCTL_DEV right
# (kernel 6.10) and the ABI-6 scope bits (kernel 6.12), and dict access
# on the parsed header KeyError'd the pins there. A released Landlock
# bit never changes value, so the literal is as authoritative as the
# header line it mirrors; header values always win (setdefault), so
# drift between a real header and the module under test still trips
# the pins.
_UAPI_BACKFILL = {
    "LANDLOCK_ACCESS_FS_IOCTL_DEV": 1 << 15,        # ABI 5, kernel 6.10
    "LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET": 1 << 0,  # ABI 6, kernel 6.12
    "LANDLOCK_SCOPE_SIGNAL": 1 << 1,                # ABI 6, kernel 6.12
}


def _header_defines(path: Path) -> dict[str, int]:
    """Parse ``#define NAME (1ULL << N)`` / ``#define NAME N`` pairs."""
    out: dict[str, int] = {}
    for line in path.read_text().splitlines():
        m = re.match(
            r"#define\s+(\w+)\s+\(?(\d+)ULL\s*<<\s*(\d+)\)?", line)
        if m:
            out[m.group(1)] = int(m.group(2)) << int(m.group(3))
            continue
        m = re.match(r"#define\s+(\w+)\s+(\d+)\s*$", line)
        if m:
            out[m.group(1)] = int(m.group(2))
    for name, bit in _UAPI_BACKFILL.items():
        out.setdefault(name, bit)
    return out


@contextlib.contextmanager
def _seeded_abi(abi: int) -> Iterator[None]:
    """Pin the process-wide Landlock probe cache to a given ABI."""
    with state._cache_lock:
        old = state._landlock_cache
        state._landlock_cache = abi
    try:
        yield
    finally:
        with state._cache_lock:
            state._landlock_cache = old


def _cells(fn: Any) -> dict[str, Any]:
    return dict(zip(fn.__code__.co_freevars, fn.__closure__))


def _cell(fn: Any, name: str) -> Any:
    return _cells(fn)[name].cell_contents


# ---------------------------------------------------------------------------
# UAPI constant pins (header-derived, skipped where headers are absent)
# ---------------------------------------------------------------------------


requires_landlock_header = pytest.mark.skipif(
    not _LANDLOCK_H.exists(), reason="kernel UAPI header not installed")


@requires_landlock_header
def test_write_mask_matches_kernel_uapi(tmp_path: Path) -> None:
    """The full-ABI handled write mask is exactly the kernel's named
    write-class rights: WRITE_FILE, REMOVE_*, MAKE_* (all seven node
    types), REFER, TRUNCATE, IOCTL_DEV. Any single drifted bit either
    restricts the wrong operation or silently stops restricting one."""
    h = _header_defines(_LANDLOCK_H)
    expected = (
        h["LANDLOCK_ACCESS_FS_WRITE_FILE"]
        | h["LANDLOCK_ACCESS_FS_REMOVE_DIR"]
        | h["LANDLOCK_ACCESS_FS_REMOVE_FILE"]
        | h["LANDLOCK_ACCESS_FS_MAKE_CHAR"]
        | h["LANDLOCK_ACCESS_FS_MAKE_DIR"]
        | h["LANDLOCK_ACCESS_FS_MAKE_REG"]
        | h["LANDLOCK_ACCESS_FS_MAKE_SOCK"]
        | h["LANDLOCK_ACCESS_FS_MAKE_FIFO"]
        | h["LANDLOCK_ACCESS_FS_MAKE_BLOCK"]
        | h["LANDLOCK_ACCESS_FS_MAKE_SYM"]
        | h["LANDLOCK_ACCESS_FS_REFER"]
        | h["LANDLOCK_ACCESS_FS_TRUNCATE"]
        | h["LANDLOCK_ACCESS_FS_IOCTL_DEV"]
    )
    with _seeded_abi(8):
        fn = ll._make_landlock_preexec([str(tmp_path)])
    assert _cell(fn, "_write_access") == expected


@requires_landlock_header
def test_read_exec_net_scope_bits_match_kernel_uapi(
        tmp_path: Path) -> None:
    h = _header_defines(_LANDLOCK_H)
    with _seeded_abi(8):
        fn = ll._make_landlock_preexec(
            [str(tmp_path)], readable_paths=[str(tmp_path)],
            allowed_tcp_ports=[443],
        )
    assert _cell(fn, "_read_access") == (
        h["LANDLOCK_ACCESS_FS_READ_FILE"]
        | h["LANDLOCK_ACCESS_FS_READ_DIR"]
    )
    # restrict_reads engages EXEC scoping: the EXECUTE right is part
    # of the handled set exactly there.
    assert _cell(fn, "_exec_access") == h["LANDLOCK_ACCESS_FS_EXECUTE"]
    assert _cell(fn, "_net_access") == h["LANDLOCK_ACCESS_NET_CONNECT_TCP"]
    assert _cell(fn, "_scoped") == (
        h["LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET"]
        | h["LANDLOCK_SCOPE_SIGNAL"]
    )
    assert _cell(fn, "RULE_NET_PORT") == 2  # enum landlock_rule_type
    assert _cell(fn, "RULE_PATH_BENEATH") == 1


@pytest.mark.skipif(
    not any(p.exists() for p in _UNISTD_CANDIDATES),
    reason="unistd UAPI header not installed")
def test_syscall_numbers_match_kernel_uapi(tmp_path: Path) -> None:
    """A drifted syscall number makes the availability probe (and the
    child's install) call a DIFFERENT syscall: the probe then fails,
    every consumer degrades to weaker isolation, and every
    availability-gated test skips — silent fleet-wide policy loss."""
    hdr = next(p for p in _UNISTD_CANDIDATES if p.exists())
    nrs = {
        m.group(1): int(m.group(2))
        for m in re.finditer(
            r"#define\s+__NR_(landlock_\w+)\s+(\d+)", hdr.read_text())
    }
    with _seeded_abi(8):
        fn = ll._make_landlock_preexec([str(tmp_path)])
    assert _cell(fn, "SYS_create") == nrs["landlock_create_ruleset"]
    assert _cell(fn, "SYS_add_rule") == nrs["landlock_add_rule"]
    assert _cell(fn, "SYS_restrict") == nrs["landlock_restrict_self"]


# ---------------------------------------------------------------------------
# ABI-gated mask construction + policy defaults
# ---------------------------------------------------------------------------


@requires_landlock_header
def test_write_mask_abi_gates_are_inclusive(tmp_path: Path) -> None:
    """REFER exists FROM ABI 2 and TRUNCATE FROM ABI 3 (inclusive) —
    an exclusive gate would omit the right on exactly the kernel that
    introduced it; including it one ABI early would EINVAL the whole
    ruleset there."""
    h = _header_defines(_LANDLOCK_H)
    refer = h["LANDLOCK_ACCESS_FS_REFER"]
    trunc = h["LANDLOCK_ACCESS_FS_TRUNCATE"]
    ioctl = h["LANDLOCK_ACCESS_FS_IOCTL_DEV"]
    masks = {}
    for abi in (1, 2, 3, 5):
        with _seeded_abi(abi):
            fn = ll._make_landlock_preexec([str(tmp_path)])
        masks[abi] = _cell(fn, "_write_access")
    assert not masks[1] & refer and not masks[1] & trunc
    assert masks[2] & refer and not masks[2] & trunc
    assert masks[3] & refer and masks[3] & trunc and not masks[3] & ioctl
    assert masks[5] & ioctl


def test_plain_write_policy_leaves_tcp_connect_unhandled(
        tmp_path: Path) -> None:
    """deny_all_tcp_connect defaults OFF: a caller asking only for
    write scoping must not get its TCP connects denied as a side
    effect — the connect-deny is separately consented degraded-mode
    behaviour."""
    with _seeded_abi(8):
        fn = ll._make_landlock_preexec([str(tmp_path)])
    assert _cell(fn, "_net_access") == 0
    with _seeded_abi(8):
        fn = ll._make_landlock_preexec(
            [str(tmp_path)], deny_all_tcp_connect=True)
    assert _cell(fn, "_net_access") != 0


def test_net_only_deny_handles_no_fs_accesses() -> None:
    # The documented net-only shape: connect-deny with no writable
    # paths, no read restriction, no port allowlist governs ONLY the
    # net axis — filesystem semantics stay exactly as without
    # Landlock.
    with _seeded_abi(8):
        fn = ll._make_landlock_preexec([], deny_all_tcp_connect=True)
    assert _cell(fn, "_handled_fs") == 0
    assert _cell(fn, "_net_access") != 0


def test_scoping_degradation_warns_on_abi_below_6(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Every ABI-gated feature announces its degradation — scoping
    included, on EVERY Landlock-capable ABI below 6 (ABI 1 is the
    boundary case: it is >= 1, so it must warn too)."""
    old = ll._scoping_warned
    ll._scoping_warned = False
    try:
        with _seeded_abi(1), caplog.at_level("WARNING"):
            ll._make_landlock_preexec([str(tmp_path)])
        assert any("scoping unavailable" in r.message.lower()
                   for r in caplog.records)
    finally:
        ll._scoping_warned = old


# ---------------------------------------------------------------------------
# availability probe fails CLOSED on every failure shape
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _fresh_cache() -> Iterator[None]:
    with state._cache_lock:
        old = state._landlock_cache
        state._landlock_cache = None
    try:
        yield
    finally:
        with state._cache_lock:
            state._landlock_cache = old


def _probe_with(syscall_result: Any, selftest: bool) -> bool:
    fake_libc = types.SimpleNamespace(
        syscall=mock.Mock(side_effect=(
            syscall_result if isinstance(syscall_result, Exception)
            else lambda *a: syscall_result)),
    )
    with _fresh_cache(), \
            mock.patch.object(ctypes, "CDLL", return_value=fake_libc), \
            mock.patch.object(ll, "_landlock_functional_self_test",
                              return_value=selftest):
        return ll.check_landlock_available()


requires_arch = pytest.mark.skipif(
    not ll._LANDLOCK_ARCH_OK, reason="unsupported syscall table")


@requires_arch
def test_probe_error_reports_unavailable() -> None:
    assert _probe_with(-1, selftest=True) is False


@requires_arch
def test_probe_zero_abi_reports_unavailable() -> None:
    # ABI versions start at 1. A zero would previously be accepted at
    # probe time but read back as unavailable by every later cached
    # check — the probe must fail closed, consistently.
    assert _probe_with(0, selftest=True) is False


@requires_arch
def test_probe_exception_reports_unavailable() -> None:
    with _fresh_cache(), \
            mock.patch.object(ctypes, "CDLL",
                              side_effect=OSError("no libc")):
        assert ll.check_landlock_available() is False


@requires_arch
def test_broken_selftest_reports_unavailable() -> None:
    # Syscalls succeeding but enforcement not observable = "looks
    # green but isn't enforcing" — strictly worse than unavailable.
    assert _probe_with(3, selftest=False) is False


@requires_arch
def test_probe_success_is_cached_and_abi_exposed() -> None:
    assert _probe_with(3, selftest=True) is True
    # NB: _probe_with restored the cache; re-seed to inspect the
    # cached read path.
    with _seeded_abi(3):
        assert ll.check_landlock_available() is True
        assert ll._get_landlock_abi() == 3


def test_cached_abi_one_counts_as_available() -> None:
    # Any positive cached ABI is available — v1 kernels (5.13) get
    # basic write restriction and must not be treated as Landlock-less.
    with _seeded_abi(1):
        assert ll.check_landlock_available() is True
        assert ll._get_landlock_abi() == 1


def test_unavailable_cache_yields_abi_zero() -> None:
    with _seeded_abi(-1):
        assert ll.check_landlock_available() is False
        assert ll._get_landlock_abi() == 0


# ---------------------------------------------------------------------------
# _apply_landlock branch matrix (closure cells swapped for recorders)
# ---------------------------------------------------------------------------


class _ExitCalled(BaseException):
    """Sentinel for os._exit in the closure-under-test (BaseException so
    the closure's own `except Exception` fail-closed arm can't eat it)."""

    def __init__(self, code: int) -> None:
        self.code = code


class _FakeLibc:
    """Programmable stand-in for the closure's captured libc handle."""

    def __init__(self, *, create: Any = 5, add_rule: int = 0,
                 restrict: int = 0, prctl_ret: int = 0) -> None:
        self._create = create
        self._add_rule = add_rule
        self._restrict = restrict
        self._prctl = prctl_ret
        self.calls: list[tuple[Any, ...]] = []
        # (rule_type, parent_fd_or_port, allowed_access) per add_rule.
        self.rules: list[tuple[int, int, int]] = []

    def syscall(self, nr: int, *args: Any) -> int:
        self.calls.append((nr, *args))
        if nr == ll._SYS_LANDLOCK_CREATE:
            if isinstance(self._create, Exception):
                raise self._create
            return self._create
        if nr == ll._SYS_LANDLOCK_ADD_RULE:
            # args = (ruleset_fd, rule_type, byref(rule), flags) — read
            # the rule struct back so tests can assert the exact
            # access mask each rule carries.
            rule = args[2]._obj
            self.rules.append(
                (args[1], rule.parent_fd if hasattr(rule, "parent_fd")
                 else rule.port, rule.allowed_access))
            return self._add_rule
        if nr == ll._SYS_LANDLOCK_RESTRICT:
            return self._restrict
        raise AssertionError(f"unexpected syscall {nr}")

    def prctl(self, *args: Any) -> int:
        self.calls.append(("prctl", *args))
        return self._prctl


class _Harness:
    """One _apply_landlock invocation with recorded channels."""

    def __init__(self, fn: Any, libc: _FakeLibc) -> None:
        self.libc = libc
        self.writes: list[tuple[int, bytes]] = []
        self.closed: list[int] = []
        cells = _cells(fn)
        cells["_libc"].cell_contents = libc
        cells["_os_write"].cell_contents = (
            lambda fd, data: self.writes.append((fd, data)))
        cells["_os_close"].cell_contents = self.closed.append
        cells["_os_open"].cell_contents = lambda *a: 7
        cells["_open_grant"].cell_contents = lambda path: (9, True)
        self.fn = fn

    def stderr(self) -> bytes:
        return b"".join(d for _fd, d in self.writes)

    def write_fds(self) -> set[int]:
        return {fd for fd, _d in self.writes}


def _harness(tmp_path: Path, *, libc: _FakeLibc,
             fail_raise: bool = False, abi: int = 8,
             **build_kwargs: Any) -> _Harness:
    build_kwargs.setdefault("writable_paths", [str(tmp_path)])
    with _seeded_abi(abi):
        fn = ll._make_landlock_preexec(fail_raise=fail_raise,
                                       **build_kwargs)
    return _Harness(fn, libc)


@pytest.fixture
def exit_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    import os as _os

    def _raise(code: int) -> None:
        raise _ExitCalled(code)

    monkeypatch.setattr(_os, "_exit", _raise)


def test_happy_path_installs_silently(
        tmp_path: Path, exit_sentinel: None) -> None:
    h = _harness(tmp_path, libc=_FakeLibc(),
                 readable_paths=[str(tmp_path)],
                 allowed_tcp_ports=[8443])
    h.fn()
    assert h.writes == []  # no warnings on a clean install
    # create → rules → prctl → restrict, in that order.
    assert h.libc.calls[0][0] == ll._SYS_LANDLOCK_CREATE
    assert h.libc.calls[-2][0] == "prctl"
    assert h.libc.calls[-1][0] == ll._SYS_LANDLOCK_RESTRICT
    assert any(c[0] == ll._SYS_LANDLOCK_ADD_RULE for c in h.libc.calls)


def test_rule_add_failures_warn_on_stderr_and_continue(
        tmp_path: Path, exit_sentinel: None) -> None:
    """Per-rule registration failures are NONFATAL (the path falls
    under the global deny — fail-closed for that path) but must be
    attributed on the child's stderr, fd 2 exactly: any other fd is
    unopened in the forked child and turns the diagnostic write into
    an aborting OSError."""
    h = _harness(tmp_path, libc=_FakeLibc(add_rule=-1),
                 readable_paths=[str(tmp_path)],
                 allowed_tcp_ports=[8443])
    h.fn()
    err = h.stderr()
    assert b"add_rule failed for a writable path" in err
    assert b"add_rule failed for a writable device" in err
    assert b"add_rule failed for a readable path" in err
    assert b"TCP port allow-rule failed" in err
    assert h.write_fds() == {2}


def test_unopenable_writable_grant_is_nonfatal_and_named(
        tmp_path: Path, exit_sentinel: None) -> None:
    h = _harness(tmp_path, libc=_FakeLibc())
    _cells(h.fn)["_open_grant"].cell_contents = mock.Mock(
        side_effect=OSError(2, "gone"))
    h.fn()
    err = h.stderr()
    assert b"writable path" in err and b"could not be opened" in err
    assert h.write_fds() == {2}
    # install still completed (prctl + restrict ran).
    assert h.libc.calls[-1][0] == ll._SYS_LANDLOCK_RESTRICT


def test_no_net_rules_attempted_below_abi_4(
        tmp_path: Path, exit_sentinel: None) -> None:
    # On a pre-net kernel the port allowlist cannot be expressed; the
    # closure must not fire net add_rules at an fs-only ruleset (they
    # would EINVAL and emit a misleading rule-failure warning).
    h = _harness(tmp_path, libc=_FakeLibc(), abi=1,
                 allowed_tcp_ports=[8443])
    h.fn()
    assert b"TCP port allow-rule failed" not in h.stderr()
    net_rules = [c for c in h.libc.calls
                 if c[0] == ll._SYS_LANDLOCK_ADD_RULE and c[2] == 2]
    assert net_rules == []


def test_create_failure_exits_with_downgrade_code(
        tmp_path: Path, exit_sentinel: None) -> None:
    h = _harness(tmp_path, libc=_FakeLibc(create=-1))
    with pytest.raises(_ExitCalled) as exc:
        h.fn()
    assert exc.value.code == SANDBOX_EXIT_LANDLOCK_DOWNGRADE
    assert b"SYS_landlock_create_ruleset failed" in h.stderr()
    assert h.write_fds() == {2}


def test_create_failure_raises_typed_error_in_fail_raise_lane(
        tmp_path: Path, exit_sentinel: None) -> None:
    h = _harness(tmp_path, libc=_FakeLibc(create=-1), fail_raise=True)
    with pytest.raises(ll.LandlockInstallError):
        h.fn()


def test_prctl_failure_fails_closed_both_lanes(
        tmp_path: Path, exit_sentinel: None) -> None:
    h = _harness(tmp_path, libc=_FakeLibc(prctl_ret=-1))
    with pytest.raises(_ExitCalled) as exc:
        h.fn()
    assert exc.value.code == 126
    assert b"PR_SET_NO_NEW_PRIVS" in h.stderr()
    assert h.write_fds() == {2}

    h = _harness(tmp_path, libc=_FakeLibc(prctl_ret=-1), fail_raise=True)
    with pytest.raises(ll.LandlockInstallError):
        h.fn()


def test_restrict_failure_fails_closed_both_lanes(
        tmp_path: Path, exit_sentinel: None) -> None:
    h = _harness(tmp_path, libc=_FakeLibc(restrict=-1))
    with pytest.raises(_ExitCalled) as exc:
        h.fn()
    assert exc.value.code == 126
    assert b"restrict_self failed" in h.stderr()
    assert h.write_fds() == {2}

    h = _harness(tmp_path, libc=_FakeLibc(restrict=-1), fail_raise=True)
    with pytest.raises(ll.LandlockInstallError):
        h.fn()


def test_unexpected_exception_fails_closed_both_lanes(
        tmp_path: Path, exit_sentinel: None) -> None:
    """ANY exception during install means the isolation guarantee is
    broken: preexec lane aborts 126 (the documented convention —
    kernel-adjacent consumers key on it), fail_raise lane re-raises."""
    boom = RuntimeError("boom")
    h = _harness(tmp_path, libc=_FakeLibc(create=boom))
    with pytest.raises(_ExitCalled) as exc:
        h.fn()
    assert exc.value.code == 126
    assert b"Landlock enforcement failed" in h.stderr()
    assert h.write_fds() == {2}

    h = _harness(tmp_path, libc=_FakeLibc(create=boom), fail_raise=True)
    with pytest.raises(RuntimeError):
        h.fn()


@requires_landlock_header
def test_device_rules_carry_truncate_from_abi_3(tmp_path: Path,
                                                exit_sentinel: None) -> None:
    """The /dev/null / /dev/tty write rules must include TRUNCATE from
    ABI 3: shell `>/dev/null` opens O_WRONLY|O_TRUNC, and a dev rule
    without the right would EACCES every `cmd >/dev/null` wrapper on
    truncate-aware kernels. (Not observable against a real /dev/null —
    the VFS skips truncation for character devices — so the rule
    payload itself is asserted.) On ABI < 3 the right does not exist
    and must be absent (EINVAL otherwise)."""
    h = _header_defines(_LANDLOCK_H)
    wf = h["LANDLOCK_ACCESS_FS_WRITE_FILE"]
    tr = h["LANDLOCK_ACCESS_FS_TRUNCATE"]
    libc = _FakeLibc()
    hh = _harness(tmp_path, libc=libc)
    hh.fn()
    # dev rules are the path_beneath rules opened via _os_open (fd 7);
    # grant rules come from _open_grant (fd 9).
    dev_rules = [r for r in libc.rules if r[0] == 1 and r[1] == 7]
    assert dev_rules, "no device rules recorded"
    for _t, _fd, access in dev_rules:
        assert access == wf | tr

    libc = _FakeLibc()
    hh = _harness(tmp_path, libc=libc, abi=1)
    hh.fn()
    dev_rules = [r for r in libc.rules if r[0] == 1 and r[1] == 7]
    assert dev_rules, "no device rules recorded at ABI 1"
    for _t, _fd, access in dev_rules:
        assert access == wf


# ---------------------------------------------------------------------------
# functional self-test child: every failure shape reports BROKEN (0)
# ---------------------------------------------------------------------------
# _run_selftest_in_child's verdict byte decides whether the whole
# process treats Landlock as usable. The success arm requires BOTH
# probes to be EACCES-denied; every error/anomaly arm must report 0
# ("broken / cannot verify") — a 1 on any error path is a fail-open
# probe: the sandbox would claim enforcement nobody verified.


class _SelftestLibc:
    def __init__(self, *, create_fail: bool = False,
                 restrict_ret: int = 0) -> None:
        self._create_fail = create_fail
        self._restrict_ret = restrict_ret

    def syscall(self, nr: int, *args: Any) -> int:
        if nr == ll._SYS_LANDLOCK_CREATE:
            if self._create_fail:
                return -1
            import os as _os
            return _os.open("/dev/null", _os.O_RDONLY)
        if nr == ll._SYS_LANDLOCK_RESTRICT:
            return self._restrict_ret
        raise AssertionError(f"unexpected syscall {nr}")

    def prctl(self, *args: Any) -> int:
        return 0


def _probe_open_patch(monkeypatch: pytest.MonkeyPatch,
                      wronly: Any, rdonly: Any) -> None:
    """Intercept the self-test's two probe opens (exact O_WRONLY /
    O_RDONLY flags on the mkstemp path); everything else passes
    through — mkstemp's own O_CREAT|O_EXCL open included."""
    import os as _os
    real_open = _os.open
    pfx = "/tmp/.raptor_landlock_selftest_"

    def fake_open(path: Any, flags: int, *a: Any, **kw: Any) -> int:
        if isinstance(path, str) and path.startswith(pfx):
            if flags == _os.O_WRONLY:
                if isinstance(wronly, Exception):
                    raise wronly
                return real_open(path, flags, *a, **kw)
            if flags == _os.O_RDONLY:
                if isinstance(rdonly, Exception):
                    raise rdonly
                return real_open(path, flags, *a, **kw)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(_os, "open", fake_open)


def test_selftest_confirms_only_when_both_probes_denied(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _probe_open_patch(monkeypatch,
                      wronly=PermissionError(13, "denied"),
                      rdonly=PermissionError(13, "denied"))
    assert ll._run_selftest_in_child(_SelftestLibc()) == 1


def test_selftest_reports_broken_when_nothing_enforces(
        ) -> None:
    # Fake libc "succeeds" at every syscall but restricts nothing —
    # the "looks green but isn't enforcing" kernel. Both probe opens
    # succeed; verdict must be 0.
    assert ll._run_selftest_in_child(_SelftestLibc()) == 0


def test_selftest_reports_broken_when_only_write_denied(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # READ_FILE silently broken (e.g. bit-value drift) while
    # WRITE_FILE still enforces: verdict 0.
    _probe_open_patch(monkeypatch,
                      wronly=PermissionError(13, "denied"),
                      rdonly=None)
    assert ll._run_selftest_in_child(_SelftestLibc()) == 0


def test_selftest_error_paths_all_report_broken(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import errno as _errno
    import os as _os
    import tempfile as _tempfile

    # libc missing (pre-fork resolution failed)
    assert ll._run_selftest_in_child(None) == 0
    # ruleset creation fails
    assert ll._run_selftest_in_child(
        _SelftestLibc(create_fail=True)) == 0
    # restrict_self fails
    assert ll._run_selftest_in_child(
        _SelftestLibc(restrict_ret=-1)) == 0
    # probe-1 fails with a NON-permission error (probe broken, not
    # enforcement confirmed)
    _probe_open_patch(monkeypatch,
                      wronly=OSError(_errno.EIO, "io"), rdonly=None)
    assert ll._run_selftest_in_child(_SelftestLibc()) == 0
    # probe-2 fails with a non-permission error after a clean
    # probe-1 denial
    _probe_open_patch(monkeypatch,
                      wronly=PermissionError(13, "denied"),
                      rdonly=OSError(_errno.EIO, "io"))
    assert ll._run_selftest_in_child(_SelftestLibc()) == 0
    monkeypatch.undo()
    # mkstemp itself fails
    monkeypatch.setattr(_tempfile, "mkstemp",
                        mock.Mock(side_effect=OSError(28, "nospace")))
    assert ll._run_selftest_in_child(_SelftestLibc()) == 0
    monkeypatch.undo()
    # the probe-file write fails (read-only fd stands in for ENOSPC)
    stub = tmp_path / "stub"
    stub.write_text("")
    monkeypatch.setattr(
        _tempfile, "mkstemp",
        mock.Mock(return_value=(_os.open(stub, _os.O_RDONLY),
                                str(stub))))
    assert ll._run_selftest_in_child(_SelftestLibc()) == 0


def test_unsupported_arch_reports_unavailable(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """On syscall tables we don't know (legacy 32-bit archs, MIPS n64
    offsets), the probe must report a hard False — issuing syscall 444
    there would invoke an unrelated syscall."""
    monkeypatch.setattr(ll, "_LANDLOCK_ARCH_OK", False)
    with _fresh_cache():
        assert ll.check_landlock_available() is False
        # and the verdict is cached as unavailable for the process
        assert ll.check_landlock_available() is False
        assert ll._get_landlock_abi() == 0


def test_selftest_ruleset_handles_exactly_write_and_read(
        ) -> None:
    """The functional self-test's ruleset must handle exactly
    WRITE_FILE|READ_FILE on the fs axis and NOTHING on the net axis —
    a stray net bit would EINVAL ruleset creation on pre-net (ABI < 4)
    kernels and flip perfectly healthy hosts to 'Landlock broken'."""
    seen: dict[str, int] = {}

    class _Recorder(_SelftestLibc):
        def syscall(self, nr: int, *args: Any) -> int:
            if nr == ll._SYS_LANDLOCK_CREATE:
                attr = args[0]._obj
                seen["fs"] = attr.handled_access_fs
                seen["net"] = attr.handled_access_net
            return super().syscall(nr, *args)

    ll._run_selftest_in_child(_Recorder())
    if _LANDLOCK_H.exists():
        h = _header_defines(_LANDLOCK_H)
        expected_fs = (h["LANDLOCK_ACCESS_FS_WRITE_FILE"]
                       | h["LANDLOCK_ACCESS_FS_READ_FILE"])
    else:
        expected_fs = (1 << 1) | (1 << 2)
    assert seen["fs"] == expected_fs
    assert seen["net"] == 0


def test_selftest_fork_bookkeeping_failures_report_false(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The fork wrapper fails CLOSED (False, never None — callers and
    tests compare the verdict, and the cache write derives from it):
    a failing fork, and a parent-side read error, both report
    unavailable."""
    import os as _os

    monkeypatch.setattr(_os, "fork",
                        mock.Mock(side_effect=OSError(11, "again")))
    assert ll._landlock_functional_self_test() is False
    monkeypatch.undo()

    # Parent lane with no real child (fake pid): the write end closes
    # with nothing written → EOF → False. The pid==0 branch dispatch
    # matters here: treating the parent as the child would apply a
    # REAL Landlock ruleset to this very process and _exit it.
    monkeypatch.setattr(_os, "fork", mock.Mock(return_value=2**22 + 1))
    assert ll._landlock_functional_self_test() is False
    monkeypatch.undo()

    # Parent-side read error → False (and the child is still reaped).
    monkeypatch.setattr(_os, "fork", mock.Mock(return_value=2**22 + 1))
    monkeypatch.setattr(_os, "read",
                        mock.Mock(side_effect=OSError(5, "io")))
    assert ll._landlock_functional_self_test() is False

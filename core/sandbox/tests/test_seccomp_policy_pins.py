"""Seccomp policy pins: probe direction, filter-rule payloads, and the
install closure's fail-closed branches.

Same construction as the Landlock policy pins: the preexec builder
runs against the REAL libseccomp (so syscall names resolve to this
arch's true numbers), then the closure's captured cells — the
libseccomp handle, libc, os.write — are swapped for recorders before
the closure is invoked in-process. Every rule the filter would install
is captured with its action, syscall number, and argument comparators
and asserted against independent sources (the ``socket`` module's
constants, kernel headers parsed by name). No filter is ever loaded
into this process.

The failure matrix drives every fail-closed branch: a rule that cannot
install must abort the exec with the documented exit code 126 and a
diagnostic on fd 2 exactly (any other fd is unopened in the forked
child and would turn the diagnostic write itself into an abort).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import re
import socket
import sys
import types
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import seccomp as sc  # noqa: E402
from core.sandbox import state  # noqa: E402

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux",
                       reason="seccomp is Linux-only"),
]

requires_libseccomp = pytest.mark.skipif(
    not sc.check_seccomp_available(),
    reason="libseccomp unavailable on this host",
)


def _header_define(paths: tuple[str, ...], name: str) -> int | None:
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        m = re.search(
            rf"#\s*define\s+{name}\s+0x([0-9a-fA-F]+)", path.read_text())
        if m:
            return int(m.group(1), 16)
    return None


# ---------------------------------------------------------------------------
# availability probe fails CLOSED on every failure shape
# ---------------------------------------------------------------------------


class _NoAttrLib:
    """Stands in for a libseccomp build missing a needed symbol."""

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(name)


def _probe(monkeypatch: pytest.MonkeyPatch, *, libname: Any = "seccomp",
           lib: Any = None, selftest: bool = True) -> bool:
    monkeypatch.setattr(state, "_libseccomp_cache", None)
    monkeypatch.setattr(ctypes.util, "find_library",
                        lambda name: libname)
    if lib is not None:
        monkeypatch.setattr(ctypes, "CDLL",
                            mock.Mock(return_value=lib))
    monkeypatch.setattr(sc, "_seccomp_functional_selftest",
                        lambda lib: selftest)
    try:
        return sc.check_seccomp_available()
    finally:
        monkeypatch.setattr(state, "_libseccomp_cache", None)


def test_probe_reports_unavailable_without_library(
        monkeypatch: pytest.MonkeyPatch) -> None:
    assert _probe(monkeypatch, libname=None) is False


def test_probe_reports_unavailable_on_load_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(state, "_libseccomp_cache", None)
    monkeypatch.setattr(ctypes.util, "find_library",
                        lambda name: "seccomp")
    monkeypatch.setattr(ctypes, "CDLL",
                        mock.Mock(side_effect=OSError("bad build")))
    assert sc.check_seccomp_available() is False


def test_probe_reports_unavailable_on_missing_symbols(
        monkeypatch: pytest.MonkeyPatch) -> None:
    assert _probe(monkeypatch, lib=_NoAttrLib()) is False


def test_probe_reports_unavailable_when_selftest_fails(
        monkeypatch: pytest.MonkeyPatch) -> None:
    lib = types.SimpleNamespace(
        seccomp_init=1, seccomp_rule_add_array=1, seccomp_load=1,
        seccomp_release=1, seccomp_syscall_resolve_name=1,
        seccomp_attr_set=1)
    assert _probe(monkeypatch, lib=lib, selftest=False) is False


def test_probe_success_caches_the_library_handle(
        monkeypatch: pytest.MonkeyPatch) -> None:
    lib = types.SimpleNamespace(
        seccomp_init=1, seccomp_rule_add_array=1, seccomp_load=1,
        seccomp_release=1, seccomp_syscall_resolve_name=1,
        seccomp_attr_set=1)
    monkeypatch.setattr(state, "_libseccomp_cache", None)
    monkeypatch.setattr(ctypes.util, "find_library",
                        lambda name: "seccomp")
    monkeypatch.setattr(ctypes, "CDLL", mock.Mock(return_value=lib))
    monkeypatch.setattr(sc, "_seccomp_functional_selftest",
                        lambda _lib: True)
    assert sc.check_seccomp_available() is True
    assert state._libseccomp_cache is lib
    monkeypatch.setattr(state, "_libseccomp_cache", None)


def test_selftest_fails_closed_on_symbol_resolution_error() -> None:
    """A lib whose needed symbols cannot even be declared must report
    the self-test FAILED (unavailable) — reporting success here would
    let the spawn child die mid-install on every run instead of
    skipping the layer up front."""
    assert sc._seccomp_functional_selftest(_NoAttrLib()) is False


@requires_libseccomp
def test_native_selftest_passes_with_real_library() -> None:
    lib = ctypes.CDLL(ctypes.util.find_library("seccomp"),
                      use_errno=True)
    assert sc._seccomp_functional_selftest(lib) is True


# ---------------------------------------------------------------------------
# closure harness
# ---------------------------------------------------------------------------


class _ExitCalled(BaseException):
    def __init__(self, code: int) -> None:
        self.code = code


class _Rule:
    __slots__ = ("action", "num", "args")

    def __init__(self, action: int, num: int,
                 args: list[tuple[int, int, int, int]]) -> None:
        self.action = action
        self.num = num
        self.args = args  # (arg_index, op, datum_a, datum_b)


class _FakeSeccompLib:
    def __init__(self, *, init_ret: int = 7, attr_ret: int = 0,
                 load_ret: int = 0, fail_rule_at: int | None = None,
                 notify_fd: int | None = None) -> None:
        self._init_ret = init_ret
        self._attr_ret = attr_ret
        self._load_ret = load_ret
        self._fail_rule_at = fail_rule_at
        self._notify_fd = notify_fd
        self.rules: list[_Rule] = []
        self.loaded = 0
        self.released = 0

    def seccomp_init(self, action: int) -> int:
        return self._init_ret

    def seccomp_attr_set(self, ctx: Any, attr: Any, value: Any) -> int:
        return self._attr_ret

    def seccomp_rule_add_array(self, ctx: Any, action: int, num: int,
                               argc: int, argv: Any) -> int:
        idx = len(self.rules)
        args = []
        if argc:
            for i in range(argc):
                cmp_ = argv[i]
                args.append((cmp_.arg, cmp_.op, cmp_.datum_a,
                             cmp_.datum_b))
        self.rules.append(_Rule(action, num, args))
        if self._fail_rule_at is not None and idx == self._fail_rule_at:
            return -1
        return 0

    def seccomp_load(self, ctx: Any) -> int:
        self.loaded += 1
        return self._load_ret

    def seccomp_release(self, ctx: Any) -> None:
        self.released += 1

    def seccomp_notify_fd(self, ctx: Any) -> int:
        import os as _os
        if self._notify_fd is not None:
            return self._notify_fd
        return _os.open("/dev/null", _os.O_RDONLY)


class _FakeLibc:
    def __init__(self, prctl_ret: int = 0) -> None:
        self._prctl = prctl_ret

    def prctl(self, *a: Any) -> int:
        return self._prctl


def _cells(fn: Any) -> dict[str, Any]:
    return dict(zip(fn.__code__.co_freevars, fn.__closure__))


def _cell(fn: Any, name: str) -> Any:
    return _cells(fn)[name].cell_contents


class _Harness:
    def __init__(self, fn: Any, lib: _FakeSeccompLib,
                 libc: _FakeLibc | None = None) -> None:
        self.fn = fn
        self.lib = lib
        self.writes: list[tuple[int, bytes]] = []
        cells = _cells(fn)
        cells["lib"].cell_contents = lib
        cells["_libc"].cell_contents = libc or _FakeLibc()
        cells["_os_write"].cell_contents = (
            lambda fd, data: self.writes.append((fd, data)))

    def stderr(self) -> bytes:
        return b"".join(d for _fd, d in self.writes)

    def write_fds(self) -> set[int]:
        return {fd for fd, _d in self.writes}


@pytest.fixture
def exit_sentinel(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record every os._exit code and raise. The closure's outer
    ``except BaseException`` fail-closed arm catches the sentinel from
    interior sites and re-routes to its own final exit, so assertions
    must read the FIRST recorded code — the one the real forked child
    would have died with."""
    import os as _os
    codes: list[int] = []

    def _raise(code: int) -> None:
        codes.append(code)
        raise _ExitCalled(code)

    monkeypatch.setattr(_os, "_exit", _raise)
    return codes


def _build(profile: str = "full", **kw: Any) -> Any:
    fn = sc._make_seccomp_preexec(profile, **kw)
    assert fn is not None
    return fn


def _harness(profile: str = "full", *, lib: _FakeSeccompLib | None = None,
             libc: _FakeLibc | None = None, **kw: Any) -> _Harness:
    return _Harness(_build(profile, **kw), lib or _FakeSeccompLib(),
                    libc=libc)


# ---------------------------------------------------------------------------
# rule payload pins (independent sources: socket module, kernel headers)
# ---------------------------------------------------------------------------

_ARG32 = 0xFFFFFFFF


@requires_libseccomp
def test_socket_family_allowlist_is_inet_only_by_default(
        exit_sentinel: None) -> None:
    """Deny-by-default family axis: the rule set permits EXACTLY
    {AF_INET, AF_INET6} in the default posture — every family below
    the ceiling gets a MASKED_EQ(low-32) deny and one GE rule at the
    ceiling refuses everything above it (future families and high-bit
    garnish included)."""
    h = _harness("full")
    h.fn()
    sock_num = _cell(h.fn, "socket_num")
    fam_denies = [r for r in h.lib.rules
                  if r.num == sock_num and len(r.args) == 1
                  and r.args[0][0] == 0
                  and r.args[0][1] == sc._SCMP_CMP_MASKED_EQ
                  and r.args[0][2] == _ARG32]
    denied = {r.args[0][3] for r in fam_denies}
    ge = [r for r in h.lib.rules
          if r.num == sock_num and len(r.args) == 1
          and r.args[0][1] == sc._SCMP_CMP_GE]
    assert ge, "no GE ceiling rule on the family axis"
    floor = ge[0].args[0][2]
    allowed = set(range(floor)) - denied
    assert allowed == {socket.AF_INET, socket.AF_INET6}
    assert floor == max(socket.AF_INET, socket.AF_INET6) + 1


@requires_libseccomp
def test_frida_profile_adds_exactly_af_unix_to_the_allowlist(
        exit_sentinel: None) -> None:
    h = _harness("frida")
    h.fn()
    sock_num = _cell(h.fn, "socket_num")
    denied = {r.args[0][3] for r in h.lib.rules
              if r.num == sock_num and len(r.args) == 1
              and r.args[0][1] == sc._SCMP_CMP_MASKED_EQ
              and r.args[0][2] == _ARG32}
    ge = [r for r in h.lib.rules
          if r.num == sock_num and len(r.args) == 1
          and r.args[0][1] == sc._SCMP_CMP_GE]
    floor = ge[0].args[0][2]
    allowed = set(range(floor)) - denied
    assert allowed == {socket.AF_UNIX, socket.AF_INET,
                       socket.AF_INET6}


@requires_libseccomp
def test_sock_raw_rule_filters_type_argument_with_kernel_mask(
        exit_sentinel: None) -> None:
    """The SOCK_RAW deny compares ARGUMENT 1 (the type) under the
    kernel's SOCK_TYPE_MASK so SOCK_RAW|SOCK_CLOEXEC and
    SOCK_RAW|SOCK_NONBLOCK match — a shifted argument index or a
    wrong mask filters something else entirely."""
    h = _harness("full")
    h.fn()
    sock_num = _cell(h.fn, "socket_num")
    # arg index 1 distinguishes the type rule from the family denies
    # (AF_AX25 == 3 == SOCK_RAW as a bare value).
    raw_rules = [r for r in h.lib.rules
                 if r.num == sock_num and len(r.args) == 1
                 and r.args[0][0] == 1
                 and r.args[0][3] == socket.SOCK_RAW]
    assert raw_rules, "no SOCK_RAW rule installed on the type argument"
    _arg_idx, op, mask, datum = raw_rules[0].args[0]
    assert op == sc._SCMP_CMP_MASKED_EQ
    assert mask == 0xF  # linux SOCK_TYPE_MASK
    assert datum == socket.SOCK_RAW


@requires_libseccomp
def test_ns_creation_rules_match_kernel_clone_flags(
        exit_sentinel: None) -> None:
    """block_ns_creation installs one MASKED_EQ rule per CLONE_NEW*
    flag on unshare AND clone, plus a wholesale setns deny and a
    clone3 ENOSYS. Flag values are pinned against the kernel's own
    sched.h — a drifted flag filters a bitmask no caller ever passes
    while the real namespace flag sails through."""
    hdr = Path("/usr/include/linux/sched.h")
    if not hdr.exists():
        pytest.skip("kernel sched.h not installed")
    text = hdr.read_text()
    expected_flags = {
        name: int(m, 16) for name, m in re.findall(
            r"#define\s+CLONE_(NEWUSER|NEWNS|NEWPID|NEWNET|NEWIPC|"
            r"NEWUTS|NEWCGROUP|NEWTIME)\s+0x([0-9a-fA-F]+)", text)
    }
    assert len(expected_flags) == 8, expected_flags
    h = _harness("full", block_ns_creation=True)
    h.fn()
    nums = _cell(h.fn, "ns_syscall_nums")
    for sysname in ("unshare", "clone"):
        num = nums[sysname]
        seen = {r.args[0][2] for r in h.lib.rules
                if r.num == num and len(r.args) == 1
                and r.args[0][1] == sc._SCMP_CMP_MASKED_EQ}
        assert seen == set(expected_flags.values()), sysname
        # MASKED_EQ(flag, flag): the rule matches any flag COMBINATION
        # containing the namespace bit.
        for r in h.lib.rules:
            if r.num == num and len(r.args) == 1:
                assert r.args[0][2] == r.args[0][3]
    assert any(r.num == nums["setns"] and not r.args
               for r in h.lib.rules)
    assert any(r.num == nums["clone3"] and not r.args
               for r in h.lib.rules)


@requires_libseccomp
def test_msg_fastopen_denied_on_every_send_path_flag_argument(
        exit_sentinel: None) -> None:
    """MSG_FASTOPEN smuggles an in-kernel TCP connect through the send
    path. The deny must sit on each syscall's FLAGS argument —
    sendto(3), sendmsg(2), sendmmsg(3) — as MASKED_EQ(flag, flag)."""
    if not hasattr(socket, "MSG_FASTOPEN"):
        pytest.skip("socket module lacks MSG_FASTOPEN on this build")
    h = _harness("full")
    h.fn()
    expected_arg = {"sendto": 3, "sendmsg": 2, "sendmmsg": 3}
    for name, num, _arg in _cell(h.fn, "send_flag_syscalls"):
        if num < 0:
            continue
        rules = [r for r in h.lib.rules
                 if r.num == num and len(r.args) == 1
                 and r.args[0][2] == socket.MSG_FASTOPEN]
        assert rules, f"no MSG_FASTOPEN rule for {name}"
        arg_idx, op, mask, datum = rules[0].args[0]
        assert arg_idx == expected_arg[name], name
        assert op == sc._SCMP_CMP_MASKED_EQ
        assert datum == socket.MSG_FASTOPEN


@requires_libseccomp
def test_udp_block_covers_both_inet_families_shape(
        exit_sentinel: None) -> None:
    h = _harness("full", block_udp=True)
    h.fn()
    sock_num = _cell(h.fn, "socket_num")
    udp_rules = [r for r in h.lib.rules
                 if r.num == sock_num and len(r.args) == 2
                 and r.args[1][3] == socket.SOCK_DGRAM]
    fams = {r.args[0][3] for r in udp_rules}
    assert fams == {socket.AF_INET, socket.AF_INET6}
    for r in udp_rules:
        assert r.args[0][0] == 0            # family argument
        assert r.args[0][2] == _ARG32       # low-32 family compare
        assert r.args[1][0] == 1            # type argument
        assert r.args[1][2] == 0xF          # SOCK_TYPE_MASK


@requires_libseccomp
def test_fileless_exec_deny_and_the_frida_memfd_carveout(
        exit_sentinel: None) -> None:
    """deny_fd_exec: memfd_create denied WHOLESALE and execveat's
    AT_EMPTY_PATH spelling denied, for every profile EXCEPT frida —
    whose agent injection is memfd-based (consented instrumentation).
    frida keeps the execveat arm. An inverted carve-out denies frida
    its injection primitive while handing every other untrusted child
    the anonymous-image loophole."""
    at_empty = _header_define(
        ("/usr/include/linux/fcntl.h", "/usr/include/fcntl.h"),
        "AT_EMPTY_PATH") or 0x1000
    h = _harness("full", deny_fd_exec=True)
    h.fn()
    memfd_num = _cell(h.fn, "memfd_create_num")
    execveat_num = _cell(h.fn, "execveat_num")
    assert memfd_num >= 0 and execveat_num >= 0
    assert any(r.num == memfd_num and not r.args for r in h.lib.rules)
    ev = [r for r in h.lib.rules
          if r.num == execveat_num and len(r.args) == 1]
    assert ev, "no execveat AT_EMPTY_PATH rule"
    arg_idx, op, mask, datum = ev[0].args[0]
    assert arg_idx == 4  # flags argument
    assert (mask, datum) == (at_empty, at_empty)

    h = _harness("frida", deny_fd_exec=True)
    h.fn()
    assert _cell(h.fn, "memfd_create_num") == -1
    assert _cell(h.fn, "deny_memfd_create") is False
    frida_execveat = _cell(h.fn, "execveat_num")
    assert any(r.num == frida_execveat and len(r.args) == 1
               for r in h.lib.rules), (
        "frida must keep the execveat AT_EMPTY_PATH arm")


@requires_libseccomp
def test_unix_dgram_socketpair_deny_follows_the_family_posture(
        exit_sentinel: None) -> None:
    """socketpair(AF_UNIX, SOCK_DGRAM) is denied exactly when
    socket(AF_UNIX, SOCK_DGRAM) is (default posture); the frida lane
    that allows AF_UNIX keeps dgram socketpair usable."""
    h = _harness("full")
    h.fn()
    sp_num = _cell(h.fn, "socketpair_num")

    def dgram_rules(h: _Harness) -> list[_Rule]:
        # family compare on arg 0 (low-32 masked), type on arg 1
        # (SOCK_TYPE_MASK) — index or mask drift means the rule
        # filters a different call shape.
        return [r for r in h.lib.rules
                if r.num == sp_num and len(r.args) == 2
                and r.args[0][:3] == (0, sc._SCMP_CMP_MASKED_EQ, _ARG32)
                and r.args[0][3] == socket.AF_UNIX
                and r.args[1][:3] == (1, sc._SCMP_CMP_MASKED_EQ, 0xF)
                and r.args[1][3] == socket.SOCK_DGRAM]

    assert dgram_rules(h), "default posture lost the dgram-pair deny"
    h = _harness("frida")
    h.fn()
    assert not dgram_rules(h), "frida lane must keep dgram socketpair"


@requires_libseccomp
def test_socketpair_family_allowlist_is_af_unix_only(
        exit_sentinel: None) -> None:
    h = _harness("full")
    h.fn()
    sp_num = _cell(h.fn, "socketpair_num")
    denied = {r.args[0][3] for r in h.lib.rules
              if r.num == sp_num and len(r.args) == 1
              and r.args[0][1] == sc._SCMP_CMP_MASKED_EQ}
    ge = [r for r in h.lib.rules
          if r.num == sp_num and len(r.args) == 1
          and r.args[0][1] == sc._SCMP_CMP_GE]
    assert ge
    floor = ge[0].args[0][2]
    assert set(range(floor)) - denied == {socket.AF_UNIX}


# ---------------------------------------------------------------------------
# resolve contract: only NEGATIVE numbers mean "unresolved"
# ---------------------------------------------------------------------------
# libseccomp's documented contract is "negative return = unknown on
# this arch" — syscall number 0 is a legal resolution and must install
# rules like any other. A guard that lumps 0 in with "unresolved"
# silently drops the rule set on whatever arch assigns 0 to a filtered
# syscall.


@requires_libseccomp
def test_syscall_number_zero_counts_as_resolved(
        exit_sentinel: None) -> None:
    for cell_name, kwargs in (
        ("socket_num", {}),
        ("socketpair_num", {}),
    ):
        h = _harness("full", **kwargs)
        _cells(h.fn)[cell_name].cell_contents = 0
        h.fn()
        assert any(r.num == 0 for r in h.lib.rules), cell_name
    # ns-creation rules on number 0
    h = _harness("full", block_ns_creation=True)
    nums = dict(_cell(h.fn, "ns_syscall_nums"))
    nums["unshare"] = 0
    _cells(h.fn)["ns_syscall_nums"].cell_contents = nums
    h.fn()
    assert any(r.num == 0 and len(r.args) == 1 for r in h.lib.rules)
    # send-path MSG_FASTOPEN rules on number 0
    h = _harness("full")
    sf = [("sendto", 0, 3)] + [
        e for e in _cell(h.fn, "send_flag_syscalls")[1:]]
    _cells(h.fn)["send_flag_syscalls"].cell_contents = sf
    h.fn()
    assert any(r.num == 0 for r in h.lib.rules)


@requires_libseccomp
def test_blocked_syscalls_resolved_to_zero_still_install(
        exit_sentinel: None) -> None:
    h = _harness("full")
    blocks = list(_cell(h.fn, "resolved_blocks"))
    blocks[0] = (blocks[0][0], 0)
    _cells(h.fn)["resolved_blocks"].cell_contents = blocks
    h.fn()
    assert any(r.num == 0 and not r.args for r in h.lib.rules)


# ---------------------------------------------------------------------------
# fail-closed branches: every install failure aborts with 126 on fd 2
# ---------------------------------------------------------------------------


@requires_libseccomp
def test_prctl_failure_aborts_exec(exit_sentinel: list[int]) -> None:
    h = _harness("full", libc=_FakeLibc(prctl_ret=-1))
    with pytest.raises(_ExitCalled):
        h.fn()
    assert exit_sentinel[0] == 126
    assert b"PR_SET_NO_NEW_PRIVS" in h.stderr()
    assert h.write_fds() == {2}


@requires_libseccomp
def test_init_failure_aborts_exec(exit_sentinel: list[int]) -> None:
    h = _harness("full", lib=_FakeSeccompLib(init_ret=0))
    with pytest.raises(_ExitCalled):
        h.fn()
    assert exit_sentinel[0] == 126
    assert b"seccomp_init failed" in h.stderr()
    assert h.write_fds() == {2}


@requires_libseccomp
def test_badarch_attr_failure_aborts_exec(
        exit_sentinel: list[int]) -> None:
    h = _harness("full", lib=_FakeSeccompLib(attr_ret=-1))
    with pytest.raises(_ExitCalled):
        h.fn()
    assert exit_sentinel[0] == 126
    assert b"BADARCH" in h.stderr()
    assert h.write_fds() == {2}


@requires_libseccomp
def test_load_failure_aborts_exec(exit_sentinel: list[int]) -> None:
    h = _harness("full", lib=_FakeSeccompLib(load_ret=-1))
    with pytest.raises(_ExitCalled):
        h.fn()
    assert exit_sentinel[0] == 126
    assert h.write_fds() == {2}


@requires_libseccomp
@pytest.mark.parametrize("config", [
    {},
    {"block_udp": True},
    {"block_ns_creation": True},
    {"deny_fd_exec": True},
    {"audit_mode": True, "observe_mode": True},
])
def test_every_rule_install_failure_aborts_exec(
        exit_sentinel: None, config: dict[str, Any]) -> None:
    """Sweep: fail seccomp_rule_add_array at EVERY index the given
    configuration installs, one at a time — each must abort the exec
    with exit 126 and a diagnostic on fd 2 exactly. A rule that fails
    open (skipped install, exec proceeds) silently drops that rule's
    policy for every child on the affected host."""
    baseline = _harness("full", **config)
    baseline.fn()
    total = len(baseline.lib.rules)
    assert total > 0
    for idx in range(total):
        codes: list[int] = []
        import os as _os
        real_exit = _os._exit
        def _record(code: int) -> None:
            codes.append(code)
            raise _ExitCalled(code)
        _os._exit = _record
        try:
            h = _harness("full", lib=_FakeSeccompLib(fail_rule_at=idx),
                         **config)
            with pytest.raises(_ExitCalled):
                h.fn()
        finally:
            _os._exit = real_exit
        assert codes[0] == 126, f"rule #{idx} did not abort 126"
        assert h.write_fds() == {2}, f"rule #{idx} diagnostic fd"
        assert h.stderr(), f"rule #{idx} aborted without a diagnostic"


@requires_libseccomp
def test_unresolved_syscalls_fail_closed_for_requested_controls(
        exit_sentinel: list[int]) -> None:
    """A REQUESTED control whose syscall cannot be resolved must not
    silently vanish: block_udp without socket(2), and deny_fd_exec
    without memfd_create/execveat, abort the exec."""
    h = _harness("full", block_udp=True)
    _cells(h.fn)["socket_num"].cell_contents = -1
    with pytest.raises(_ExitCalled):
        h.fn()
    assert exit_sentinel[0] == 126
    assert b"block_udp" in h.stderr()
    assert h.write_fds() == {2}

    for cell in ("memfd_create_num", "execveat_num"):
        exit_sentinel.clear()
        h = _harness("full", deny_fd_exec=True)
        _cells(h.fn)[cell].cell_contents = -1
        with pytest.raises(_ExitCalled):
            h.fn()
        assert exit_sentinel[0] == 126, cell
        assert h.write_fds() == {2}


@requires_libseccomp
def test_unexpected_install_exception_aborts_exec(
        exit_sentinel: list[int]) -> None:
    """ANY exception during install aborts the exec (BaseException
    catch-all — the child must never continue filterless), naming the
    exception on fd 2."""

    class _Boom(_FakeSeccompLib):
        def seccomp_attr_set(self, *a: Any) -> int:
            raise RuntimeError("boom")

    h = _harness("full", lib=_Boom())
    with pytest.raises(_ExitCalled):
        h.fn()
    assert exit_sentinel[0] == 126
    assert b"enforcement failed" in h.stderr()
    assert b"boom" in h.stderr()
    assert h.write_fds() == {2}


# ---------------------------------------------------------------------------
# ioctl deny payloads + zero-resolution for ioctl
# ---------------------------------------------------------------------------


@requires_libseccomp
def test_blocked_tty_ioctls_filter_cmd_argument_low32(
        exit_sentinel: list[int]) -> None:
    """The tty-hijack ioctls are denied by cmd value on ARGUMENT 1
    under the low-32 mask (the kernel reads cmd as unsigned int, so
    exact equality misses TIOCSTI | 1<<32)."""
    import termios
    h = _harness("full")
    h.fn()
    ioctl_num = _cell(h.fn, "ioctl_num")
    rules = [r for r in h.lib.rules
             if r.num == ioctl_num and len(r.args) == 1]
    cmds = {r.args[0][3] for r in rules}
    for name in ("TIOCSTI", "TIOCCONS", "TIOCSCTTY"):
        want = getattr(termios, name, None)
        if want is None:
            continue
        assert want in cmds, name
    for r in rules:
        assert r.args[0][0] == 1        # cmd argument
        assert r.args[0][1] == sc._SCMP_CMP_MASKED_EQ
        assert r.args[0][2] == _ARG32


@requires_libseccomp
def test_ioctl_number_zero_counts_as_resolved(
        exit_sentinel: list[int]) -> None:
    h = _harness("full")
    _cells(h.fn)["ioctl_num"].cell_contents = 0
    h.fn()
    assert any(r.num == 0 and len(r.args) == 1 for r in h.lib.rules)


# ---------------------------------------------------------------------------
# connect-scoping (unix_scope_export_sock) arm
# ---------------------------------------------------------------------------


def _scope_pair() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)


@requires_libseccomp
def test_connect_scoping_installs_notify_and_ships_the_fd(
        exit_sentinel: list[int]) -> None:
    """The scoping arm puts SCMP_ACT_NOTIFY on connect(2), denies the
    AF_UNIX datagram shapes that would bypass the chokepoint, and
    ships the notify fd to the supervisor with the pinned-device
    payload — connect(2) is unusable until supervised, so the export
    must happen before exec."""
    parent, child = _scope_pair()
    try:
        h = _harness("full", unix_scope_export_sock=child)
        h.fn()
        connect_num = _cell(h.fn, "connect_num")
        assert connect_num >= 0
        notify = [r for r in h.lib.rules
                  if r.num == connect_num and not r.args]
        assert notify and notify[0].action == sc._SCMP_ACT_NOTIFY
        # supervisor side receives the payload + one fd
        import array as _array
        msg, ancdata, _flags, _addr = parent.recvmsg(
            64, socket.CMSG_SPACE(4))
        assert msg.startswith(b"F2")
        fds = _array.array("i")
        for _level, _type, data in ancdata:
            fds.frombytes(data[:4])
        assert len(fds) == 1
        import os as _os
        _os.close(fds[0])
    finally:
        parent.close()
        try:
            child.close()
        except OSError:
            pass


@requires_libseccomp
def test_connect_scoping_treats_syscall_zero_as_resolved(
        exit_sentinel: list[int]) -> None:
    parent, child = _scope_pair()
    try:
        h = _harness("full", unix_scope_export_sock=child)
        _cells(h.fn)["connect_num"].cell_contents = 0
        _cells(h.fn)["socket_num"].cell_contents = 0
        h.fn()
        assert exit_sentinel == []
        assert any(r.num == 0 and not r.args
                   and r.action == sc._SCMP_ACT_NOTIFY
                   for r in h.lib.rules)
        # the AF_UNIX dgram socket deny rides socket_num too
        assert any(r.num == 0 and len(r.args) == 2
                   and r.args[0][3] == socket.AF_UNIX
                   and r.args[1][3] == socket.SOCK_DGRAM
                   for r in h.lib.rules)
    finally:
        parent.close()
        try:
            child.close()
        except OSError:
            pass


@requires_libseccomp
def test_connect_scoping_fails_closed_without_notify_fd(
        exit_sentinel: list[int]) -> None:
    parent, child = _scope_pair()
    try:
        h = _harness("full", unix_scope_export_sock=child,
                     lib=_FakeSeccompLib(notify_fd=-1))
        with pytest.raises(_ExitCalled):
            h.fn()
        assert exit_sentinel[0] == 126
        assert b"seccomp_notify_fd failed" in h.stderr()
        assert h.write_fds() == {2}
    finally:
        parent.close()
        try:
            child.close()
        except OSError:
            pass


@requires_libseccomp
def test_connect_scoping_fails_closed_when_export_fails(
        exit_sentinel: list[int]) -> None:
    parent, child = _scope_pair()
    child.close()  # sendmsg on a closed socket raises OSError
    try:
        h = _harness("full", unix_scope_export_sock=child)
        with pytest.raises(_ExitCalled):
            h.fn()
        assert exit_sentinel[0] == 126
        assert b"notify fd export" in h.stderr()
        assert h.write_fds() == {2}
    finally:
        parent.close()


@requires_libseccomp
def test_unresolved_connect_fails_closed_for_scoping(
        exit_sentinel: list[int]) -> None:
    parent, child = _scope_pair()
    try:
        h = _harness("full", unix_scope_export_sock=child)
        _cells(h.fn)["connect_num"].cell_contents = -1
        with pytest.raises(_ExitCalled):
            h.fn()
        assert exit_sentinel[0] == 126
        assert b"connect() is" in h.stderr() or b"unresolved" in h.stderr()
    finally:
        parent.close()
        try:
            child.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# builder-side diagnostics + selftest parent bookkeeping
# ---------------------------------------------------------------------------


@requires_libseccomp
def test_healthy_build_reports_no_missing_syscalls(
        caplog: pytest.LogCaptureFixture) -> None:
    """On an arch where everything resolves, the missing-syscall
    warning must stay silent — an inverted membership check would cry
    wolf about every present syscall and train operators to ignore
    the one warning that matters on exotic arches."""
    state.reset_warn_once("_seccomp_arch_missing_warned")
    try:
        with caplog.at_level("WARNING"):
            _build("full")
        assert not any("could not resolve" in r.message
                       for r in caplog.records)
    finally:
        state.reset_warn_once("_seccomp_arch_missing_warned")


def test_selftest_reports_false_when_child_cannot_be_reaped(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Parent-side bookkeeping failure (waitpid says no such child)
    must report unavailable, never success — fail-open here would
    enable seccomp on hosts where the probe never actually ran."""
    import os as _os
    lib = mock.Mock()
    monkeypatch.setattr(_os, "fork", mock.Mock(return_value=2**22 + 3))
    assert sc._seccomp_functional_selftest(lib) is False


class _FailMatching(_FakeSeccompLib):
    """Fail rule installs selected by a predicate over (action, num,
    args) — reaches failure exits the index sweep cannot (rules that
    only exist under cell-forced configurations)."""

    def __init__(self, pred: Any, **kw: Any) -> None:
        super().__init__(**kw)
        self._pred = pred

    def seccomp_rule_add_array(self, ctx: Any, action: int, num: int,
                               argc: int, argv: Any) -> int:
        ret = super().seccomp_rule_add_array(ctx, action, num, argc,
                                             argv)
        rule = self.rules[-1]
        if self._pred(rule):
            return -1
        return ret


@requires_libseccomp
def test_socketcall_multiplexer_rule_installs_and_fails_closed(
        exit_sentinel: list[int]) -> None:
    """On arches that retain socketcall(2), the multiplexer must be
    denied wholesale (its real arguments hide in user memory — an
    unfiltered socketcall bypasses every socket-argument rule), and a
    failed install aborts the exec."""
    h = _harness("full")
    _cells(h.fn)["socketcall_num"].cell_contents = 0
    h.fn()
    assert any(r.num == 0 for r in h.lib.rules)

    lib = _FailMatching(lambda r: r.num == 0)
    h = _Harness(_build("full"), lib)
    _cells(h.fn)["socketcall_num"].cell_contents = 0
    with pytest.raises(_ExitCalled):
        h.fn()
    assert exit_sentinel[0] == 126
    assert b"socketcall rule" in h.stderr()
    assert h.write_fds() == {2}


@requires_libseccomp
def test_connect_scoping_rule_failures_abort_exec(
        exit_sentinel: list[int]) -> None:
    """Both scoping-arm installs fail closed: the connect NOTIFY rule
    (an unsupervised NOTIFY would hang the child) and the AF_UNIX
    dgram deny (the datagram bypass of the connect chokepoint)."""
    parent, child = _scope_pair()
    try:
        lib = _FailMatching(
            lambda r: r.action == sc._SCMP_ACT_NOTIFY)
        h = _Harness(_build("full", unix_scope_export_sock=child), lib)
        with pytest.raises(_ExitCalled):
            h.fn()
        assert exit_sentinel[0] == 126
        assert b"connect NOTIFY" in h.stderr()
        assert h.write_fds() == {2}
    finally:
        parent.close()
        try:
            child.close()
        except OSError:
            pass

    exit_sentinel.clear()
    parent, child = _scope_pair()
    try:
        sock_num = None

        def _is_unix_dgram(r: _Rule) -> bool:
            return (len(r.args) == 2
                    and r.args[0][3] == socket.AF_UNIX
                    and r.args[1][3] == socket.SOCK_DGRAM
                    and r.num == sock_num)

        fn = _build("full", unix_scope_export_sock=child)
        sock_num = _cell(fn, "socket_num")
        h = _Harness(fn, _FailMatching(_is_unix_dgram))
        with pytest.raises(_ExitCalled):
            h.fn()
        assert exit_sentinel[0] == 126
        assert b"AF_UNIX DGRAM" in h.stderr()
        assert h.write_fds() == {2}
    finally:
        parent.close()
        try:
            child.close()
        except OSError:
            pass

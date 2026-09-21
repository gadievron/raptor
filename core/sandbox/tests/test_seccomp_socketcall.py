"""socketcall(2) multiplexer deny — shape-verified.

On architectures where the socket API multiplexes through
socketcall(2) (s390x among the supported set), every socket-ARGUMENT
seccomp rule — the family allowlist, SOCK_RAW, the protocol/type
denies, the UDP block, MSG_FASTOPEN — is bypassable via the
multiplexer: its real arguments live in a user-memory array no BPF
filter can dereference, so the filter sees only the call number. The
builder therefore denies socketcall with ENOSYS wherever the arch
defines it, driving libc fallback to the direct, filterable syscalls
(the clone3 treatment).

Honesty about verification tier: there is no s390x host here, so the
kernel-level behaviour is verified by SHAPE — a recording fake of the
libseccomp handle captures the exact rules the builder installs when
"socketcall" resolves to a positive number, and the negative-
resolution no-op is pinned live for the direct-syscall arches. The
preexec closure runs in a forked child because it sets
PR_SET_NO_NEW_PRIVS (one-way) on the calling process.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import platform
import sys
import warnings
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox import seccomp, state  # noqa: E402

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux seccomp internals",
)

_ENOSYS_ACTION = seccomp._SCMP_ACT_ERRNO(38)
_SOCKETCALL_FAKE_NUM = 4242


class _Fn:
    """Callable that tolerates the builder's .restype/.argtypes
    assignments (plain instance attributes)."""

    def __init__(self, impl):
        self._impl = impl

    def __call__(self, *args):
        return self._impl(*args)


class _RecordingLib:
    """libseccomp stand-in: records every rule the builder adds."""

    def __init__(self, resolve_overrides: dict[str, int] | None = None):
        self.rules: list[tuple[int, int, list[list[int]]]] = []
        self._names: dict[str, int] = {}
        self._overrides = dict(resolve_overrides or {})
        self.seccomp_init = _Fn(lambda act: 1)
        self.seccomp_attr_set = _Fn(lambda ctx, attr, val: 0)
        self.seccomp_rule_add_array = _Fn(self._rule_add)
        self.seccomp_load = _Fn(lambda ctx: 0)
        self.seccomp_release = _Fn(lambda ctx: None)
        self.seccomp_syscall_resolve_name = _Fn(self._resolve)

    def _resolve(self, name_bytes: bytes) -> int:
        name = name_bytes.decode("ascii")
        if name in self._overrides:
            return self._overrides[name]
        # Deterministic positive numbers for everything else — the
        # builder only compares against 0 and uses them as opaque ids.
        return self._names.setdefault(name, 1000 + len(self._names))

    def _rule_add(self, ctx, action, num, argc, args) -> int:
        cmps = [
            [int(args[i].arg), int(args[i].op),
             int(args[i].datum_a), int(args[i].datum_b)]
            for i in range(argc)
        ]
        self.rules.append((int(action), int(num), cmps))
        return 0


def _rules_for(resolve_overrides: dict[str, int],
               **builder_kwargs) -> list[tuple[int, int, list[list[int]]]]:
    """Build the preexec against the recording fake, execute it in a
    forked child (PR_SET_NO_NEW_PRIVS is one-way), and return the
    recorded rules."""
    fake = _RecordingLib(resolve_overrides)
    with mock.patch.object(state, "_libseccomp_cache", fake), \
            mock.patch.object(seccomp, "check_seccomp_available",
                              return_value=True):
        fn = seccomp._make_seccomp_preexec("default", **builder_kwargs)
    assert fn is not None
    r, w = os.pipe()
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", category=DeprecationWarning,
            message=r".*fork.*may lead to deadlocks.*",
        )
        pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            fn()
            payload = json.dumps(fake.rules).encode()
            os.write(w, payload)
            os._exit(0)
        except BaseException:  # noqa: BLE001 — post-fork: never unwind into pytest
            os._exit(1)
    os.close(w)
    chunks = []
    while True:
        b = os.read(r, 65536)
        if not b:
            break
        chunks.append(b)
    os.close(r)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, "preexec child failed"
    return [tuple([a, n, c]) for a, n, c in json.loads(b"".join(chunks))]


class TestSocketcallDeny:
    def test_unconditional_enosys_rule_when_arch_has_socketcall(self):
        rules = _rules_for({"socketcall": _SOCKETCALL_FAKE_NUM})
        sc = [r for r in rules if r[1] == _SOCKETCALL_FAKE_NUM]
        assert len(sc) == 1, rules
        action, _num, cmps = sc[0]
        # ENOSYS (fallback-driving, the clone3 treatment), never
        # EPERM: a libc that probes the multiplexer must conclude
        # "absent" and take the direct syscalls the filter governs.
        assert action == _ENOSYS_ACTION
        # Unconditional — no argument comparators: the call number in
        # arg 0 is the only inspectable datum and no subset of call
        # numbers is safe when the real arguments are uninspectable.
        assert cmps == []

    def test_enosys_survives_audit_mode(self):
        # Audit mode swaps deny → TRACE for the observable blocklist;
        # the multiplexer must NOT become allow-and-log (it wraps the
        # very socket-argument rules that stay hard under audit).
        rules = _rules_for({"socketcall": _SOCKETCALL_FAKE_NUM},
                           audit_mode=True)
        sc = [r for r in rules if r[1] == _SOCKETCALL_FAKE_NUM]
        assert len(sc) == 1, rules
        assert sc[0][0] == _ENOSYS_ACTION

    def test_no_rule_where_arch_lacks_socketcall(self):
        # libseccomp returns a negative pseudo-number on arches
        # without the multiplexer; the builder must skip the rule
        # (there is no syscall to deny).
        pseudo = -10060
        rules = _rules_for({"socketcall": pseudo})
        assert not [r for r in rules if r[1] == pseudo], rules

    def test_direct_syscall_arch_resolves_socketcall_negative(self):
        # Live pin for the arches this host can verify: x86_64 and
        # aarch64 64-bit userspace never had the multiplexer wired,
        # so the real resolver must return a negative number and the
        # rule is a no-op here — the load-bearing arch is s390x,
        # covered by the shape tests above.
        if platform.machine() not in ("x86_64", "aarch64"):
            pytest.skip("pin only meaningful on direct-syscall arches")
        libname = ctypes.util.find_library("seccomp")
        if not libname:
            pytest.skip("libseccomp unavailable")
        lib = ctypes.CDLL(libname)
        lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
        lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        assert lib.seccomp_syscall_resolve_name(b"socketcall") < 0

"""Tests for core.sandbox.seccomp's audit_mode kwarg.

Audit mode swaps the deny action from SCMP_ACT_ERRNO(EPERM) to
SCMP_ACT_TRACE so the attached ptrace tracer is notified instead of
the syscall failing. Also adds open/openat/connect to the trace set
for b3 filesystem + network audit coverage.

These tests exercise the helpers directly (constants, kwarg shape,
audit_extra resolution). The full live behaviour — installed filter
firing TRACE events, tracer receiving them — needs the spawn
integration in this same commit; the end-to-end test there is the
proof that the wiring works.
"""

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (mount-ns / Landlock / seccomp / ptrace tracer / pid1 shim) — see core/sandbox/_macos_spawn.py for the macOS path",
)


import pytest  # noqa: E402

from core.sandbox import seccomp  # noqa: E402


class TestScmpActTrace:
    """SCMP_ACT_TRACE construction helper. Action value layout is:
    bits [31:24] = action class (0x7f = TRACE)
    bits [23:16] = filter return code (we use 0)
    bits [15:0]  = msg_num passed to the tracer (we use 0)
    Total expected value: 0x7ff00000.
    """

    def test_trace_action_value_default(self):
        # Default msg_num=0 → exactly 0x7ff00000.
        assert seccomp._SCMP_ACT_TRACE() == 0x7ff00000

    def test_trace_action_includes_msg_num(self):
        # msg_num is OR'd into the low 16 bits.
        assert seccomp._SCMP_ACT_TRACE(0x42) == 0x7ff00042

    def test_trace_action_msg_num_masked_to_16_bits(self):
        # Values > 16 bits should be masked, not corrupt the action class.
        assert seccomp._SCMP_ACT_TRACE(0x10042) == 0x7ff00042

    def test_trace_action_distinct_from_errno_action(self):
        # Sanity: TRACE and ERRNO actions live in different action-class
        # ranges so the kernel dispatches them to different handlers.
        # Without this distinction, audit-mode rules would still EPERM
        # the syscall instead of pausing for the tracer.
        assert seccomp._SCMP_ACT_TRACE() != seccomp._SCMP_ACT_ERRNO(1)


class TestAuditExtraSyscalls:
    """The audit-mode-only trace set adds open/openat/connect on top
    of the existing blocklist. Pin the membership so a future change
    can't silently drop b3 path coverage."""

    def test_includes_open_and_openat(self):
        assert "open" in seccomp._AUDIT_EXTRA_TRACE_SYSCALLS
        assert "openat" in seccomp._AUDIT_EXTRA_TRACE_SYSCALLS

    def test_includes_connect(self):
        assert "connect" in seccomp._AUDIT_EXTRA_TRACE_SYSCALLS

    def test_does_not_overlap_existing_blocklist(self):
        # The audit-extras are syscalls that aren't normally blocked.
        # Adding open/openat/connect to _SECCOMP_BLOCK_ALWAYS would be
        # a serious regression (would EPERM ALL file/network operations
        # under enforcement mode). Pin the disjointness invariant.
        always = set(seccomp._SECCOMP_BLOCK_ALWAYS)
        unless_debug = set(seccomp._SECCOMP_BLOCK_UNLESS_DEBUG)
        extras = set(seccomp._AUDIT_EXTRA_TRACE_SYSCALLS)
        overlap = (always | unless_debug) & extras
        assert overlap == set(), (
            f"audit-extra syscalls overlap with blocklist: {overlap} — "
            f"would be blocked under enforcement, breaking everything"
        )


class TestAuditHardDenySet:
    """Escape primitives must keep the ERRNO action under audit mode —
    allow-and-log would grant an audited child the very capabilities
    (cross-process memory reads, kernel keyring, Landlock-bypassing
    io_uring, bpf/userfaultfd) the sandbox exists to deny."""

    def test_set_is_subset_of_blocklist(self):
        blocklist = (set(seccomp._SECCOMP_BLOCK_ALWAYS)
                     | set(seccomp._SECCOMP_BLOCK_UNLESS_DEBUG))
        stray = seccomp._AUDIT_HARD_DENY_SYSCALLS - blocklist
        assert stray == set(), (
            f"hard-deny entries not in any blocklist: {stray} — they "
            f"would never have a rule installed")

    def test_escape_primitives_pinned(self):
        # Membership pin: dropping any of these silently restores the
        # allow-and-log downgrade for a live escape primitive.
        for name in ("ptrace", "process_vm_readv", "process_vm_writev",
                     "keyctl", "add_key", "request_key",
                     "bpf", "userfaultfd",
                     "io_uring_setup", "io_uring_enter",
                     "io_uring_register"):
            assert name in seccomp._AUDIT_HARD_DENY_SYSCALLS

    def test_observational_syscalls_not_hard_denied(self):
        # The audit/observe trace sets must stay trace-allow — that
        # is the observational signal audit mode exists for.
        extras = (set(seccomp._AUDIT_EXTRA_TRACE_SYSCALLS)
                  | set(seccomp._OBSERVE_EXTRA_TRACE_SYSCALLS))
        overlap = extras & seccomp._AUDIT_HARD_DENY_SYSCALLS
        assert overlap == set()

    def _run_syscall_in_audit_child(self, syscall_name, *args):
        """Fork a child, install the audit-mode filter (NO tracer),
        invoke *syscall_name* via raw syscall(2), report
        ``(returncode_or_signal, result, errno)``.

        Everything the child calls post-load (write, exit_group,
        raw syscall) is outside the TRACE set, so no tracer is needed
        unless the tested syscall itself is TRACE-action — in which
        case the kernel fails it with ENOSYS (no tracer attached),
        which is exactly the differential this harness measures.
        """
        import ctypes
        import ctypes.util
        import os
        import warnings

        from core.sandbox import state
        from core.sandbox.seccomp import check_seccomp_available

        if not check_seccomp_available():
            pytest.skip("libseccomp unavailable")
        pre = seccomp._make_seccomp_preexec("full", audit_mode=True)
        assert pre is not None

        lib = state._libseccomp_cache
        nr = lib.seccomp_syscall_resolve_name(syscall_name.encode())
        if nr < 0:
            pytest.skip(f"{syscall_name} unresolved on this arch")

        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        libc.syscall.restype = ctypes.c_long
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
                pre()  # os._exit(126) internally on install failure
                res = libc.syscall(
                    ctypes.c_long(nr),
                    *[ctypes.c_long(a) for a in args],
                )
                err = ctypes.get_errno()
                os.write(w, f"{res}:{err}".encode("ascii"))
                os._exit(0)
            except BaseException:  # noqa: BLE001 — post-fork guard
                os._exit(120)
        os.close(w)
        try:
            data = os.read(r, 256)
        finally:
            os.close(r)
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            return -os.WTERMSIG(status), None, None
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, (
            f"child exited {os.WEXITSTATUS(status)}"
        )
        res_s, err_s = data.decode("ascii").split(":")
        return 0, int(res_s), int(err_s)

    @pytest.mark.skipif(_sys.platform != "linux", reason="Linux-only")
    def test_keyctl_denied_with_eperm_under_audit(self):
        import errno as _errno
        rc, res, err = self._run_syscall_in_audit_child(
            "keyctl", 0, 0, 0, 0, 0)
        assert rc == 0, f"child died by signal {-rc}"
        assert res == -1
        assert err == _errno.EPERM, (
            f"keyctl under audit mode returned errno {err}; expected "
            f"EPERM — the escape primitive was allow-and-logged")

    @pytest.mark.skipif(_sys.platform != "linux", reason="Linux-only")
    def test_openat_stays_trace_action_under_audit(self):
        # Differential control: openat is in the observational trace
        # set. With no tracer attached the kernel fails a TRACE-action
        # syscall with ENOSYS — proving the rule is TRACE, not ERRNO.
        import errno as _errno
        _AT_FDCWD = -100
        rc, res, err = self._run_syscall_in_audit_child(
            "openat", _AT_FDCWD, 0, 0, 0)
        assert rc == 0, f"child died by signal {-rc}"
        assert res == -1
        assert err == _errno.ENOSYS, (
            f"openat under audit mode (no tracer) returned errno "
            f"{err}; expected ENOSYS from the unhandled TRACE action")


class TestMakeSeccompPreexecAuditKwarg:
    """The audit_mode kwarg flows through _make_seccomp_preexec without
    breaking the no-libseccomp-available fast-path."""

    def test_kwarg_accepted(self):
        # If libseccomp is missing the function returns None regardless
        # of audit_mode value — fast path. We just verify it doesn't
        # raise on the new kwarg.
        # Skip if libseccomp IS available (then we'd actually try to
        # build the filter, which needs more setup).
        from core.sandbox import check_seccomp_available
        if check_seccomp_available():
            pytest.skip("libseccomp available — kwarg fast-path not exercised")
        result = seccomp._make_seccomp_preexec(
            "full", block_udp=False, audit_mode=True,
        )
        assert result is None  # libseccomp unavailable

    def test_audit_mode_with_no_profile_returns_none(self):
        # Profile "none" disables seccomp entirely; audit_mode shouldn't
        # accidentally re-enable it.
        result = seccomp._make_seccomp_preexec(
            "none", block_udp=False, audit_mode=True,
        )
        assert result is None

    def test_default_audit_mode_is_false(self):
        # Backwards compatibility: existing callers passing only profile
        # + block_udp must get the SAME behaviour as before (deny =
        # ERRNO, no audit-extra trace set). Default audit_mode=False
        # protects that.
        import inspect
        sig = inspect.signature(seccomp._make_seccomp_preexec)
        assert sig.parameters["audit_mode"].default is False

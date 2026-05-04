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


import pytest

from core.sandbox import seccomp


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

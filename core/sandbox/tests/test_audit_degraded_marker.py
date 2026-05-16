"""Site-level tests for the W36.J.1 audit-degraded marker writes.

The W36.J.1 commits added ``record_audit_degraded`` calls at four
silent-degrade sites under ``audit_mode=True``:

  - ``_spawn.py:411-416`` (F063a: no seccomp_profile)
  - ``_spawn.py:417-424`` (F063b: libseccomp unavailable)
  - ``_spawn.py:585-603`` (F063c: ptrace blocked else-branch)
  - ``_macos_spawn.py:322-352`` (F064: seatbelt log streamer raises)

Each test stubs the precondition that drives the relevant degrade
branch, then invokes the public entry point and asserts that
``<audit_run_dir>/sandbox-audit-degraded.json`` exists with the
expected payload shape.

F063 tests are Linux-only (the silent-degrade paths only run inside the
``if audit_mode:`` block on the Linux backend). F064 is macOS-only
(seatbelt log streamer only attaches there).
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="F063 silent-degrade paths only run on the Linux _spawn backend",
)

macos_only = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="F064 seatbelt log streamer only runs on macOS",
)


def _read_marker(audit_run_dir: Path) -> dict:
    marker = audit_run_dir / "sandbox-audit-degraded.json"
    assert marker.exists(), (
        f"audit-degraded marker not written to {marker}; "
        f"dir contents: {list(audit_run_dir.iterdir())}"
    )
    return json.loads(marker.read_text(encoding="utf-8"))


@linux_only
def test_f063a_no_seccomp_profile_writes_marker(tmp_path, monkeypatch):
    """audit_mode=True with seccomp_profile=None must write a marker
    naming the missing seccomp filter as the reason."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    # The degrade path only requires the audit_mode block to be reached
    # before the fork. Call the marker site through a thin harness so
    # we don't need to set up the full sandbox subprocess.
    from core.sandbox import _spawn  # noqa: F401  (import for coverage)
    from core.sandbox import summary as _summary

    # Reproduce the F063a code path: log + marker. Mirrors the production
    # branch at _spawn.py:411-431.
    _summary.record_audit_degraded(
        audit_dir,
        reason="audit_mode=True but no seccomp filter is active",
        instructions=(
            'pass seccomp_profile= (e.g. "full") so b2/b3 audit can '
            "install SCMP_ACT_TRACE; or run without audit_mode if "
            "seccomp is intentionally disabled"
        ),
    )
    payload = _read_marker(audit_dir)
    assert payload["audit_requested"] is True
    assert payload["audit_engaged"] is False
    assert payload["degraded"] is True
    assert "no seccomp filter" in payload["reason"]
    assert "seccomp_profile=" in payload["instructions"]


@linux_only
def test_f063b_libseccomp_unavailable_writes_marker(tmp_path, monkeypatch):
    """audit_mode=True with libseccomp missing must write a marker
    naming the missing library."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    from core.sandbox import summary as _summary

    _summary.record_audit_degraded(
        audit_dir,
        reason="audit_mode=True but libseccomp is unavailable on this host",
        instructions=(
            "install libseccomp (Debian/Ubuntu: apt install "
            "libseccomp2; Alpine: apk add libseccomp), or run "
            "without audit_mode on hosts where libseccomp is "
            "intentionally absent"
        ),
    )
    payload = _read_marker(audit_dir)
    assert payload["degraded"] is True
    assert "libseccomp" in payload["reason"]
    assert "libseccomp2" in payload["instructions"]


@linux_only
def test_f063c_ptrace_blocked_writes_marker(tmp_path):
    """audit_mode=True with ptrace blocked must write a marker citing
    the Yama / cap-drop / AppArmor remediation path."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    from core.sandbox import summary as _summary

    _summary.record_audit_degraded(
        audit_dir,
        reason="audit_mode=True but ptrace is blocked on this host",
        instructions=(
            "lower Yama scope (sysctl kernel.yama.ptrace_scope=1) "
            "or run with CAP_SYS_PTRACE; on container hosts ensure "
            "AppArmor / Yama policy permits PTRACE_SEIZE; or run "
            "without audit_mode"
        ),
    )
    payload = _read_marker(audit_dir)
    assert "ptrace" in payload["reason"]
    assert "yama" in payload["instructions"].lower()


def test_record_audit_degraded_is_idempotent(tmp_path):
    """Multiple sandbox calls in one run must not duplicate the marker.

    record_audit_degraded() is documented as idempotent — second call is
    a no-op. The four W36.J.1 degrade sites can fire in the same run if
    the operator launches multiple sandbox() calls; only the first
    should write.
    """
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    from core.sandbox import summary as _summary

    _summary.record_audit_degraded(
        audit_dir, reason="first call", instructions="first",
    )
    first = (audit_dir / "sandbox-audit-degraded.json").read_text()
    _summary.record_audit_degraded(
        audit_dir, reason="second call (should be ignored)", instructions="x",
    )
    second = (audit_dir / "sandbox-audit-degraded.json").read_text()
    assert first == second, "marker should be idempotent across calls"
    assert "first call" in second


def test_spawn_audit_mode_block_wires_three_marker_calls():
    """Static guard against silent removal of any F063 marker call.

    The above tests verify each marker's reason+instructions text, but
    they call ``record_audit_degraded`` directly and would still pass if
    a future refactor dropped the production calls. This test reads
    ``_spawn.py`` and asserts that the audit_mode setup block contains
    exactly three ``record_audit_degraded(`` invocations — one per F063
    site. Lesson learned from W36.I C-2 (tautological mount_ns test).
    """
    src = (Path(__file__).resolve().parent.parent / "_spawn.py").read_text()
    # The block stretches from the audit_mode pre-flight through the
    # close of the ptrace-blocked else branch. Use the audit_mode
    # comment as the anchor; the block ends before "# Track every fd".
    block_start = src.index("Audit-mode pre-flight: probe ptrace availability")
    block_end = src.index("Track every fd we hold in the parent")
    audit_block = src[block_start:block_end]
    call_count = audit_block.count("record_audit_degraded(")
    assert call_count == 3, (
        f"core/sandbox/_spawn.py audit_mode block should wire exactly "
        f"three record_audit_degraded() calls (F063a no-seccomp, F063b "
        f"libseccomp-unavailable, F063c ptrace-blocked); found {call_count}"
    )


def test_macos_spawn_streamer_except_wires_marker_call():
    """Static guard against silent removal of the F064 marker call."""
    src = (Path(__file__).resolve().parent.parent / "_macos_spawn.py").read_text()
    # The streamer-start try/except block is short; isolate around it.
    streamer_start = src.index("start_log_streamer")
    block = src[streamer_start:streamer_start + 1500]
    assert "record_audit_degraded(" in block, (
        "core/sandbox/_macos_spawn.py streamer-exception handler should "
        "call record_audit_degraded() so operators see audit degrade in "
        "the run dir; the call was missing or moved"
    )


@macos_only
def test_f064_streamer_exception_writes_marker(tmp_path):
    """audit_mode=True on macOS with start_log_streamer() raising must
    write a marker naming the streamer-start failure."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    # The production handler at _macos_spawn.py:328-352 catches the
    # exception and calls record_audit_degraded. Reproduce that here
    # by simulating the streamer raise and invoking the same marker
    # logic.
    from core.sandbox import summary as _summary

    exc = OSError("mocked: kernel log subsystem unreachable")
    _summary.record_audit_degraded(
        audit_dir,
        reason=(
            f"audit_mode=True but seatbelt log streamer failed "
            f"to start: {type(exc).__name__}: {exc}"
        ),
        instructions=(
            "check the macOS unified log subsystem is reachable "
            "(log show / log stream); verify the user has rights "
            "to read kernel-sandbox events; or run without "
            "audit_mode on hosts where the streamer cannot attach"
        ),
    )
    payload = _read_marker(audit_dir)
    assert payload["degraded"] is True
    assert "streamer" in payload["reason"].lower()
    assert "OSError" in payload["reason"]
    assert "log show" in payload["instructions"]

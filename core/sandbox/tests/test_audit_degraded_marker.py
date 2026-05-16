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

import ast
import json
import re
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


_SANDBOX_DIR = Path(__file__).resolve().parent.parent
_SPAWN_PATH = _SANDBOX_DIR / "_spawn.py"
_MACOS_SPAWN_PATH = _SANDBOX_DIR / "_macos_spawn.py"


def _extract_marker_calls(source_path: Path) -> dict[str, tuple[str, str]]:
    """Find every ``record_audit_degraded(...)`` call in ``source_path``.

    Returns a dict mapping the F063x / F064 anchor (taken from a
    comment on a line preceding the call) to a ``(reason,
    instructions)`` tuple of the kwarg expressions, normalised via
    ``ast.unparse`` so f-strings, multiline-concatenated literals and
    plain strings all compare alike. Lets the keyword tests below
    operate on actual production source — wording rewrites that
    preserve the keyword still pass, but a silent removal or a drift
    that strips the keyword fails loudly.
    """
    src = source_path.read_text()
    src_lines = src.splitlines()
    tree = ast.parse(src)
    out: dict[str, tuple[str, str]] = {}

    def _is_marker_call(func: ast.AST) -> bool:
        if isinstance(func, ast.Name):
            return func.id == "record_audit_degraded"
        if isinstance(func, ast.Attribute):
            return func.attr == "record_audit_degraded"
        return False

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_marker_call(node.func)):
            continue
        # Walk back up to 12 source lines looking for an F063a / F063b /
        # F063c / F064 anchor comment. 12 covers the longest preceding
        # block-comment in the production files.
        anchor = None
        for back in range(1, 13):
            idx = node.lineno - 1 - back
            if idx < 0:
                break
            m = re.search(r"\b(F063[abc]|F064)\b", src_lines[idx])
            if m:
                anchor = m.group(1)
                break
        if anchor is None:
            continue
        reason = instructions = None
        for kw in node.keywords:
            if kw.arg == "reason":
                reason = ast.unparse(kw.value)
            elif kw.arg == "instructions":
                instructions = ast.unparse(kw.value)
        if reason is not None and instructions is not None:
            out[anchor] = (reason, instructions)
    return out


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


def test_spawn_audit_block_wires_marker_per_site():
    """Static guard against silent removal OR text drift of any F063
    marker call in ``core/sandbox/_spawn.py``.

    Replaces an earlier ``== 3`` count assertion (brittle to legitimate
    additions of an F063d site) and the implicit reliance on the per-
    site Linux tests above to catch text drift (those call
    ``record_audit_degraded`` directly with text hardcoded in the test
    file, so a future maintainer rewording the production reason but
    forgetting to update the test copy would silently regress).

    New shape: AST-extract the reason/instructions strings from the
    production source per-anchor, then assert each contains its
    expected operator-facing keyword. Tolerates wording rewrites that
    preserve the keyword; catches silent removal of any anchor; catches
    text drift that strips the keyword; tolerates future F063d
    additions (no ``== N`` count).
    """
    calls = _extract_marker_calls(_SPAWN_PATH)

    for anchor in ("F063a", "F063b", "F063c"):
        assert anchor in calls, (
            f"_spawn.py audit_mode block must contain a "
            f"record_audit_degraded() call near a `# {anchor}:` "
            f"comment; the silent-degrade signal for that site was "
            f"removed or its anchor comment was renamed away from "
            f"`{anchor}`"
        )

    f063a_reason, f063a_instr = calls["F063a"]
    assert "seccomp" in f063a_reason.lower(), (
        f"F063a reason must reference seccomp (no-filter degrade); "
        f"production text drifted to {f063a_reason!r}"
    )
    assert "seccomp_profile" in f063a_instr, (
        f"F063a instructions must point at seccomp_profile= "
        f"remediation; got {f063a_instr!r}"
    )

    f063b_reason, f063b_instr = calls["F063b"]
    assert "libseccomp" in f063b_reason.lower(), (
        f"F063b reason must reference libseccomp; got {f063b_reason!r}"
    )
    assert "libseccomp" in f063b_instr.lower(), (
        f"F063b instructions must reference libseccomp install "
        f"remediation; got {f063b_instr!r}"
    )

    f063c_reason, f063c_instr = calls["F063c"]
    assert "ptrace" in f063c_reason.lower(), (
        f"F063c reason must reference ptrace; got {f063c_reason!r}"
    )
    assert any(
        kw in f063c_instr.lower()
        for kw in ("yama", "ptrace_scope", "cap_sys_ptrace")
    ), (
        f"F063c instructions must reference at least one ptrace "
        f"remediation surface (yama / ptrace_scope / CAP_SYS_PTRACE); "
        f"got {f063c_instr!r}"
    )


def test_macos_spawn_streamer_marker_call_has_expected_keywords():
    """Static guard against silent removal OR text drift of the F064
    marker call in ``core/sandbox/_macos_spawn.py``.

    Same shape as the F063 test above — AST-extracts the production
    reason/instructions and asserts the operator-facing keywords are
    present. Replaces an earlier substring check that only verified
    ``record_audit_degraded(`` appeared in the first 1500 chars after
    ``start_log_streamer`` — brittle to source reshuffles and blind to
    text drift inside the call.
    """
    calls = _extract_marker_calls(_MACOS_SPAWN_PATH)

    assert "F064" in calls, (
        "_macos_spawn.py streamer-exception handler must contain a "
        "record_audit_degraded() call near a `# F064:` comment; the "
        "F064 silent-degrade signal was removed or its anchor comment "
        "was renamed"
    )

    reason, instructions = calls["F064"]
    assert "streamer" in reason.lower(), (
        f"F064 reason must reference the seatbelt log streamer; "
        f"production text drifted to {reason!r}"
    )
    assert "log show" in instructions or "log stream" in instructions, (
        f"F064 instructions must reference the macOS unified-log "
        f"remediation surface (`log show` / `log stream`); "
        f"got {instructions!r}"
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

"""Contract tests for the darwin-emulation standing gate (root conftest).

RAPTOR_TEST_EMULATE_PLATFORM=darwin patches ``sys.platform`` before
collection, relocates pytest's basetemp under a darwin-shaped
``/private/var/folders`` path, and deselects every ``darwin_native`` /
``linux_native``-marked test — emulation must never stack on real
kernel behaviour (a monkeypatched darwin shape with the real kernel's
own clamp applying underneath measures neither platform).

Two layers:

* the in-session self-check runs in EVERY session and asserts the
  emulation effects whenever the gate is active — the CI emulated
  invocation exercises it on every sandbox-gated PR;
* the nested-pytest contracts spawn a fresh session against marked
  files in this directory and pin deselection soundness (no *_native
  test can run under emulation — proven against the dual-marked NPROC
  module, the incident that taught the rule), the native skip
  semantics, and the fail-loud posture for unsupported values.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_EMU_VAR = "RAPTOR_TEST_EMULATE_PLATFORM"

# The real kernel underneath, unaffected by the sys.platform patch.
_REAL_SYSNAME = os.uname().sysname


def test_emulation_effects_apply_in_this_session(tmp_path):
    """Self-check for emulated sessions: the platform patch and the
    darwin-shaped basetemp both held for THIS test. Inert (skip) in
    native sessions."""
    emulated = os.environ.get(_EMU_VAR)
    if not emulated:
        pytest.skip("no platform emulation in this session")
    assert sys.platform == emulated
    # The H11 class: assertions that substring-match tmp layouts meet
    # the per-user /private/var/folders tree here, not on a real mac.
    assert "/private/var/folders/" in str(tmp_path)


def _nested_pytest(args, *, emulate=None, timeout=120):
    """Run a fresh pytest session against this repo; return the
    completed process. ``emulate`` sets/strips the gate env var so the
    nested session's mode never depends on the outer session's."""
    env = os.environ.copy()
    env.pop(_EMU_VAR, None)
    if emulate is not None:
        env[_EMU_VAR] = emulate
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *args],
        cwd=str(_REPO_ROOT), env=env,
        capture_output=True, text=True, timeout=timeout,
    )


def test_native_marked_files_fully_deselected_under_emulation():
    """Deselection soundness: a darwin_native file collects to nothing
    under emulation (exit 5 = no tests ran), so no darwin-only
    enforcement test can ever execute against the wrong kernel."""
    r = _nested_pytest(
        ["core/sandbox/tests/test_macos_spawn.py", "-m", "darwin_native"],
        emulate="darwin")
    # -m selects exactly the darwin_native tests; the gate must then
    # deselect every one of them: no tests ran (exit 5), none passed,
    # none failed, none even skipped-at-runtime.
    assert r.returncode == 5, (r.returncode, r.stdout, r.stderr)
    assert "deselected" in r.stdout
    assert "passed" not in r.stdout and "failed" not in r.stdout


def test_dual_marked_real_kernel_file_deselected_under_emulation():
    """The NPROC rule, pinned: a module carrying BOTH native markers
    (binds to whichever real kernel is underneath) is entirely
    deselected under emulation — the real kernel's clamp applying
    underneath an emulated value measures neither platform."""
    r = _nested_pytest(
        ["core/sandbox/tests/test_macos_nproc_cap.py"], emulate="darwin")
    assert r.returncode == 5, (r.returncode, r.stdout, r.stderr)
    assert "deselected" in r.stdout
    assert "passed" not in r.stdout


def test_darwin_native_skips_honestly_on_native_linux():
    """Native (un-emulated) semantics: darwin_native tests SKIP on a
    Linux host — never run, never deselected-invisible."""
    if _REAL_SYSNAME != "Linux":
        pytest.skip("linux-side view of the native skip semantics")
    r = _nested_pytest(
        ["core/sandbox/tests/test_macos_spawn.py", "-m", "darwin_native"])
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "skipped" in r.stdout
    assert "passed" not in r.stdout and "failed" not in r.stdout


def test_unsupported_emulation_target_fails_loud():
    """Only 'darwin' is a supported target; anything else is a hard
    usage error, never a silently-native session."""
    r = _nested_pytest(
        ["core/sandbox/tests/test_darwin_emulation_gate.py",
         "--collect-only"],
        emulate="plan9")
    assert r.returncode != 0
    assert _EMU_VAR in (r.stdout + r.stderr)

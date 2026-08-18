"""Tests for ``packages.sca.patch_apply.apply_patch_to_target``.

Both ``raptor-sca fix --harden --apply`` and ``raptor-sca fix --cve-only --apply``
share this helper. The apply runs inside the target's (potentially
attacker-controlled) checkout, so it must route through
``core.sandbox.context.run_untrusted`` — a malicious ``.git/config``
can RCE via ``core.fsmonitor`` / ``core.sshCommand`` at git startup.
Most tests stub ``run_untrusted`` so no real ``git apply`` is fired —
we're testing the pre-flight (refusal policy + path resolution + log
lines), the sandbox wiring, and the result-mapping (exit-code
translation). The end-to-end tests execute the exact command the
helper builds against a real ``git init`` checkout to prove the
apply semantics survived the sandbox routing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List

import pytest

from packages.sca.patch_apply import apply_patch_to_target


def _make_patch(tmp_path: Path) -> Path:
    p = tmp_path / "upgrade.patch"
    p.write_text("diff --git a/x b/x\n", encoding="utf-8")
    return p


def _stub_run_untrusted(monkeypatch: pytest.MonkeyPatch,
                        returncode: int = 0, stdout: str = "",
                        stderr: str = "") -> List[dict]:
    """Replace ``run_untrusted`` with a recorder returning a fixed
    result. Returns the list the recorder appends into."""
    recorded: List[dict] = []

    def fake_run_untrusted(cmd, **kwargs):
        recorded.append({"cmd": cmd, **kwargs})
        return subprocess.CompletedProcess(
            args=cmd, returncode=returncode,
            stdout=stdout, stderr=stderr)

    monkeypatch.setattr(
        "core.sandbox.context.run_untrusted", fake_run_untrusted,
    )
    return recorded


def test_no_patch_path_is_graceful_noop(tmp_path: Path,
                                          capsys: pytest.CaptureFixture):
    """No patch generated == no work to do; not an error condition."""
    rc = apply_patch_to_target(tmp_path, None)
    assert rc == 0
    out = capsys.readouterr().out
    assert "no patch generated" in out


def test_missing_patch_file_is_graceful_noop(tmp_path: Path):
    """Patch path doesn't exist on disk → same as ``patch_path=None``."""
    rc = apply_patch_to_target(tmp_path, tmp_path / "absent.patch")
    assert rc == 0


def test_target_without_dot_git_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture,
):
    """Without ``.git`` we can't roll back — refuse and tell the operator
    where the patch lives so they can apply manually if they accept the
    risk."""
    patch = _make_patch(tmp_path)
    rc = apply_patch_to_target(tmp_path, patch)
    assert rc == 4
    err = capsys.readouterr().err
    assert "not a git checkout" in err
    assert str(patch) in err


def test_clean_apply_returns_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
):
    (tmp_path / ".git").mkdir()
    patch = _make_patch(tmp_path)
    _stub_run_untrusted(monkeypatch, returncode=0)
    rc = apply_patch_to_target(tmp_path, patch, caller_label="raptor-sca fix --cve-only")
    assert rc == 0
    out = capsys.readouterr().out
    assert "raptor-sca fix --cve-only --apply" in out


def test_apply_failure_propagates_returncode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
):
    (tmp_path / ".git").mkdir()
    patch = _make_patch(tmp_path)
    _stub_run_untrusted(monkeypatch, returncode=1,
                        stderr="error: patch failed: x:1")
    rc = apply_patch_to_target(tmp_path, patch)
    assert rc == 1
    err = capsys.readouterr().err
    assert "patch failed" in err


def test_subprocess_oserror_returns_5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
):
    """``git`` not in PATH (or other OSError) maps to a distinct exit
    code so CI can distinguish "git couldn't start" from "patch was
    rejected"."""
    (tmp_path / ".git").mkdir()
    patch = _make_patch(tmp_path)

    def boom(*a, **kw):
        raise FileNotFoundError("git not found")

    monkeypatch.setattr("core.sandbox.context.run_untrusted", boom)
    rc = apply_patch_to_target(tmp_path, patch)
    assert rc == 5


def test_caller_label_threads_into_log_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
):
    """Both harden and update share the helper; the label tells
    operators which subcommand emitted the message."""
    (tmp_path / ".git").mkdir()
    patch = _make_patch(tmp_path)
    _stub_run_untrusted(monkeypatch, returncode=0)
    apply_patch_to_target(tmp_path, patch, caller_label="raptor-sca fix --harden")
    out = capsys.readouterr().out
    assert "raptor-sca fix --harden --apply" in out


# ---------------------------------------------------------------------------
# Sandbox wiring
# ---------------------------------------------------------------------------


def test_apply_routes_through_run_untrusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """The apply must go through ``run_untrusted`` with the target
    checkout as the only writable surface and the patch fed via
    stdin (out_dir isn't readable inside the sandbox). Defense in
    depth: a plain ``subprocess.run`` must never be reached."""
    (tmp_path / ".git").mkdir()
    patch = _make_patch(tmp_path)
    recorded = _stub_run_untrusted(monkeypatch, returncode=0)

    def raising_run(*a, **kw):
        raise AssertionError(
            "subprocess.run() reached from apply_patch_to_target; "
            "must route through core.sandbox.context.run_untrusted"
        )

    monkeypatch.setattr(subprocess, "run", raising_run)

    rc = apply_patch_to_target(tmp_path, patch)
    assert rc == 0

    assert len(recorded) == 1
    call = recorded[0]
    assert call["cmd"] == ["git", "apply", "-"], (
        "patch must be applied via stdin (`git apply -`), not a "
        "path the sandbox can't read"
    )
    assert call.get("input") == patch.read_text(encoding="utf-8")
    assert call.get("target") == str(tmp_path), (
        "sandbox engagement requires target="
    )
    assert call.get("output"), (
        "sandbox needs a scratch dir (outside the operator's tree) "
        "to land $HOME / temp files into"
    )
    assert not call["output"].startswith(str(tmp_path)), (
        "sandbox scratch dir must not litter the operator's checkout"
    )
    assert call.get("writable_paths") == [str(tmp_path)], (
        "writes must be scoped to the target checkout "
        "(worktree + .git)"
    )
    assert call.get("cwd") == str(tmp_path)
    assert call.get("timeout") == 60
    assert call.get("caller_label"), "caller_label missing (telemetry)"


# ---------------------------------------------------------------------------
# End-to-end apply semantics (real git, no real sandbox needed)
# ---------------------------------------------------------------------------

_needs_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git not installed")


def _passthrough_run_untrusted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Execute the exact argv + stdin the helper builds, in the cwd
    it chose — proves the constructed command applies for real
    without depending on host sandbox support."""

    def passthrough(cmd, **kwargs):
        return subprocess.run(
            cmd, cwd=kwargs["cwd"], input=kwargs["input"],
            capture_output=True, text=True,
            timeout=kwargs.get("timeout", 60),
        )

    monkeypatch.setattr(
        "core.sandbox.context.run_untrusted", passthrough,
    )


def _make_checkout(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    subprocess.run(["git", "init", "-q", str(target)], check=True)
    (target / "requirements.txt").write_text(
        "requests==2.19.0\n", encoding="utf-8")
    return target


_GOOD_PATCH = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-requests==2.19.0
+requests==2.32.3
"""

# Context line doesn't match the checkout → git apply rejects.
_BAD_PATCH = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-flask==0.12.0
+flask==2.3.0
"""


@_needs_git
def test_sandboxed_apply_applies_good_patch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
):
    target = _make_checkout(tmp_path)
    patch = tmp_path / "upgrade.patch"
    patch.write_text(_GOOD_PATCH, encoding="utf-8")
    _passthrough_run_untrusted(monkeypatch)

    rc = apply_patch_to_target(target, patch)
    assert rc == 0
    assert (target / "requirements.txt").read_text() \
        == "requests==2.32.3\n"
    out = capsys.readouterr().out
    assert f"patch applied to {target}" in out


@_needs_git
def test_sandboxed_apply_rejects_bad_patch_with_same_error_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
):
    """A patch that doesn't apply must keep the pre-sandbox failure
    contract: git's non-zero rc propagated, the "rejected the patch"
    line + git's stderr on our stderr, tree untouched."""
    target = _make_checkout(tmp_path)
    patch = tmp_path / "upgrade.patch"
    patch.write_text(_BAD_PATCH, encoding="utf-8")
    _passthrough_run_untrusted(monkeypatch)

    rc = apply_patch_to_target(target, patch)
    assert rc != 0
    err = capsys.readouterr().err
    assert "git apply rejected the patch" in err
    assert "patch does not apply" in err or "error:" in err
    assert (target / "requirements.txt").read_text() \
        == "requests==2.19.0\n", "failed apply must not touch the tree"

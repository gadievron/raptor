"""Tests for ``packages.sca.patch_apply.apply_patch_to_target``.

Both ``raptor-sca fix --harden --apply`` and ``raptor-sca fix --cve-only --apply``
share this helper. The tests stub ``subprocess.run`` so no real ``git apply``
is fired — we're testing the pre-flight (refusal policy + path resolution +
log lines) and the result-mapping (exit-code translation).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from packages.sca.patch_apply import apply_patch_to_target


def _make_patch(tmp_path: Path) -> Path:
    p = tmp_path / "upgrade.patch"
    p.write_text("diff --git a/x b/x\n", encoding="utf-8")
    return p


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
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            args=a[0], returncode=0, stdout="", stderr=""),
    )
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
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            args=a[0], returncode=1,
            stdout="", stderr="error: patch failed: x:1"),
    )
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

    monkeypatch.setattr(subprocess, "run", boom)
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
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            args=a[0], returncode=0, stdout="", stderr=""),
    )
    apply_patch_to_target(tmp_path, patch, caller_label="raptor-sca fix --harden")
    out = capsys.readouterr().out
    assert "raptor-sca fix --harden --apply" in out

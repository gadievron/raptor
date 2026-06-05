"""CLI-level smoke tests for /describe — runs the actual
``raptor.py describe`` mode dispatcher AND ``libexec/raptor-describe``
shim against a synthetic target.

These tests exercise the wiring (argparse → resolve → build →
render → exit code) that the unit tests for substrate
(target_shape / tool_readiness / report) don't cover. A bug
where the mode handler doesn't pass ``--json`` through, or the
libexec shim panics on missing target, would slip past the
unit tests but get caught here.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _c_daemon_target(tmp_path: Path) -> Path:
    """Synthesise a c.userspace-daemon shape that exercises both
    the language detector and the catalog match."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "configure.ac").write_text("")
    (tmp_path / "Makefile.am").write_text("")
    src = tmp_path / "src"
    src.mkdir()
    for i in range(5):
        (src / f"f{i}.c").write_text("int main(){return 0;}")
    return tmp_path


def _run(cmd_args: list, *, env_extra: dict | None = None,
         timeout: int = 30) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["CLAUDECODE"] = "1"
    env["RAPTOR_DIR"] = str(_RAPTOR_ROOT)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        cmd_args, capture_output=True, text=True,
        env=env, timeout=timeout,
    )


class TestRaptorPrepareMode:
    """``python3 raptor.py describe ...`` — the operator-facing
    dispatcher path."""

    def test_text_output_against_c_daemon_target(self, tmp_path):
        target = _c_daemon_target(tmp_path / "t")
        result = _run([
            sys.executable, str(_RAPTOR_ROOT / "raptor.py"),
            "describe", "--target", str(target),
        ])
        assert result.returncode == 0
        out = result.stdout
        assert "Target analysis:" in out
        assert "Detected type: c.userspace-daemon" in out
        assert "Target-specific checks:" in out
        assert "raptor doctor" in out  # doctor-deferral footer
        # /describe is read-only — target-type preview is data,
        # not commands. No "Recommended pipeline" with numbered
        # steps (that would imply operator should run them).
        assert "Defaults for this target type" in out
        assert "Recommended pipeline:" not in out
        # Footer substitutes the resolved target path (no
        # <target> placeholder). Operator can copy the line
        # directly.
        assert "<target>" not in out, (
            "footer should substitute the resolved target path; "
            "<target> placeholder forces operators to hand-edit"
        )
        assert str(target) in out

    def test_json_output_parses_and_has_expected_keys(self, tmp_path):
        target = _c_daemon_target(tmp_path / "t")
        result = _run([
            sys.executable, str(_RAPTOR_ROOT / "raptor.py"),
            "describe", "--target", str(target), "--json",
        ])
        assert result.returncode == 0
        doc = json.loads(result.stdout)
        # Pin the top-level schema operators / CI consumers
        # will rely on.
        assert doc["primary_language"] == "cpp"
        assert doc["target_type"] == "c.userspace-daemon"
        assert doc["build_systems"] == {"cpp": "autotools"}
        assert "tool_checks" in doc
        # Catalog preview present + populated for a matched entry.
        assert doc["target_type_defaults"] is not None
        assert (
            "security-audit" in doc["target_type_defaults"]["semgrep_packs"]
        )
        # SCOPE GUARDRAIL (read-only describe): JSON output
        # must not contain runnable-command lists — see
        # report.py docstring + test_no_runnable_build_commands
        # for the security rationale.
        forbidden = {"pipeline", "setup_steps", "analysis_steps"}
        assert forbidden.isdisjoint(doc.keys()), (
            f"JSON must not include runnable-command lists; "
            f"intersection: {doc.keys() & forbidden}"
        )

    def test_missing_target_path_exits_nonzero(self, tmp_path):
        # --target points at a path that doesn't exist; clean
        # error message + non-zero exit (operator script doesn't
        # silently proceed).
        result = _run([
            sys.executable, str(_RAPTOR_ROOT / "raptor.py"),
            "describe", "--target", "/nonexistent/raptor-describe-test",
        ])
        assert result.returncode != 0
        assert "does not exist" in result.stderr

    def test_no_target_no_active_project_exits_nonzero(self, tmp_path):
        # Single expected outcome: refusal with non-zero exit
        # AND operator-actionable stderr. Pre-fix the test
        # accepted either refusal OR active-project leak; that
        # passed for the wrong reason whenever the developer's
        # worktree had an active project pointing somewhere
        # real. Now: HOME is a tmp dir (no ~/.raptor/projects/.active)
        # and RAPTOR_CALLER_DIR is empty → resolver MUST return
        # None → /describe MUST refuse.
        env = os.environ.copy()
        env["CLAUDECODE"] = "1"
        env["RAPTOR_DIR"] = str(_RAPTOR_ROOT)
        env["HOME"] = str(tmp_path)  # no ~/.raptor/projects/.active
        env.pop("RAPTOR_CALLER_DIR", None)
        result = subprocess.run(
            [sys.executable, str(_RAPTOR_ROOT / "raptor.py"), "describe"],
            capture_output=True, text=True,
            env=env, cwd=str(tmp_path), timeout=30,
        )
        assert result.returncode != 0, (
            f"expected refusal; got success. stdout:\n{result.stdout}"
        )
        assert "--target required" in result.stderr, (
            f"expected explicit '--target required' refusal; "
            f"stderr was:\n{result.stderr}"
        )


class TestLibexecRaptorPrepare:
    """``libexec/raptor-describe`` — the slash-command surface
    invoked from Claude Code sessions."""

    def test_libexec_text_output(self, tmp_path):
        target = _c_daemon_target(tmp_path / "t")
        result = _run([
            sys.executable,
            str(_RAPTOR_ROOT / "libexec" / "raptor-describe"),
            "--target", str(target),
        ])
        assert result.returncode == 0
        assert "Target analysis:" in result.stdout
        assert "Detected type: c.userspace-daemon" in result.stdout

    def test_libexec_json_output(self, tmp_path):
        target = _c_daemon_target(tmp_path / "t")
        result = _run([
            sys.executable,
            str(_RAPTOR_ROOT / "libexec" / "raptor-describe"),
            "--target", str(target), "--json",
        ])
        assert result.returncode == 0
        doc = json.loads(result.stdout)
        assert doc["target_type"] == "c.userspace-daemon"

    def test_libexec_trust_marker_required(self, tmp_path):
        # The libexec script gates on CLAUDECODE / _RAPTOR_TRUSTED.
        # Without them, exit 2 + stderr advice.
        env = os.environ.copy()
        env.pop("CLAUDECODE", None)
        env.pop("_RAPTOR_TRUSTED", None)
        target = _c_daemon_target(tmp_path / "t")
        result = subprocess.run(
            [sys.executable,
             str(_RAPTOR_ROOT / "libexec" / "raptor-describe"),
             "--target", str(target)],
            capture_output=True, text=True,
            env=env, timeout=15,
        )
        assert result.returncode == 2
        assert "Run via" in result.stderr  # the trust-marker hint

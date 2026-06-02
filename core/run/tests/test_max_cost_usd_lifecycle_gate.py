"""Tests for the --max-cost-usd pre-flight gate (QoL #21).

Covers:
  1. ``raptor._extract_and_strip_max_cost_usd`` — argument-level
     parsing + scrubbing of the lifecycle-only flag.
  2. ``libexec/raptor-run-lifecycle start --max-cost-usd <cap>``
     end-to-end: estimate prints, exit code 0 when estimate within
     cap, exit code 1 + clear stderr message when estimate exceeds
     cap.

Both raptor.py and libexec/raptor-run-lifecycle apply the gate;
both surfaces are exercised so a regression in one path doesn't
slip past tests covering only the other.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# Helper-level: _extract_and_strip_max_cost_usd
# ---------------------------------------------------------------------------


def _import_raptor():
    """Import the dispatcher module. Cached after first call so
    repeat tests in the same process don't re-exec the import."""
    if "raptor" not in sys.modules:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor  # noqa: PLC0415
    return raptor


class TestExtractAndStrip:
    def test_returns_none_when_flag_absent(self):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--repo", "/x", "--codeql"],
        )
        assert cap is None
        assert out == ["--repo", "/x", "--codeql"]

    def test_space_form_extracted_and_stripped(self):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd", "10", "--repo", "/x"],
        )
        assert cap == 10.0
        assert "--max-cost-usd" not in out
        assert "10" not in out
        assert out == ["--repo", "/x"]

    def test_equals_form_extracted_and_stripped(self):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--repo", "/x", "--max-cost-usd=25.50"],
        )
        assert cap == 25.5
        assert out == ["--repo", "/x"]

    def test_fractional_dollar_amount_preserved(self):
        # Sub-penny precision the scorecard uses (``$0.0042``) is
        # representable; gate should accept floats with arbitrary
        # decimals.
        raptor = _import_raptor()
        cap, _ = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd", "0.0042"],
        )
        assert cap == pytest.approx(0.0042)

    def test_non_numeric_value_warns_and_returns_unchanged(self, capsys):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd", "lots", "--repo", "/x"],
        )
        # Bad value → no cap applied; args returned UNCHANGED so
        # the lifecycle doesn't silently lose context.
        assert cap is None
        assert out == ["--max-cost-usd", "lots", "--repo", "/x"]
        captured = capsys.readouterr()
        assert "not a number" in captured.err

    def test_zero_value_warns_and_returns_unchanged(self, capsys):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd", "0"],
        )
        assert cap is None
        assert out == ["--max-cost-usd", "0"]
        assert "> 0" in capsys.readouterr().err

    def test_negative_value_warns(self, capsys):
        raptor = _import_raptor()
        cap, _ = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd=-5"],
        )
        assert cap is None
        assert "> 0" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# End-to-end: libexec/raptor-run-lifecycle start --max-cost-usd <cap>
# ---------------------------------------------------------------------------


def _build_c_daemon_target(tmp_path: Path) -> Path:
    """Synthesise a tree that the catalog detects as
    c.userspace-daemon (estimated cost $25-$50)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "configure.ac").write_text("")
    (tmp_path / "Makefile.am").write_text("")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("")
    return tmp_path


def _run_lifecycle_start(
    target: Path, out_dir: Path, *, max_cost_usd: str | None = None,
) -> subprocess.CompletedProcess:
    """Invoke libexec/raptor-run-lifecycle start; returns the
    completed process for assertion."""
    cmd = [
        sys.executable,
        str(_RAPTOR_ROOT / "libexec" / "raptor-run-lifecycle"),
        "start", "scan",
        "--target", str(target),
        "--out", str(out_dir),
    ]
    if max_cost_usd is not None:
        cmd += ["--max-cost-usd", max_cost_usd]
    env = os.environ.copy()
    env["CLAUDECODE"] = "1"  # bypass trust-marker gate
    # The .active project symlink in a developer worktree would
    # interfere with --out resolution; force the explicit out path
    # by setting a non-existent active dir.
    env.pop("RAPTOR_PROJECT", None)
    return subprocess.run(
        cmd, env=env, capture_output=True, text=True, timeout=30,
    )


class TestLibexecPreflightGate:
    """The skills-path lifecycle (libexec/raptor-run-lifecycle)
    applies the same pre-flight gate as the dispatcher path so
    /understand, /codeql, /validate etc. all benefit."""

    def test_no_cap_proceeds_with_estimate_printed(self, tmp_path):
        target = _build_c_daemon_target(tmp_path / "target")
        out_dir = tmp_path / "out"
        result = _run_lifecycle_start(target, out_dir)
        assert result.returncode == 0
        # Estimate line lands on stderr (per design — stdout
        # reserved for the OUTPUT_DIR= sentinel).
        assert "Expected: $25-$50" in result.stderr
        assert "c.userspace-daemon" in result.stderr
        # Sentinel still on stdout intact.
        assert f"OUTPUT_DIR={out_dir}" in result.stdout

    def test_cap_above_estimate_proceeds(self, tmp_path):
        # Cap of $100 > estimate upper bound $50 → proceed.
        target = _build_c_daemon_target(tmp_path / "target")
        out_dir = tmp_path / "out"
        result = _run_lifecycle_start(
            target, out_dir, max_cost_usd="100",
        )
        assert result.returncode == 0
        assert f"OUTPUT_DIR={out_dir}" in result.stdout
        assert "Pre-flight cost gate" not in result.stderr

    def test_cap_below_estimate_hard_fails(self, tmp_path):
        # Cap of $20 < estimate upper bound $50 → refuse.
        target = _build_c_daemon_target(tmp_path / "target")
        out_dir = tmp_path / "out"
        result = _run_lifecycle_start(
            target, out_dir, max_cost_usd="20",
        )
        assert result.returncode == 1
        assert "Pre-flight cost gate" in result.stderr
        assert "$50.00" in result.stderr  # estimate upper bound
        assert "$20.00" in result.stderr  # cap
        # Operator-actionable guidance present.
        assert "Raise the cap" in result.stderr

    def test_cap_equal_to_estimate_proceeds(self, tmp_path):
        # Boundary: cap == estimate.cost_high → proceed (gate is
        # strict `>`, not `>=`, so the operator who set the cap
        # at the catalog's documented upper bound isn't refused
        # for matching exactly).
        target = _build_c_daemon_target(tmp_path / "target")
        out_dir = tmp_path / "out"
        result = _run_lifecycle_start(
            target, out_dir, max_cost_usd="50",
        )
        assert result.returncode == 0
        assert "Pre-flight cost gate" not in result.stderr

    def test_cap_with_no_catalog_match_proceeds_quietly(self, tmp_path):
        # Empty target → catalog falls back to ``generic`` (cost
        # $10-$30). Cap of $5 < $30 → refuse. (Verifies the gate
        # also bites on the generic fallback path.)
        target = tmp_path / "empty"
        target.mkdir()
        out_dir = tmp_path / "out"
        result = _run_lifecycle_start(
            target, out_dir, max_cost_usd="5",
        )
        assert result.returncode == 1
        assert "Pre-flight cost gate" in result.stderr

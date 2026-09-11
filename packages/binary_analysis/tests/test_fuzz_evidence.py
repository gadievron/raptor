"""Tests for fuzz-run evidence ingestion."""

from __future__ import annotations

from pathlib import Path

from packages.binary_analysis.fuzz_evidence import _resolve_crashes_dir


def test_relative_crashes_dir_anchored_at_fuzz_dir(tmp_path: Path) -> None:
    # A relative recorded path is relative to the fuzz run dir, not the
    # process CWD (which is the framework repo, never the run).
    fuzz_dir = tmp_path / "run"
    crashes = fuzz_dir / "libfuzzer-custom" / "crashes"
    crashes.mkdir(parents=True)
    resolved = _resolve_crashes_dir(
        fuzz_dir, {"crashes_dir": "libfuzzer-custom/crashes"},
    )
    assert resolved == crashes


def test_absolute_crashes_dir_still_used(tmp_path: Path) -> None:
    fuzz_dir = tmp_path / "run"
    fuzz_dir.mkdir()
    crashes = tmp_path / "elsewhere" / "crashes"
    crashes.mkdir(parents=True)
    resolved = _resolve_crashes_dir(fuzz_dir, {"crashes_dir": str(crashes)})
    assert resolved == crashes


def test_missing_recorded_dir_falls_back_to_defaults(tmp_path: Path) -> None:
    fuzz_dir = tmp_path / "run"
    default = fuzz_dir / "afl" / "main" / "crashes"
    default.mkdir(parents=True)
    resolved = _resolve_crashes_dir(fuzz_dir, {"crashes_dir": "gone"})
    assert resolved == default


def test_no_candidates_returns_none(tmp_path: Path) -> None:
    fuzz_dir = tmp_path / "run"
    fuzz_dir.mkdir()
    assert _resolve_crashes_dir(fuzz_dir, {}) is None

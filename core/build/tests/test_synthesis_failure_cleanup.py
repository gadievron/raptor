"""synthesise_build_command must not leak artifacts into the repo on failure.

The method creates ``.raptor_build_*`` script + build-dir UNDER the
scanned repo (deliberately: operator-visible residue instead of tmp
reaper territory) and hands cleanup_paths to the caller ONLY on
success. Every raise between creation and return — the heuristic
script write, either sandboxed dry-run re-raising SandboxSetupError,
or a CC-retry rewrite — must therefore walk the cleanup list itself,
or RAPTOR's own build script pollutes the target tree and gets
inventoried as project source by the next scan.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from core.build.build_detector import BuildDetector
from core.sandbox import SandboxSetupError


def _residue(repo: Path) -> list[Path]:
    return list(repo.glob(".raptor_build_*"))


def _sources(repo: Path) -> list[Path]:
    return [repo / "a.c", repo / "b.c"]


def _patched(repo: Path, **overrides):
    """Common patch set; individual tests override the failing stage."""
    patches = {
        "_detect_build_params": mock.patch.object(
            BuildDetector, "_detect_build_params",
            return_value=(_sources(repo), "gcc", ["-I."], []),
        ),
        "detect_missing_config_headers": mock.patch.object(
            BuildDetector, "detect_missing_config_headers",
            return_value=[],
        ),
        "_write_build_script": mock.patch.object(
            BuildDetector, "_write_build_script",
            return_value=None,
        ),
        "_dry_run": mock.patch.object(
            BuildDetector, "_dry_run", return_value=None,
        ),
        "_cc_suggest_flags": mock.patch.object(
            BuildDetector, "_cc_suggest_flags", return_value=None,
        ),
    }
    patches.update(overrides)
    return patches


def _run_expecting(repo: Path, exc_type, patches) -> None:
    with patches["_detect_build_params"], \
         patches["detect_missing_config_headers"], \
         patches["_write_build_script"], \
         patches["_dry_run"], \
         patches["_cc_suggest_flags"]:
        detector = BuildDetector(repo)
        with pytest.raises(exc_type):
            detector.synthesise_build_command("cpp")


class TestFailureCleanup:
    def test_dry_run_sandbox_failure_leaves_no_residue(self, tmp_path):
        patches = _patched(tmp_path, _dry_run=mock.patch.object(
            BuildDetector, "_dry_run",
            side_effect=SandboxSetupError("isolation could not engage"),
        ))
        _run_expecting(tmp_path, SandboxSetupError, patches)
        assert _residue(tmp_path) == []

    def test_first_script_write_failure_leaves_no_residue(self, tmp_path):
        patches = _patched(tmp_path, _write_build_script=mock.patch.object(
            BuildDetector, "_write_build_script",
            side_effect=OSError("disk full"),
        ))
        _run_expecting(tmp_path, OSError, patches)
        assert _residue(tmp_path) == []

    def test_cc_retry_write_failure_leaves_no_residue(self, tmp_path):
        # Heuristic write succeeds; dry-run reports failures; the
        # CC-flag rewrite raises.
        writes = iter([None, RuntimeError("rewrite failed")])

        def write_side_effect(*args, **kwargs):
            step = next(writes)
            if isinstance(step, Exception):
                raise step

        patches = _patched(
            tmp_path,
            _write_build_script=mock.patch.object(
                BuildDetector, "_write_build_script",
                side_effect=write_side_effect,
            ),
            _dry_run=mock.patch.object(
                BuildDetector, "_dry_run",
                return_value=[{"file": "a.c", "error": "missing header"}],
            ),
            _cc_suggest_flags=mock.patch.object(
                BuildDetector, "_cc_suggest_flags",
                return_value={"includes": ["-Igen"], "defines": []},
            ),
        )
        _run_expecting(tmp_path, RuntimeError, patches)
        assert _residue(tmp_path) == []

    def test_success_returns_cleanup_paths_and_keeps_artifacts(
        self, tmp_path,
    ):
        """Two-direction: on success the artifacts survive and the
        CALLER owns cleanup via cleanup_paths."""
        patches = _patched(tmp_path, _dry_run=mock.patch.object(
            BuildDetector, "_dry_run", return_value=[],
        ))
        with patches["_detect_build_params"], \
             patches["detect_missing_config_headers"], \
             patches["_write_build_script"], \
             patches["_dry_run"], \
             patches["_cc_suggest_flags"]:
            result = BuildDetector(tmp_path).synthesise_build_command("cpp")
        assert result is not None
        assert len(result.cleanup_paths) == 2
        assert all(p.exists() for p in result.cleanup_paths)
        assert len(_residue(tmp_path)) == 2
        for p in result.cleanup_paths:
            if p.is_dir():
                import shutil
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)

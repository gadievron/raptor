"""Tests for core.sandbox.exec_stage — consented-exec staging.

Env-built artifacts sit 0444 in the run dir (core/env/build.py strips
the exec bits deliberately). ``executable_stage`` must yield a runnable
private copy for those without ever touching the original, and must be
a pass-through for everything else.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from core.sandbox import executable_stage


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


class TestStagesNonExecutable:
    def test_yields_runnable_private_copy(self, tmp_path):
        artifact = tmp_path / "src__screen"
        artifact.write_bytes(b"\x7fELF-ish bytes")
        artifact.chmod(0o444)  # the env-build extraction shape

        with executable_stage(artifact) as staged:
            assert staged != artifact
            assert os.access(staged, os.X_OK)
            assert _mode(staged) == 0o500
            assert staged.read_bytes() == artifact.read_bytes()
            staged_dir = staged.parent

        # The copy and its private dir are gone after the context.
        assert not staged.exists()
        assert not staged_dir.exists()

    def test_original_and_run_dir_stay_non_executable(self, tmp_path):
        artifact = tmp_path / "app"
        artifact.write_bytes(b"bytes")
        artifact.chmod(0o444)
        with executable_stage(artifact):
            assert _mode(artifact) == 0o444
        assert _mode(artifact) == 0o444

    def test_keeps_basename_for_maps_matching(self, tmp_path):
        artifact = tmp_path / "src__screen"
        artifact.write_bytes(b"bytes")
        artifact.chmod(0o444)
        with executable_stage(artifact) as staged:
            assert staged.name == "src__screen"

    def test_staging_dir_is_owner_only(self, tmp_path):
        artifact = tmp_path / "app"
        artifact.write_bytes(b"bytes")
        artifact.chmod(0o444)
        with executable_stage(artifact) as staged:
            assert _mode(staged.parent) == 0o700


class TestPassThrough:
    def test_executable_file_yielded_unchanged(self, tmp_path):
        harness = tmp_path / "harness"
        harness.write_bytes(b"#!/bin/sh\n")
        harness.chmod(0o755)
        with executable_stage(harness) as staged:
            assert staged == harness

    def test_missing_path_yielded_unchanged(self, tmp_path):
        ghost = tmp_path / "missing"
        # The caller's missing-binary handling stays authoritative.
        with executable_stage(ghost) as staged:
            assert staged == ghost

    def test_directory_yielded_unchanged(self, tmp_path):
        with executable_stage(tmp_path) as staged:
            assert staged == Path(tmp_path)

    def test_accepts_str_paths(self, tmp_path):
        artifact = tmp_path / "app"
        artifact.write_bytes(b"bytes")
        artifact.chmod(0o444)
        with executable_stage(str(artifact)) as staged:
            assert os.access(staged, os.X_OK)

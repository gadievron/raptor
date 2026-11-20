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

import pytest

from core.sandbox import executable_stage


@pytest.fixture(autouse=True)
def _owned_stage_parent(tmp_path, monkeypatch):
    """Stage fixtures under this test, independently of session workdir state."""
    from core.sandbox import exec_stage

    monkeypatch.setattr(exec_stage, "exec_workdir", lambda: tmp_path)


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


class TestScratchPlacement:
    def test_stages_under_exec_workdir(self, tmp_path, monkeypatch):
        from core.sandbox import exec_stage

        family = tmp_path / "session"
        family.mkdir()
        monkeypatch.setattr(exec_stage, "exec_workdir", lambda: family)
        artifact = tmp_path / "app"
        artifact.write_bytes(b"bytes")
        artifact.chmod(0o444)
        with executable_stage(artifact) as staged:
            assert staged.parent.parent == family

    def test_fallback_prefix_is_reaper_registered(self):
        # exec_workdir() may fall back to the default temp dir; a
        # SIGKILLed run must never strand a mode-0o500 copy of an
        # attacker-built binary there.
        from core.run import tmp_reaper

        assert "raptor-exec-stage-" in tmp_reaper._DIR_PREFIXES


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


class TestSymlinksNeverStaged:
    def test_symlink_to_non_executable_not_staged(self, tmp_path):
        """A planted link must not get its destination copied into an
        executable staging dir — the copy would read (and re-expose,
        runnable) a file the sandboxed child itself could not."""
        secret = tmp_path / "secret"
        secret.write_bytes(b"not for the child")
        secret.chmod(0o444)
        link = tmp_path / "app"
        link.symlink_to(secret)
        with executable_stage(link) as staged:
            assert staged == link, "symlinked artifact was staged"

    def test_dangling_symlink_yielded_unchanged(self, tmp_path):
        link = tmp_path / "app"
        link.symlink_to(tmp_path / "nowhere")
        with executable_stage(link) as staged:
            assert staged == link

    def test_intermediate_symlink_dir_not_staged(self, tmp_path):
        """The lens shape: callers pass target-repo build paths, so a
        planted DIRECTORY link (``build -> <elsewhere>``) is as
        attacker-reachable as a linked leaf — the parent-side copy
        would re-expose, executable, a file the child could not
        read. Any symlink component means no staging."""
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "harness"
        secret.write_bytes(b"not for the child")
        secret.chmod(0o444)
        build = tmp_path / "build"
        build.symlink_to(outside)
        linked = build / "harness"
        with executable_stage(linked) as staged:
            assert staged == linked, "intermediate-link artifact staged"

    def test_source_swapped_to_symlink_refused_by_open(self, tmp_path,
                                                       monkeypatch):
        """A link raced in AFTER the gates is refused loudly by the
        symlink-refusing re-walk instead of being followed."""
        from core.sandbox import exec_stage

        artifact = tmp_path / "app"
        artifact.write_bytes(b"bytes")
        artifact.chmod(0o444)
        secret = tmp_path / "secret"
        secret.write_bytes(b"not for the child")

        real_realpath = os.path.realpath

        def _realpath_then_swap(path, **kwargs):
            resolved = real_realpath(path, **kwargs)
            if Path(path) == artifact:
                # The check saw a clean path; the swap lands after it.
                artifact.unlink()
                artifact.symlink_to(secret)
                monkeypatch.setattr(
                    exec_stage.os.path, "realpath", real_realpath)
            return resolved

        monkeypatch.setattr(
            exec_stage.os.path, "realpath", _realpath_then_swap)
        with pytest.raises(OSError):
            with executable_stage(artifact):
                pytest.fail("swapped symlink source was staged")

    def test_source_swapped_during_gate_not_staged(self, tmp_path,
                                                   monkeypatch):
        """A link raced in during the lstat gate itself lands in the
        stable-shape check and passes through unstaged."""
        from core.sandbox import exec_stage

        artifact = tmp_path / "app"
        artifact.write_bytes(b"bytes")
        artifact.chmod(0o444)
        secret = tmp_path / "secret"
        secret.write_bytes(b"not for the child")

        real_lstat = os.lstat

        def _lstat_then_swap(path, *args, **kwargs):
            st = real_lstat(path, *args, **kwargs)
            if Path(path) == artifact:
                artifact.unlink()
                artifact.symlink_to(secret)
                monkeypatch.setattr(exec_stage.os, "lstat", real_lstat)
            return st

        monkeypatch.setattr(exec_stage.os, "lstat", _lstat_then_swap)
        with executable_stage(artifact) as staged:
            assert staged == artifact, "swapped symlink source was staged"

    def test_inode_swap_after_gate_refused(self, tmp_path, monkeypatch):
        """The copy must read exactly the inode the gate cleared: a
        same-path different-inode swap after the gate raises ESTALE."""
        import errno

        from core.sandbox import exec_stage

        artifact = tmp_path / "app"
        artifact.write_bytes(b"bytes")
        artifact.chmod(0o444)
        other = tmp_path / "other"
        other.write_bytes(b"not for the child")
        other.chmod(0o444)

        real_lstat = os.lstat

        def _lstat_other(path, *args, **kwargs):
            if Path(path) == artifact:
                # The gate sees a different inode than the path opens —
                # the deterministic stand-in for a post-gate swap.
                return real_lstat(other, *args, **kwargs)
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(exec_stage.os, "lstat", _lstat_other)
        with pytest.raises(OSError) as ei:
            with executable_stage(artifact):
                pytest.fail("inode-swapped source was staged")
        assert ei.value.errno == errno.ESTALE

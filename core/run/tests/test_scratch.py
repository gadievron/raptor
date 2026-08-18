"""Tests for core.run.scratch — the shared scratch-dir context manager.

Pins the consolidated behaviours of the hand-rolled mkdtemp sites this
replaces: best-effort cleanup on both normal and exceptional exit, the
``dir=`` run-output shape (parent created ``exist_ok``, no reaper
registration), the ``TMPDIR`` export shape, the ``keep`` ownership-
transfer escape hatch, and the reaper auto-registration for system-tmp
prefixes (the coverage gap that let unlisted prefixes leak forever).
"""

from __future__ import annotations

import os
import time

import pytest

from core.run import tmp_reaper
from core.run.scratch import scratch_dir

_OLD = time.time() - 25 * 3600  # past the 24h default age floor


@pytest.fixture
def tmp_root(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.delenv("RAPTOR_TMP_REAP_MAX_AGE_H", raising=False)
    return tmp_path


@pytest.fixture(autouse=True)
def _isolated_runtime_prefixes(monkeypatch):
    monkeypatch.setattr(tmp_reaper, "_RUNTIME_DIR_PREFIXES", set())


class TestBasicLifecycle:

    def test_yields_existing_path_with_prefix(self, tmp_root):
        with scratch_dir("raptor-scratch-test-") as p:
            assert p.is_dir()
            assert p.name.startswith("raptor-scratch-test-")
            assert p.parent == tmp_root
        assert not p.exists()

    def test_cleanup_on_exception(self, tmp_root):
        with pytest.raises(RuntimeError), \
                scratch_dir("raptor-scratch-test-") as p:
            (p / "litter.txt").write_text("x")
            raise RuntimeError("boom")
        assert not p.exists()

    def test_cleanup_is_best_effort(self, tmp_root):
        # A subdir made unreadable must not turn cleanup into a raise
        # (the hand-rolled sites used ignore_errors / suppress(OSError)).
        with scratch_dir("raptor-scratch-test-") as p:
            sub = p / "sub"
            sub.mkdir()
            (sub / "f").write_text("x")
            os.chmod(sub, 0o000)
        os.chmod(sub, 0o755)  # allow the fixture's own teardown
        assert p.exists() or not p.exists()  # no exception is the assertion

    def test_keep_transfers_ownership(self, tmp_root):
        with scratch_dir("raptor-scratch-test-", keep=True) as p:
            pass
        assert p.is_dir()


class TestRunOutputShape:

    def test_dir_parent_created_exist_ok(self, tmp_path):
        parent = tmp_path / "out" / "scratch"
        with scratch_dir("git_oracle_", dir=parent) as p:
            assert p.parent == parent
            assert p.name.startswith("git_oracle_")
        assert not p.exists()
        assert parent.is_dir()  # parent survives; only the scratch goes

    def test_dir_shape_not_reaper_registered(self, tmp_path):
        with scratch_dir("compiler_sweep_", dir=tmp_path):
            pass
        assert "compiler_sweep_" not in tmp_reaper._RUNTIME_DIR_PREFIXES


class TestTmpdirExport:

    def test_env_gets_tmpdir(self, tmp_root):
        env: dict[str, str] = {"PATH": "/usr/bin"}
        with scratch_dir("raptor-scratch-test-", env=env) as p:
            assert env["TMPDIR"] == str(p)
        # Nothing restored on exit — the mapping is the caller's copy.
        assert env["TMPDIR"] == str(p)


class TestReaperRegistration:

    def test_system_tmp_prefix_registered(self, tmp_root):
        with scratch_dir("raptor-scratch-reg-"):
            assert "raptor-scratch-reg-" in tmp_reaper._RUNTIME_DIR_PREFIXES

    def test_registered_prefix_is_swept(self, tmp_root):
        # A stale orphan with a runtime-registered prefix is reclaimed
        # by the same process's next sweep — the coverage gap the
        # hand-enumerated prefix tuple left open for unlisted prefixes.
        with scratch_dir("raptor-scratch-reg-"):
            pass
        orphan = tmp_root / "raptor-scratch-reg-orphan1"
        orphan.mkdir()
        os.utime(orphan, (_OLD, _OLD))
        reaped = tmp_reaper.reap_stale_tmp()
        assert orphan in reaped
        assert not orphan.exists()

    def test_unregistered_prefix_not_swept(self, tmp_root):
        stranger = tmp_root / "raptor-scratch-unreg-orphan1"
        stranger.mkdir()
        os.utime(stranger, (_OLD, _OLD))
        assert tmp_reaper.reap_stale_tmp() == []
        assert stranger.is_dir()

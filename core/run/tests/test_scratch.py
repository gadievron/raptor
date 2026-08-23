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


class TestLiveSessionKeepalive:
    """A LIVE session whose system-tmp scratch goes mtime-quiet past
    the reaper's age floor (default 24 h) must not be false-reaped by
    a concurrent process's sweep. The owning process keeps the dir's
    mtime fresh: scratch_dir registers each system-tmp scratch with a
    keepalive that a daemon thread ticks periodically. Tests drive
    the tick directly (fake-clock style) instead of waiting."""

    @pytest.fixture(autouse=True)
    def _isolated_keepalive(self, monkeypatch):
        from core.run import scratch as scratch_mod
        monkeypatch.setattr(scratch_mod, "_keepalive_paths", set())

    def test_quiet_live_scratch_survives_sweep(self, tmp_root):
        from core.run import scratch as scratch_mod
        with scratch_dir("raptor-keepalive-test-") as p:
            # Simulate a session quiet past the age floor: nothing
            # touched the dir's own mtime for >24h while the owning
            # process (us) stayed alive.
            os.utime(p, (_OLD, _OLD))
            scratch_mod._keepalive_tick()  # what the thread does
            assert tmp_reaper.reap_stale_tmp() == []
            assert p.is_dir()

    def test_without_tick_quiet_scratch_would_be_reaped(self, tmp_root):
        # The exposure the keepalive closes, pinned as a control: same
        # scenario minus the tick — the sweep takes the live dir.
        with scratch_dir("raptor-keepalive-test-") as p:
            os.utime(p, (_OLD, _OLD))
            assert tmp_reaper.reap_stale_tmp() == [p]
            assert not p.exists()

    def test_tick_refreshes_mtime(self, tmp_root):
        from core.run import scratch as scratch_mod
        with scratch_dir("raptor-keepalive-test-") as p:
            os.utime(p, (_OLD, _OLD))
            scratch_mod._keepalive_tick()
            assert time.time() - p.stat().st_mtime < 3600

    def test_exit_unregisters(self, tmp_root):
        from core.run import scratch as scratch_mod
        with scratch_dir("raptor-keepalive-test-") as p:
            assert str(p) in scratch_mod._keepalive_paths
        assert str(p) not in scratch_mod._keepalive_paths
        scratch_mod._keepalive_tick()  # tolerates the gone dir

    def test_keep_unregisters_too(self, tmp_root):
        # keep=True transfers ownership — the keepalive window is the
        # context-manager window, so a kept dir ages out normally once
        # its owner stops using it (same contract as --keep dirs).
        from core.run import scratch as scratch_mod
        with scratch_dir("raptor-keepalive-test-", keep=True) as p:
            pass
        assert str(p) not in scratch_mod._keepalive_paths
        assert p.is_dir()

    def test_dir_shape_not_registered(self, tmp_path):
        # Run-output scratch is never reaper-swept, so it needs no
        # keepalive either.
        from core.run import scratch as scratch_mod
        with scratch_dir("compiler_sweep_", dir=tmp_path) as p:
            assert str(p) not in scratch_mod._keepalive_paths

    def test_daemon_thread_started(self, tmp_root):
        from core.run import scratch as scratch_mod
        with scratch_dir("raptor-keepalive-test-"):
            thread = scratch_mod._keepalive_thread
            assert thread is not None
            assert thread.daemon
            assert thread.is_alive()

    def test_tick_survives_vanished_path(self, tmp_root):
        from core.run import scratch as scratch_mod
        scratch_mod._keepalive_paths.add(str(tmp_root / "gone"))
        scratch_mod._keepalive_tick()  # no raise is the assertion

    def test_tick_never_follows_a_squatting_symlink(self, tmp_root):
        # /tmp is world-writable: if the scratch vanished and someone
        # squatted a symlink on its path, the tick must not refresh
        # the target's mtime (that could keep an unrelated artifact
        # alive past the reaper's floor).
        import os as _os
        if _os.utime not in _os.supports_follow_symlinks:
            pytest.skip("platform cannot utime without following")
        from core.run import scratch as scratch_mod
        victim = tmp_root / "victim"
        victim.mkdir()
        os.utime(victim, (_OLD, _OLD))
        link = tmp_root / "squatted"
        link.symlink_to(victim)
        scratch_mod._keepalive_paths.add(str(link))
        scratch_mod._keepalive_tick()
        assert victim.stat().st_mtime == pytest.approx(_OLD)


class TestKeepalivePublicAPI:
    """register/unregister are public: scratch owners whose dirs
    outlive a lexical scope (teardown-method / returned-handle /
    caller-finally ownership) hold a keepalive while the dir is live,
    which is what makes reaper-listing their prefixes safe for
    long-quiet-but-alive dirs."""

    @pytest.fixture(autouse=True)
    def _isolated_keepalive(self, monkeypatch):
        from core.run import scratch as scratch_mod
        monkeypatch.setattr(scratch_mod, "_keepalive_paths", set())

    def test_register_then_tick_refreshes(self, tmp_path):
        from core.run import scratch as scratch_mod
        from core.run.scratch import keepalive_register
        d = tmp_path / "owned"
        d.mkdir()
        os.utime(d, (_OLD, _OLD))
        keepalive_register(d)
        scratch_mod._keepalive_tick()
        assert time.time() - d.stat().st_mtime < 3600

    def test_unregister_stops_refresh(self, tmp_path):
        from core.run import scratch as scratch_mod
        from core.run.scratch import keepalive_register, keepalive_unregister
        d = tmp_path / "owned"
        d.mkdir()
        keepalive_register(d)
        keepalive_unregister(d)
        os.utime(d, (_OLD, _OLD))
        scratch_mod._keepalive_tick()
        assert d.stat().st_mtime == pytest.approx(_OLD)

    def test_unregister_is_idempotent(self, tmp_path):
        from core.run.scratch import keepalive_unregister
        keepalive_unregister(tmp_path / "never-registered")
        keepalive_unregister(str(tmp_path / "never-registered"))

    def test_str_and_path_are_equivalent(self, tmp_path):
        from core.run import scratch as scratch_mod
        from core.run.scratch import keepalive_register, keepalive_unregister
        d = tmp_path / "owned"
        d.mkdir()
        keepalive_register(str(d))
        keepalive_unregister(d)
        assert str(d) not in scratch_mod._keepalive_paths

    def test_register_starts_ticker(self, tmp_path):
        from core.run import scratch as scratch_mod
        from core.run.scratch import keepalive_register, keepalive_unregister
        d = tmp_path / "owned"
        d.mkdir()
        keepalive_register(d)
        try:
            assert scratch_mod._keepalive_thread is not None
            assert scratch_mod._keepalive_thread.daemon
            assert scratch_mod._keepalive_thread.is_alive()
        finally:
            keepalive_unregister(d)

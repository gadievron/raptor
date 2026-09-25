"""Tests for core.run.workdir — canonical executed-artifact workspace.

Behaviour contract (EDR-coexistence refactor):

* Under the launcher (``tempfile.gettempdir()`` already inside a
  ``raptor-<euid>`` family dir) ``exec_workdir()`` is a NO-OP —
  returns ``None`` so ``tempfile`` factories keep producing byte-
  identical paths.
* Outside the launcher it consolidates executed artifacts under
  ``<base>/raptor-<euid>/session-<pid>-<rand>`` (0700, squat-refusing,
  dead-pid-sweeping) instead of scattering them across the temp root.
* ``RAPTOR_WORK_DIR`` overrides ``<base>``.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path

import pytest

from core.run import workdir


# Captured pre-patch so test_family_name_is_the_launcher_shape pins
# the production name even though the autouse fixture swaps it out.
_REAL_FAMILY_NAME = workdir._family_name


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    """Reset the process cache and point the temp root at a private dir.

    The family name is patched to a test-private one: this suite may
    itself run under the ``bin/raptor`` launcher, where pytest's
    ``tmp_path`` ALREADY lies inside the real ``raptor-<euid>`` family
    (``TMPDIR=/…/raptor-<euid>/session-…``). The no-op detection then
    correctly vetoes consolidation for any dir we can create, and every
    standalone-behaviour test would fail while testing nothing. A
    private name keeps all the logic under test real (mkdir posture,
    squat refusal, dead-pid sweep, session naming) while making
    "outside the family" constructible on any host;
    test_family_name_is_the_launcher_shape pins the production name.
    """
    monkeypatch.setattr(workdir, "_resolved", False)
    monkeypatch.setattr(workdir, "_cached", None)
    monkeypatch.delenv("RAPTOR_WORK_DIR", raising=False)
    monkeypatch.setattr(
        workdir, "_family_name",
        lambda: f"raptor-{os.geteuid()}-selftest",
    )
    tmp_root = tmp_path / "tmproot"
    tmp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_root))
    yield tmp_root
    tempfile.tempdir = None


def _family(base: Path) -> Path:
    return base / workdir._family_name()


def test_family_name_is_the_launcher_shape():
    """The production family name must stay byte-compatible with the
    ``bin/raptor`` launcher's session base (its sweep and this module
    reclaim each other's dirs by that shared shape)."""
    assert _REAL_FAMILY_NAME() == f"raptor-{os.geteuid()}"


class TestLauncherNoOp:
    def test_returns_none_when_tmpdir_is_a_launcher_session(
        self, monkeypatch, tmp_path,
    ):
        session = _family(tmp_path) / "session-1-2"
        session.mkdir(parents=True)
        monkeypatch.setattr(tempfile, "tempdir", str(session))
        assert workdir.exec_workdir() is None

    def test_returns_none_anywhere_inside_the_family(
        self, monkeypatch, tmp_path,
    ):
        nested = _family(tmp_path) / "session-1-2" / "deeper"
        nested.mkdir(parents=True)
        monkeypatch.setattr(tempfile, "tempdir", str(nested))
        assert workdir.exec_workdir() is None

    def test_tempfile_paths_unchanged_under_launcher(
        self, monkeypatch, tmp_path,
    ):
        """The wired call shape (dir=exec_workdir()) must keep
        producing the same parent dir as an unwired call."""
        session = _family(tmp_path) / "session-1-2"
        session.mkdir(parents=True)
        monkeypatch.setattr(tempfile, "tempdir", str(session))
        with tempfile.TemporaryDirectory(
            prefix="raptor_dyn_", dir=workdir.exec_workdir(),
        ) as d:
            assert Path(d).parent == session


class TestStandaloneConsolidation:
    def test_creates_family_session_dir(self, _fresh):
        got = workdir.exec_workdir()
        assert got is not None
        assert got.parent == _family(_fresh)
        assert re.fullmatch(r"session-\d+-\d+", got.name)
        assert str(os.getpid()) in got.name
        mode = stat.S_IMODE(os.lstat(got).st_mode)
        assert mode == 0o700
        parent_mode = stat.S_IMODE(os.lstat(got.parent).st_mode)
        assert parent_mode == 0o700

    def test_cached_per_process(self, _fresh):
        assert workdir.exec_workdir() == workdir.exec_workdir()

    def test_executed_artifact_lands_inside_family(self, _fresh):
        with tempfile.TemporaryDirectory(
            prefix="raptor_dyn_", dir=workdir.exec_workdir(),
        ) as d:
            p = Path(d)
            assert p.name.startswith("raptor_dyn_")
            assert _family(_fresh) in p.parents

    def test_env_override_wins(self, monkeypatch, tmp_path):
        override = tmp_path / "opt-scratch"
        override.mkdir()
        monkeypatch.setenv("RAPTOR_WORK_DIR", str(override))
        got = workdir.exec_workdir()
        assert got is not None
        assert got.parent == _family(override)

    def test_blank_env_override_ignored(self, monkeypatch, _fresh):
        monkeypatch.setenv("RAPTOR_WORK_DIR", "   ")
        got = workdir.exec_workdir()
        assert got is not None
        assert got.parent == _family(_fresh)

    def test_removed_session_dir_is_recreated(self, _fresh):
        import shutil
        first = workdir.exec_workdir()
        assert first is not None
        shutil.rmtree(first)
        second = workdir.exec_workdir()
        assert second is not None
        assert second.is_dir()
        assert second != first


class TestSafetyPosture:
    def test_symlink_family_root_refused(self, _fresh):
        real = _fresh / "elsewhere"
        real.mkdir()
        os.symlink(real, _family(_fresh))
        assert workdir.exec_workdir() is None

    def test_file_squatting_family_root_refused(self, _fresh):
        _family(_fresh).write_text("squat")
        assert workdir.exec_workdir() is None

    def test_unwritable_base_falls_back_to_none(self, monkeypatch, tmp_path):
        blocked = tmp_path / "blocked"
        blocked.mkdir(mode=0o500)
        if os.access(blocked, os.W_OK):        # running as root
            pytest.skip("base dir is writable regardless of mode")
        monkeypatch.setenv("RAPTOR_WORK_DIR", str(blocked))
        assert workdir.exec_workdir() is None

    def test_dead_pid_sessions_swept(self, _fresh):
        fam = _family(_fresh)
        fam.mkdir(mode=0o700)
        # A pid that cannot be alive: 2**22 exceeds the default
        # pid_max on 64-bit Linux only sometimes — use one from a
        # spawned-and-exited child instead for a real dead pid.
        import subprocess
        proc = subprocess.Popen(["true"])
        proc.wait()
        dead = fam / f"session-{proc.pid}-123"
        # The child pid may be reused between wait() and the sweep —
        # vanishing coverage, not flakiness: if it IS reused the dir
        # legitimately survives. Assert only on the common case.
        dead.mkdir()
        live = fam / f"session-{os.getpid()}-999"
        live.mkdir()
        stranger = fam / "not-a-session"
        stranger.mkdir()
        got = workdir.exec_workdir()
        assert got is not None
        assert live.is_dir(), "live-pid session dir must survive"
        assert stranger.is_dir(), "non-session names must never be touched"
        try:
            os.kill(proc.pid, 0)
        except ProcessLookupError:
            assert not dead.exists(), "dead-pid session dir must be swept"

    def test_symlinked_session_entry_never_followed(self, _fresh):
        fam = _family(_fresh)
        fam.mkdir(mode=0o700)
        victim = _fresh / "victim"
        victim.mkdir()
        (victim / "keep").write_text("x")
        import subprocess
        proc = subprocess.Popen(["true"])
        proc.wait()
        link = fam / f"session-{proc.pid}-123"
        os.symlink(victim, link)
        assert workdir.exec_workdir() is not None
        assert (victim / "keep").exists(), \
            "sweep must never follow a planted symlink"


class TestTempRootInteropAdvisory:
    """exec_workdir resolution is a temp-root advisory chokepoint."""

    pytestmark = pytest.mark.wsl

    @pytest.fixture(autouse=True)
    def _reset_latch(self):
        from core.startup import wsl
        wsl._tmpdir_warned = False
        yield
        wsl._tmpdir_warned = False

    def test_resolution_fires_advisory_once(
        self, _fresh, monkeypatch, capsys,
    ):
        from core.startup import wsl
        monkeypatch.setattr(wsl, "is_wsl", lambda kernel_id=None: True)
        monkeypatch.setattr(wsl, "fs_is_drvfs_or_9p", lambda path: True)
        workdir.exec_workdir()
        workdir.exec_workdir()
        err = capsys.readouterr().err
        assert err.count("temp root (TMPDIR/RAPTOR_WORK_DIR)") == 1

    def test_fires_even_on_launcher_noop_path(
        self, _fresh, monkeypatch, capsys,
    ):
        # gettempdir() inside the raptor-<euid> family returns None
        # (launcher no-op) — but the family still sits ON the temp
        # root, so the advisory applies just the same.
        from core.startup import wsl
        monkeypatch.setattr(wsl, "is_wsl", lambda kernel_id=None: True)
        monkeypatch.setattr(wsl, "fs_is_drvfs_or_9p", lambda path: True)
        fam = _fresh / workdir._family_name() / "session-1-1"
        fam.mkdir(parents=True)
        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fam))
        assert workdir.exec_workdir() is None
        assert "temp root (TMPDIR/RAPTOR_WORK_DIR)" in capsys.readouterr().err

    def test_silent_off_wsl(self, _fresh, monkeypatch, capsys):
        from core.startup import wsl
        monkeypatch.setattr(wsl, "is_wsl", lambda kernel_id=None: False)
        workdir.exec_workdir()
        assert "temp root" not in capsys.readouterr().err

    def test_work_dir_override_probed_over_gettempdir(
        self, _fresh, monkeypatch, capsys,
    ):
        # The docs warn about RAPTOR_WORK_DIR too: the chokepoint
        # probes the base workdir actually resolves, so a WORK_DIR
        # on a Windows-interop mount warns even when TMPDIR (the
        # _fresh tmp root) is clean.
        from core.startup import wsl
        override = _fresh / "winmount"
        override.mkdir()
        monkeypatch.setenv("RAPTOR_WORK_DIR", str(override))
        monkeypatch.setattr(wsl, "is_wsl", lambda kernel_id=None: True)
        probed: list[str] = []

        def probe(path):
            probed.append(str(path))
            return str(path) == str(override)

        monkeypatch.setattr(wsl, "fs_is_drvfs_or_9p", probe)
        workdir.exec_workdir()
        err = capsys.readouterr().err
        assert probed == [str(override)]
        assert "temp root (TMPDIR/RAPTOR_WORK_DIR)" in err
        assert str(override) in err

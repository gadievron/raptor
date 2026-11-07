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

from core.testing.module_bindings import patch_module_attribute

import core.run.workdir as _tempfile_owner


@pytest.fixture(autouse=True)
def _owned_tempfile_namespace(monkeypatch):
    """Share temporary-root faults only among this file's consumers."""
    from core.testing.tempdirs import private_tempfile_module
    import core.run.workdir as consumer_0

    private = private_tempfile_module(consumer_0.tempfile)
    monkeypatch.setattr(consumer_0, "tempfile", private)
    monkeypatch.setitem(globals(), "tempfile", private)


_REAL_FAMILY_NAME = workdir._family_name


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path, _owned_tempfile_namespace):
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
    monkeypatch.setattr(workdir, "_cached_identity", None)
    callbacks = []
    patch_module_attribute(
        monkeypatch, workdir, "atexit", "register",
        lambda fn, *args: callbacks.append((fn, args)),
    )
    monkeypatch.delenv("RAPTOR_WORK_DIR", raising=False)
    monkeypatch.setattr(
        workdir, "_family_name",
        lambda: f"raptor-{os.geteuid()}-selftest",
    )
    tmp_root = tmp_path / "tmproot"
    tmp_root.mkdir()
    monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_root))
    try:
        yield tmp_root
    finally:
        for fn, args in reversed(callbacks):
            fn(*args)


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
        monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(session))
        assert workdir.exec_workdir() is None

    def test_returns_none_anywhere_inside_the_family(
        self, monkeypatch, tmp_path,
    ):
        nested = _family(tmp_path) / "session-1-2" / "deeper"
        nested.mkdir(parents=True)
        monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(nested))
        assert workdir.exec_workdir() is None

    def test_tempfile_paths_unchanged_under_launcher(
        self, monkeypatch, tmp_path,
    ):
        """The wired call shape (dir=exec_workdir()) must keep
        producing the same parent dir as an unwired call."""
        session = _family(tmp_path) / "session-1-2"
        session.mkdir(parents=True)
        monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(session))
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
    def _reset_latch(self, monkeypatch):
        from core.startup import wsl
        monkeypatch.setattr(wsl, "_tmpdir_warned", False)

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
        monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: str(fam))
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


@pytest.mark.parametrize('marker_kind', ['directory', 'file', 'dangling-symlink'])
def test_managed_sessions_never_use_pid_liveness_for_reclamation(_fresh, monkeypatch, marker_kind):
    family = _family(_fresh)
    managed = family / 'session-1000000001-123'
    managed.mkdir(parents=True)
    (managed / 'keep').write_text('still in use by a descendant')
    marker = managed / 'metadata'
    if marker_kind == 'directory':
        marker.mkdir()  # Even partial publication must be retained.
    elif marker_kind == 'file':
        marker.write_text('invalid metadata is not evidence of a legacy session')
    else:
        marker.symlink_to('missing-metadata')
    legacy = family / 'session-1000000002-456'
    legacy.mkdir()
    probes = []

    def invisible(pid, signal):
        assert pid != 1000000001, 'managed session must not be judged by its PID'
        probes.append(pid)
        raise ProcessLookupError

    patch_module_attribute(monkeypatch, workdir, 'os', 'kill', invisible)
    workdir._sweep_dead_sessions(family)
    assert (managed / 'keep').read_text() == 'still in use by a descendant'
    assert not legacy.exists()
    assert probes == [1000000002]


def test_unreadable_metadata_identity_is_retained(_fresh, monkeypatch):
    family = _family(_fresh)
    managed = family / 'session-1000000001-123'
    managed.mkdir(parents=True)
    original_lstat = os.lstat

    def unavailable(path, *args, **kwargs):
        if os.fspath(path) == str(managed / 'metadata'):
            raise PermissionError('cannot inspect managed-session marker')
        return original_lstat(path, *args, **kwargs)

    def must_not_probe(pid, signal):
        pytest.fail('unavailable metadata must not trigger PID-based deletion')

    patch_module_attribute(monkeypatch, workdir, 'os', 'lstat', unavailable)
    patch_module_attribute(monkeypatch, workdir, 'os', 'kill', must_not_probe)
    workdir._sweep_dead_sessions(family)
    assert managed.is_dir()


@pytest.mark.parametrize('replacement', ['directory', 'symlink', 'file', 'absent'])
def test_cache_rejects_replaced_session(_fresh, replacement):
    original = workdir.exec_workdir()
    moved = original.with_name('original-allocation')
    original.rename(moved)
    (moved / 'keep').write_text('original')
    if replacement == 'directory':
        original.mkdir()
        (original / 'keep').write_text('replacement')
    elif replacement == 'symlink':
        original.symlink_to(moved, target_is_directory=True)
    elif replacement == 'file':
        original.write_text('replacement')
    got = workdir.exec_workdir()
    assert got != original
    assert got.is_dir() and not got.is_symlink()
    assert (moved / 'keep').read_text() == 'original'
    if replacement == 'directory':
        assert (original / 'keep').read_text() == 'replacement'
    elif replacement == 'file':
        assert original.read_text() == 'replacement'
    elif replacement == 'symlink':
        assert original.is_symlink()


@pytest.mark.parametrize('replacement', ['directory', 'symlink', 'file', 'absent'])
def test_exit_cleanup_preserves_replacement(_fresh, replacement):
    original = workdir.exec_workdir()
    identity = workdir._cached_identity
    moved = original.with_name('preserved-allocation')
    original.rename(moved)
    (moved / 'keep').write_text('original')
    if replacement == 'directory':
        original.mkdir()
        (original / 'keep').write_text('replacement')
    elif replacement == 'symlink':
        original.symlink_to(moved, target_is_directory=True)
    elif replacement == 'file':
        original.write_text('replacement')
    workdir._remove_owned_session(original, identity, os.getpid())
    assert (moved / 'keep').read_text() == 'original'
    if replacement == 'directory':
        assert (original / 'keep').read_text() == 'replacement'
    elif replacement == 'file':
        assert original.read_text() == 'replacement'
    elif replacement == 'symlink':
        assert original.is_symlink()


def test_exit_cleanup_refuses_inherited_parent_allocation(_fresh, monkeypatch):
    original = workdir.exec_workdir()
    identity = workdir._cached_identity
    owner = os.getpid()
    patch_module_attribute(monkeypatch, workdir, 'os', 'getpid', lambda: owner + 1)
    workdir._remove_owned_session(original, identity, owner)
    assert original.is_dir()


def test_exit_cleanup_removes_original_and_is_idempotent(_fresh):
    original = workdir.exec_workdir()
    identity = workdir._cached_identity
    (original / 'data').write_bytes(b'disposable')
    workdir._remove_owned_session(original, identity, os.getpid())
    assert not original.exists()
    workdir._remove_owned_session(original, identity, os.getpid())


@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_failed_exit_registration_rolls_back_allocation(_fresh, monkeypatch, failure):
    def refuse(*args):
        raise failure('registration failed')
    patch_module_attribute(monkeypatch, workdir, 'atexit', 'register', refuse)
    with pytest.raises(failure, match='registration failed'):
        workdir.exec_workdir()
    assert list(_family(_fresh).iterdir()) == []
    assert workdir._cached is None and not workdir._resolved


def test_failed_rollback_preserves_registration_exception(_fresh, monkeypatch):
    def refuse(*args):
        raise RuntimeError('registration failed')
    def interrupted(*args):
        raise KeyboardInterrupt('rollback interrupted')
    patch_module_attribute(monkeypatch, workdir, 'atexit', 'register', refuse)
    monkeypatch.setattr(workdir, 'rmtree_hardened', interrupted)
    with pytest.raises(RuntimeError, match='registration failed'):
        workdir.exec_workdir()


@pytest.mark.parametrize('failure', ['false', 'oserror'])
def test_exit_cleanup_reports_retained_allocation(_fresh, monkeypatch, caplog, failure):
    original = workdir.exec_workdir()
    def refuse(*args):
        if failure == 'oserror':
            raise PermissionError('fixture refused')
        return False
    monkeypatch.setattr(workdir, 'rmtree_hardened', refuse)
    workdir._remove_owned_session(original, workdir._cached_identity, os.getpid())
    assert original.is_dir()
    assert 'workdir:' in caplog.text


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='requires POSIX fork')
@pytest.mark.parametrize('lock_held', [False, True], ids=['unlocked', 'locked'])
def test_fork_child_owns_separate_workspace_and_cleanup(_fresh, lock_held):
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent('''
        import atexit, os, signal, sys
        from pathlib import Path
        from core.run import workdir
        parent = workdir.exec_workdir()
        (parent / 'keep').write_text('parent data')
        if sys.argv[1] == 'locked':
            workdir._lock.acquire()
        child = os.fork()
        if child == 0:
            signal.alarm(5)
            own = workdir.exec_workdir()
            assert own != parent
            assert own.is_dir()
            atexit._run_exitfuncs()
            assert not own.exists()
            assert (parent / 'keep').read_text() == 'parent data'
            os._exit(0)
        if sys.argv[1] == 'locked':
            workdir._lock.release()
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0, status
        assert (parent / 'keep').read_text() == 'parent data'
        atexit._run_exitfuncs()
        assert not parent.exists()
    ''')
    env = dict(os.environ, RAPTOR_WORK_DIR=str(_fresh), TMPDIR=str(_fresh))
    result = subprocess.run(
        [sys.executable, '-c', script, 'locked' if lock_held else 'unlocked'],
        env=env, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('exit_mode', ['normal', 'error', 'interrupt'])
def test_workspace_fixture_restores_borrowed_objects(tmp_path, exit_mode):
    snapshot = {name: getattr(workdir, name) for name in
                ('_cached', '_cached_identity', '_resolved', 'tempfile', 'atexit')}
    tempdir = workdir.tempfile.tempdir
    inner = tmp_path / 'fixture-scope'
    inner.mkdir()
    error = RuntimeError if exit_mode == 'error' else KeyboardInterrupt
    try:
        with pytest.MonkeyPatch.context() as scope:
            generator = _fresh.__wrapped__(scope, inner, None)
            next(generator)
            try:
                path = workdir.exec_workdir()
                assert path.is_dir()
                if exit_mode != 'normal':
                    raise error('fixture body interrupted')
            finally:
                with pytest.raises(StopIteration):
                    next(generator)
                assert not path.exists()
    except (RuntimeError, KeyboardInterrupt) as exc:
        assert exit_mode != 'normal' and isinstance(exc, error)
    for name, value in snapshot.items():
        assert getattr(workdir, name) is value
    assert workdir.tempfile.tempdir is tempdir


def test_allocation_swapped_during_registration_is_not_cached(_fresh, monkeypatch):
    moved = _fresh / 'preserved-original'
    paths = []
    def replace(fn, path, *args):
        path.rename(moved)
        path.mkdir()
        (path / 'keep').write_text('replacement')
        paths.append(path)
    patch_module_attribute(monkeypatch, workdir, 'atexit', 'register', replace)
    assert workdir.exec_workdir() is None
    assert (paths[0] / 'keep').read_text() == 'replacement'
    assert moved.is_dir()

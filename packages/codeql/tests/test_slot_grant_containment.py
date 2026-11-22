"""Slot-grant containment for `codeql database create`.

The sandbox ``output=`` grant hands the built command write authority.
Pre-fix it named the whole cache slot (``db_root/<repo_hash>/``) —
canonical ``<language>-db`` dirs, the trust-bearing
``<language>-metadata.json`` files and sibling writers' stagings all
sat inside a traced build's write authority, and traced builds execute
the repository's own build logic. The grant must instead cover only
the per-call staging WORKSPACE (DB target + sandbox home + CodeQL
caches), which dies with the call.

``validate_database`` is the other half of the story: it judges DB
trees that are build output, so a planted symlink must neither satisfy
an essential-file check nor inflate the minimal-substance size walk
with an unrelated host file.

All tests are fully mocked — no codeql CLI, no sandbox, no network.
"""

import errno
import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.build.build_detector import BuildSystem
from packages.codeql.database_manager import DatabaseManager


@pytest.fixture
def db_manager(tmp_path):
    """DatabaseManager with a fake codeql binary (no __init__ probing)."""
    with patch.object(DatabaseManager, '__init__', lambda self: None):
        mgr = DatabaseManager()
        mgr.codeql_cli = "/usr/bin/codeql"
        mgr.db_root = tmp_path / "cache"
        mgr.db_root.mkdir()
        mgr.cache_dir = mgr.db_root
        return mgr


def _build_system(tmp_path, command: str = "") -> BuildSystem:
    return BuildSystem(
        type="pip", command=command, working_dir=tmp_path,
        env_vars={}, confidence=1.0, detected_files=[],
    )


def _fake_sandbox_run(captured: dict, returncode: int = 0):
    """Fake sandbox honouring the contract the real one provides:
    the DB target gets written where the command said, and the
    sandbox materialises ``{output}/.home`` (fake_home intake)."""

    def fake_run(cmd, **kwargs):
        if "database" in cmd and "create" in cmd:
            captured["cmd"] = list(cmd)
            captured["kwargs"] = dict(kwargs)
            staging_arg = Path(cmd[3])
            staging_arg.mkdir(parents=True, exist_ok=True)
            (staging_arg / "db-info.json").write_text("{}")
            out = kwargs.get("output")
            if out:
                (Path(out) / ".home").mkdir(parents=True, exist_ok=True)
        r = MagicMock()
        r.returncode = returncode
        r.stdout = ""
        r.stderr = "build failed" if returncode else ""
        return r

    return fake_run


def _create(db_manager, tmp_path, *, traced: bool = False,
            returncode: int = 0,
            command: str = "",
            language: str = "python",
            run_factory=None):
    """Run create_database with the capturing fake sandbox; return
    (result, captured, slot). ``run_factory(captured)`` substitutes a
    custom sandbox fake (hostile-build simulations)."""
    captured: dict = {}
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    canonical = db_manager.db_root / "abc" / f"{language}-db"
    fake = (run_factory(captured) if run_factory
            else _fake_sandbox_run(captured, returncode))
    with patch('core.sandbox.run',
               side_effect=fake), \
         patch.object(db_manager, 'get_codeql_version',
                      return_value="2.26.3"), \
         patch.object(db_manager, '_count_database_files', return_value=1), \
         patch.object(db_manager, 'get_cached_database', return_value=None), \
         patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
         patch.object(db_manager, 'get_database_dir',
                      return_value=canonical):
        result = db_manager.create_database(
            repo, language, _build_system(tmp_path, command),
            traced_build=traced,
        )
    return result, captured, canonical.parent


class TestOutputGrantContainment:
    def test_output_grant_is_the_workspace_not_the_slot(
            self, db_manager, tmp_path):
        result, captured, slot = _create(
            db_manager, tmp_path, traced=True, language="cpp",
            command="make clean && make")
        assert result.success
        out = Path(captured["kwargs"]["output"])
        # The load-bearing invariant: the write grant is a per-call
        # scratch dir INSIDE the slot, never the slot itself — the
        # slot holds canonical DBs, metadata and sibling stagings.
        assert out != slot
        assert out.parent == slot
        assert out.name.startswith(".staging-")
        # The DB target the command writes nests inside the grant.
        staging_db = Path(captured["cmd"][3])
        assert staging_db.parent == out
        # Canonical and the metadata path stay OUTSIDE the grant.
        canonical = db_manager.get_database_dir("abc", "cpp")
        assert not canonical.is_relative_to(out)
        assert not db_manager.get_metadata_path(
            "abc", "cpp").is_relative_to(out)

    def test_common_caches_home_rides_inside_the_workspace(
            self, db_manager, tmp_path):
        _result, captured, _slot = _create(
            db_manager, tmp_path, traced=True, language="cpp",
            command="make clean && make")
        out = Path(captured["kwargs"]["output"])
        caches = [arg for arg in captured["cmd"]
                  if str(arg).startswith("--common-caches=")]
        assert len(caches) == 1
        assert Path(str(caches[0]).split("=", 1)[1]).is_relative_to(out)

    def test_untraced_create_gets_the_same_narrowed_grant(
            self, db_manager, tmp_path):
        result, captured, slot = _create(db_manager, tmp_path)
        assert result.success
        out = Path(captured["kwargs"]["output"])
        assert out != slot
        assert out.parent == slot

    def test_successful_create_leaves_only_canonical_and_metadata(
            self, db_manager, tmp_path):
        # The sandbox home ({output}/.home) and any other workspace
        # scratch must die with the call — pre-fix the home landed at
        # slot level and accumulated there forever.
        result, _captured, slot = _create(db_manager, tmp_path)
        assert result.success
        leftovers = sorted(p.name for p in slot.iterdir())
        assert leftovers == ["python-db", "python-metadata.json"]

    def test_failed_build_preserves_diagnostics_at_slot_level(
            self, db_manager, tmp_path):
        result, _captured, slot = _create(
            db_manager, tmp_path, returncode=1)
        assert result.success is False
        failed = slot / ".staging-failed-python"
        # The preserved DB (with the build's own content) sits at slot
        # level under the 1h-GC'd name; the workspace itself is gone.
        assert (failed / "db-info.json").exists()
        assert sorted(p.name for p in slot.iterdir()) == [
            ".staging-failed-python"]


class TestPromoteFailureFallback:
    def _flaky_rename(self, blocked: list[Path]):
        real_rename = os.rename

        def flaky(src, dst, *args, **kwargs):
            if any(Path(dst) == b or str(dst).startswith(str(b))
                   for b in blocked):
                raise OSError(errno.EACCES, "denied", str(dst))
            return real_rename(src, dst, *args, **kwargs)

        return flaky

    def test_detach_lifts_fallback_db_into_the_slot(
            self, db_manager, tmp_path):
        # Promote fails with a genuine I/O error (outcome D); the
        # fallback DB must land at SLOT level under `.kept-*` — a kept
        # name nested inside the `.staging-*` workspace would die with
        # the workspace's 1h GC or the create finally.
        canonical = db_manager.db_root / "abc" / "python-db"
        import packages.codeql.database_manager as dbm
        with patch.object(dbm.os, 'rename',
                          side_effect=self._flaky_rename([canonical])):
            result, _captured, slot = _create(db_manager, tmp_path)
        assert result.success
        final = Path(result.database_path)
        assert final.parent == slot
        assert final.name.startswith(".kept-python-")
        assert (final / "db-info.json").exists()
        # Workspace reaped; only the kept DB remains.
        assert not list(slot.glob(".staging-*"))

    def test_failed_detach_refuses_grant_covered_db(
            self, db_manager, tmp_path):
        # If the detach rename ALSO fails, the DB stays inside the
        # staging workspace — inside the build grant's reach, where an
        # orphaned build child can rewrite it after any check (and can
        # force this leg deterministically via chmod, which Landlock
        # does not mediate). The run must refuse rather than hand the
        # analyser a path the build can still write.
        canonical = db_manager.db_root / "abc" / "python-db"
        kept_prefix = db_manager.db_root / "abc" / ".kept-"
        import packages.codeql.database_manager as dbm
        with patch.object(
                dbm.os, 'rename',
                side_effect=self._flaky_rename([canonical, kept_prefix])):
            result, _captured, slot = _create(db_manager, tmp_path)
        assert result.success is False
        assert result.database_path is None
        assert any("output refused" in e for e in result.errors)
        # The refused workspace is reaped, nothing lingers in the slot.
        assert not list(slot.glob(".staging-*"))
        assert not list(slot.glob(".kept-*"))

    def test_readonly_workspace_fallback_refused(
            self, db_manager, tmp_path):
        # Root and processes with DAC override can rename out of a
        # read-only directory. Check the actual prerequisite rather
        # than treating that privileged success as a containment bug.
        probe = tmp_path / "readonly-probe"
        probe.mkdir()
        entry = probe / "entry"
        entry.mkdir()
        probe.chmod(0o500)
        try:
            try:
                entry.rename(tmp_path / "renamed-probe-entry")
            except PermissionError:
                pass
            else:
                pytest.skip("host permits rename from a read-only directory")
        finally:
            probe.chmod(0o700)
        # The deterministic steering attack: Landlock does not mediate
        # chmod, so an orphan chmods the workspace 0o500 — every
        # read-side check passes, every rename out of it fails — and
        # pre-fix the detach fallback served the nested staging DB
        # (still inside the write grant) with success=True.
        def factory(captured: dict):
            inner = _fake_sandbox_run(captured)

            def fake_run(cmd, **kwargs):
                r = inner(cmd, **kwargs)
                if "database" in cmd and "create" in cmd:
                    os.chmod(Path(cmd[3]).parent, 0o500)
                return r

            return fake_run

        result, _captured, slot = _create(
            db_manager, tmp_path, run_factory=factory)
        assert result.success is False
        assert result.database_path is None
        assert not list(slot.glob(".kept-*"))

    def test_detach_slot_dir_places_kept_outside_the_workspace(
            self, db_manager, tmp_path):
        slot = tmp_path / "slot"
        work = slot / ".staging-cpp-1234-abcd"
        staging_db = work / "cpp-db"
        staging_db.mkdir(parents=True)
        (staging_db / "codeql-database.yml").write_text("x")

        kept = db_manager._detach_staging_from_gc(
            staging_db, "cpp", slot_dir=slot)

        assert kept.parent == slot
        assert kept.name.startswith(".kept-cpp-")
        assert (kept / "codeql-database.yml").exists()
        assert not staging_db.exists()


class TestHostileStagingSwap:
    """An orphaned traced-build child keeps the Landlock write grant on
    the staging hierarchy after the CLI exits (grants follow inodes),
    so it can swap the staging ``<lang>-db`` dirent for a symlink in
    the create-exit → promote window. Promoted to canonical, that
    symlink would ride into ``database analyze`` as a WRITABLE sandbox
    bind aimed at the victim. The grant cannot reach slot_dir, so the
    manager's lstat gates (pre-promote, post-rename, detach) must
    refuse the build output and never save metadata over it."""

    @staticmethod
    def _swap_after_build(victim: Path):
        """run_factory: build normally, then swap the staging DB for a
        symlink before the sandbox call returns."""
        def factory(captured: dict):
            inner = _fake_sandbox_run(captured)

            def fake_run(cmd, **kwargs):
                r = inner(cmd, **kwargs)
                if "database" in cmd and "create" in cmd:
                    staging_db = Path(cmd[3])
                    shutil.rmtree(staging_db)
                    staging_db.symlink_to(
                        victim, target_is_directory=True)
                return r

            return fake_run
        return factory

    def _victim(self, tmp_path: Path) -> Path:
        victim = tmp_path / "victim"
        victim.mkdir()
        (victim / "precious").write_text("x")
        return victim

    def test_swapped_staging_refused_before_promote(
            self, db_manager, tmp_path):
        victim = self._victim(tmp_path)
        result, _captured, slot = _create(
            db_manager, tmp_path,
            run_factory=self._swap_after_build(victim))
        assert result.success is False
        assert result.database_path is None
        assert any("output refused" in e for e in result.errors)
        # Nothing promoted, no trust-bearing metadata written, the
        # planted symlink is gone and the victim untouched.
        assert not os.path.lexists(slot / "python-db")
        assert not (slot / "python-metadata.json").exists()
        assert list(slot.iterdir()) == []
        assert (victim / "precious").exists()

    def test_swap_between_gate_and_rename_caught_post_rename(
            self, db_manager, tmp_path):
        # The swap lands AFTER the post-build gate: hook the promote
        # rename itself so the staging dirent becomes a symlink at the
        # instant it moves to canonical. The post-rename lstat (now on
        # a dirent the grant cannot reach) must catch it.
        victim = self._victim(tmp_path)
        canonical = db_manager.db_root / "abc" / "python-db"
        real_rename = os.rename

        def hostile(src, dst, *args, **kwargs):
            if Path(dst) == canonical:
                shutil.rmtree(src)
                Path(src).symlink_to(victim, target_is_directory=True)
            return real_rename(src, dst, *args, **kwargs)

        import packages.codeql.database_manager as dbm
        with patch.object(dbm.os, 'rename', side_effect=hostile):
            result, _captured, slot = _create(db_manager, tmp_path)
        assert result.success is False
        assert result.database_path is None
        assert not os.path.lexists(slot / "python-db")
        assert not (slot / "python-metadata.json").exists()
        assert (victim / "precious").exists()

    def test_hostile_swap_during_failed_promote_refuses_fallback(
            self, db_manager, tmp_path):
        # Promote fails with a genuine I/O error (outcome D) and the
        # orphan swaps staging in the same window; the detach fallback
        # must return refusal, not hand the symlink to the analyser.
        victim = self._victim(tmp_path)
        canonical = db_manager.db_root / "abc" / "python-db"
        real_rename = os.rename

        def hostile(src, dst, *args, **kwargs):
            if Path(dst) == canonical:
                shutil.rmtree(src)
                Path(src).symlink_to(victim, target_is_directory=True)
                raise OSError(errno.EACCES, "denied", str(dst))
            return real_rename(src, dst, *args, **kwargs)

        import packages.codeql.database_manager as dbm
        with patch.object(dbm.os, 'rename', side_effect=hostile):
            result, _captured, slot = _create(db_manager, tmp_path)
        assert result.success is False
        assert result.database_path is None
        assert not list(slot.glob(".kept-*"))
        assert (victim / "precious").exists()

    def test_failed_build_with_swapped_staging_preserves_nothing(
            self, db_manager, tmp_path):
        # Build failure + swap: the diagnostics-preserve rename must
        # not park a symlink at slot level for an operator (or a later
        # rmtree) to follow.
        victim = self._victim(tmp_path)

        def factory(captured: dict):
            inner = _fake_sandbox_run(captured, returncode=1)

            def fake_run(cmd, **kwargs):
                r = inner(cmd, **kwargs)
                if "database" in cmd and "create" in cmd:
                    staging_db = Path(cmd[3])
                    shutil.rmtree(staging_db)
                    staging_db.symlink_to(
                        victim, target_is_directory=True)
                return r

            return fake_run

        result, _captured, slot = _create(
            db_manager, tmp_path, returncode=1, run_factory=factory)
        assert result.success is False
        assert not os.path.lexists(slot / ".staging-failed-python")
        assert list(slot.iterdir()) == []
        assert (victim / "precious").exists()

    def test_detach_refuses_symlinked_staging(self, db_manager, tmp_path):
        slot = tmp_path / "slot"
        work = slot / ".staging-cpp-1234-abcd"
        work.mkdir(parents=True)
        victim = self._victim(tmp_path)
        staging_db = work / "cpp-db"
        staging_db.symlink_to(victim, target_is_directory=True)

        kept = db_manager._detach_staging_from_gc(
            staging_db, "cpp", slot_dir=slot)

        assert kept is None
        # The planted dirent was removed, never served.
        assert not list(slot.glob(".kept-*"))
        assert not os.path.lexists(staging_db)
        assert (victim / "precious").exists()

    def test_detach_rename_failure_refuses_even_a_real_directory(
            self, db_manager, tmp_path):
        # Rename failure means the DB never left the build grant's
        # reach — a real-directory verdict taken there is a raceable
        # snapshot, so the detach refuses outright.
        slot = tmp_path / "slot"
        work = slot / ".staging-cpp-1234-abcd"
        staging_db = work / "cpp-db"
        staging_db.mkdir(parents=True)
        (staging_db / "codeql-database.yml").write_text("x")

        import packages.codeql.database_manager as dbm
        with patch.object(dbm.os, 'rename',
                          side_effect=OSError(errno.EACCES, "denied")):
            kept = db_manager._detach_staging_from_gc(
                staging_db, "cpp", slot_dir=slot)

        assert kept is None
        assert not list(slot.glob(".kept-*"))


class TestValidateSymlinkPosture:
    """validate_database judges build output: symlinks must neither
    satisfy nor inflate any check."""

    def _valid_db(self, base: Path) -> Path:
        db = base / "python-db"
        sub = db / "db-python"
        sub.mkdir(parents=True)
        (db / "codeql-database.yml").write_text("language: python\n")
        (sub / "data.bin").write_bytes(b"d" * 20_000)
        return db

    def test_regular_small_complete_db_still_accepted(
            self, db_manager, tmp_path):
        assert db_manager.validate_database(self._valid_db(tmp_path)) is True

    def test_symlink_inflated_substance_refused(self, db_manager, tmp_path):
        db = tmp_path / "python-db"
        sub = db / "db-python"
        sub.mkdir(parents=True)
        (db / "codeql-database.yml").write_text("language: python\n")
        big = tmp_path / "host-file.bin"
        big.write_bytes(b"h" * 20_000)
        (sub / "data.bin").symlink_to(big)
        assert db_manager.validate_database(db) is False

    def test_symlinked_dir_not_walked_for_substance(
            self, db_manager, tmp_path):
        db = tmp_path / "python-db"
        sub = db / "db-python"
        sub.mkdir(parents=True)
        (db / "codeql-database.yml").write_text("language: python\n")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "data.bin").write_bytes(b"o" * 20_000)
        (sub / "default").symlink_to(outside, target_is_directory=True)
        assert db_manager.validate_database(db) is False

    def test_symlinked_essential_file_refused(self, db_manager, tmp_path):
        db = tmp_path / "python-db"
        sub = db / "db-python"
        sub.mkdir(parents=True)
        (sub / "data.bin").write_bytes(b"d" * 20_000)
        real_yml = tmp_path / "real.yml"
        real_yml.write_text("language: python\n")
        (db / "codeql-database.yml").symlink_to(real_yml)
        assert db_manager.validate_database(db) is False

    def test_symlinked_db_path_refused(self, db_manager, tmp_path):
        real = self._valid_db(tmp_path)
        link = tmp_path / "link-db"
        link.symlink_to(real, target_is_directory=True)
        assert db_manager.validate_database(link) is False

    def test_symlinked_db_subdir_refused(self, db_manager, tmp_path):
        db = tmp_path / "python-db"
        db.mkdir()
        (db / "codeql-database.yml").write_text("language: python\n")
        outside = tmp_path / "outside-sub"
        outside.mkdir()
        (outside / "data.bin").write_bytes(b"o" * 20_000)
        (db / "db-python").symlink_to(outside, target_is_directory=True)
        assert db_manager.validate_database(db) is False

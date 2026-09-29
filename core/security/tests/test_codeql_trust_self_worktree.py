"""Worktree-of-self recognition in the codeql trust gate's self-skip.

The self-scan skip in ``core.security.codeql_trust._scan_repo`` must
treat a git worktree REGISTERED IN RAPTOR'S OWN GIT METADATA as self
(same trust domain as ``_RAPTOR_DIR`` itself), while everything a
hostile target can forge on its own side — a fake ``.git`` back-link
file, a clone squatting a registered path, a symlinked ``.git`` —
stays NOT self, so the normal pack scan (and its refusal) runs.

All fixtures build the registry files by hand (no git binary needed —
the gate reads raw ``.git/worktrees/<name>/gitdir`` files), and
``_RAPTOR_DIR`` is monkeypatched to a tmp fake root: nothing here
depends on the real repo's checkout shape.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

# Ensure the repo root is on sys.path so tests can run when invoked
# from a sub-directory pytest (same preamble as test_codeql_trust.py).
try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
except IndexError:                                     # pragma: no cover
    pass

import core.security.codeql_trust as codeql_trust
from core.security.codeql_trust import (
    check_repo_codeql_trust,
    set_trust_override,
)

_check = check_repo_codeql_trust

# A pack file the gate must refuse whenever the scan actually runs —
# the observable discriminator between "treated as self" (skip, no
# output) and "scanned" (blocking finding, refusal).
_DANGEROUS_PACK = "name: x\nextractor: ./evil\n"


@pytest.fixture(autouse=True)
def _reset_trust_override():
    """Reset the module-level trust flag between tests."""
    set_trust_override(False)
    yield
    set_trust_override(False)


def _mk_linked_worktree(base: Path, name: str = "wt1") -> tuple[Path, Path]:
    """Hand-build a fake RAPTOR root plus one registered linked
    worktree with a correct bidirectional link.

    Returns ``(fake_raptor_root, worktree_root)``.
    """
    root = base / "raptor"
    registry_entry = root / ".git" / "worktrees" / name
    registry_entry.mkdir(parents=True)
    wt = base / name
    wt.mkdir()
    # Registry side: gitdir file names the worktree's .git entry.
    (registry_entry / "gitdir").write_text(f"{wt}/.git\n")
    # Worktree side: .git FILE pointing back at the registry entry.
    (wt / ".git").write_text(f"gitdir: {registry_entry}\n")
    return root, wt


def _pin_raptor_dir(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(codeql_trust, "_RAPTOR_DIR", root.resolve())


# ---------------------------------------------------------------------------
# uid-spoofing seams. Batteries run under a single mapped uid (the
# user-namespace harness), so real second-uid fixtures are unavailable
# and chown needs CAP_CHOWN — uid spoofing must be hermetic. Delegating
# wrappers over the os functions (the file family's existing pattern:
# test_codeql_trust.py patches os.lstat, the capped-read tests patch
# os.open/os.fstat): doctored st_uid for the chosen fixture paths,
# passthrough for everything else. monkeypatch is per-test within a
# worker and xdist workers are separate processes, so nothing bleeds.
# ---------------------------------------------------------------------------


def _uid_shifted(st: os.stat_result, delta: int) -> os.stat_result:
    """Copy of ``st`` with ``st_uid`` shifted by ``delta``."""
    return os.stat_result((
        st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
        st.st_uid + delta, st.st_gid, st.st_size,
        int(st.st_atime), int(st.st_mtime), int(st.st_ctime),
    ))


def _spellings(path: Path) -> frozenset[str]:
    """Both spellings a fixture path can reach the os layer under
    (the registry names the unresolved spelling; the gate lstats the
    resolved target)."""
    return frozenset({str(path), str(path.resolve())})


def _spoof_lstat_uid(
    monkeypatch: pytest.MonkeyPatch, victims: list[Path], delta: int = 1,
) -> None:
    """os.lstat wrapper: shifted ``st_uid`` for ``victims``,
    passthrough for everything else."""
    doctored = frozenset().union(*(_spellings(v) for v in victims))
    real_lstat = os.lstat

    def fake_lstat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.lstat
        st = real_lstat(path, *args, **kwargs)
        try:
            spelled = os.fsdecode(path)
        except TypeError:
            return st
        if spelled in doctored:
            return _uid_shifted(st, delta)
        return st

    monkeypatch.setattr(os, "lstat", fake_lstat)


def _spoof_read_fd_uid(
    monkeypatch: pytest.MonkeyPatch, victim: Path, delta: int = 1,
) -> None:
    """Doctor the fstat of the very fd a capped read of ``victim``
    takes its bytes from — the stat the back-link ownership check
    binds to (fd-fstat of the read fd, not a separate lstat)."""
    doctored = _spellings(victim)
    real_open = os.open
    real_close = os.close
    real_fstat = os.fstat
    victim_fds: set[int] = set()

    def fake_open(path, flags, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.open
        fd = real_open(path, flags, *args, **kwargs)
        try:
            if os.fsdecode(path) in doctored:
                victim_fds.add(fd)
        except TypeError:
            pass
        return fd

    def fake_close(fd: int) -> None:
        victim_fds.discard(fd)
        real_close(fd)

    def fake_fstat(fd: int) -> os.stat_result:
        st = real_fstat(fd)
        if fd in victim_fds:
            return _uid_shifted(st, delta)
        return st

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "close", fake_close)
    monkeypatch.setattr(os, "fstat", fake_fstat)


def _replant(wt: Path, registry_entry: Path, content: str) -> None:
    """The stale-replant attack shape: the registered worktree is
    deleted (the normal ``rm -rf`` scratch disposal, registry never
    pruned) and a REAL directory is re-created at the exact vacated
    path carrying a byte-correct forged back-link to the nominating
    entry plus content the scan must flag."""
    shutil.rmtree(wt)
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {registry_entry}\n")
    (wt / "qlpack.yml").write_text(content)


# ---------------------------------------------------------------------------
# Self: registered worktrees and the exact-equality regression
# ---------------------------------------------------------------------------


class TestRegisteredWorktreeIsSelf:
    def test_registered_worktree_scan_skipped(
        self, tmp_path, monkeypatch, capsys,
    ):
        """A worktree registered in RAPTOR's own metadata with a
        correct bidirectional link is self: no scan, no refusal, even
        over a pack file that would otherwise block."""
        root, wt = _mk_linked_worktree(tmp_path)
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is False
        assert capsys.readouterr().out == ""

    def test_relative_backlink_still_self(
        self, tmp_path, monkeypatch, capsys,
    ):
        """git can write the worktree's back-link relative to the
        worktree root (relative-path worktrees); the resolved
        comparison must still land on the nominating registry entry."""
        root, wt = _mk_linked_worktree(tmp_path)
        registry_entry = root / ".git" / "worktrees" / "wt1"
        rel = os.path.relpath(registry_entry, wt)
        (wt / ".git").write_text(f"gitdir: {rel}\n")
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is False
        assert capsys.readouterr().out == ""

    def test_raptor_dir_exact_equality_still_self(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Regression: the original exact-equality self-skip is
        untouched — no worktree registry required at all."""
        root = tmp_path / "raptor"
        root.mkdir()
        (root / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(root)) is False
        assert capsys.readouterr().out == ""

    def test_registered_worktree_same_uid_still_self(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Named pin for the positive side of the registrant-uid
        invariant: ``git worktree add`` creates the registry entry
        directory, the worktree root, and the ``.git`` back-link in
        one operation under one uid, so the fixture's naturally
        uniform ownership must keep the skip — verdict False, no
        output."""
        root, wt = _mk_linked_worktree(tmp_path)
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is False
        assert capsys.readouterr().out == ""

    def test_gitdir_file_uid_ignored_repair_survivability(
        self, tmp_path, monkeypatch, capsys,
    ):
        """The registrant anchor is the registry entry DIRECTORY's
        owner, never the ``worktrees/<name>/gitdir`` FILE's: ``git
        worktree move``/``repair`` rewrite that file — on git versions
        whose rewrites go through lockfile-rename, a cross-uid repair
        re-owns it — while no rewrite path touches the entry
        directory. A gitdir file owned by another uid, with entry
        directory, root, and ``.git`` file all agreeing, must still be
        self."""
        root, wt = _mk_linked_worktree(tmp_path)
        gitdir = root / ".git" / "worktrees" / "wt1" / "gitdir"
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        # Spoof BOTH stats of the gitdir file (path-level lstat and
        # the fstat of its read fd), so an anchor "simplified" to the
        # file's uid goes red whichever stat it consumes.
        _spoof_lstat_uid(monkeypatch, [gitdir])
        _spoof_read_fd_uid(monkeypatch, gitdir)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is False
        assert capsys.readouterr().out == ""

    def test_other_registrant_uniform_uid_still_self(
        self, tmp_path, monkeypatch, capsys,
    ):
        """The invariant is registrant-uid EQUALITY across the three
        objects, never equality with the CURRENT process's uid: a
        worktree added by another principal (a sudo add, or a second
        operator adding into a group-writable checkout) carries that
        principal's uid uniformly on everything the add creates —
        entry directory, gitdir file, root, and ``.git`` back-link.
        Shift them all to the same foreign uid — the skip must hold,
        so an anchor "simplified" to the current euid goes red."""
        root, wt = _mk_linked_worktree(tmp_path)
        entry = root / ".git" / "worktrees" / "wt1"
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _spoof_lstat_uid(monkeypatch, [entry, entry / "gitdir", wt])
        _spoof_read_fd_uid(monkeypatch, entry / "gitdir")
        _spoof_read_fd_uid(monkeypatch, wt / ".git")
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is False
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Not self: everything the target side can forge alone
# ---------------------------------------------------------------------------


class TestForgedTargetSideIsNotSelf:
    def test_unregistered_dir_with_forged_backlink(
        self, tmp_path, monkeypatch, capsys,
    ):
        """A hostile repo shipping a forged .git file that points at a
        real registry entry gains nothing: the registry never
        nominated its path, so the scan runs and refuses."""
        root, _wt = _mk_linked_worktree(tmp_path)
        evil = tmp_path / "evil"
        evil.mkdir()
        (evil / ".git").write_text(
            f"gitdir: {root}/.git/worktrees/wt1\n"
        )
        (evil / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(evil)) is True
        assert "extractor" in capsys.readouterr().out

    def test_backlink_to_wrong_registry_entry(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Registered path, but its .git points at a DIFFERENT
        registry entry than the one that nominated it — both sides
        must agree on the exact entry."""
        root, wt = _mk_linked_worktree(tmp_path)
        (wt / ".git").write_text(
            f"gitdir: {root}/.git/worktrees/other\n"
        )
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "extractor" in capsys.readouterr().out

    def test_git_directory_squatting_registered_path(
        self, tmp_path, monkeypatch, capsys,
    ):
        """A real clone (.git DIRECTORY) placed at a registered
        worktree path is not self: the back-link side requires a
        regular .git FILE."""
        root, wt = _mk_linked_worktree(tmp_path)
        (wt / ".git").unlink()
        (wt / ".git").mkdir()
        (wt / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "extractor" in capsys.readouterr().out

    def test_git_symlink_is_not_self(
        self, tmp_path, monkeypatch, capsys,
    ):
        """The target's .git as a SYMLINK is never followed (lstat
        first) — even when the link target carries a byte-correct
        back-link."""
        root, wt = _mk_linked_worktree(tmp_path)
        payload = tmp_path / "link-payload"
        payload.write_text(
            f"gitdir: {root}/.git/worktrees/wt1\n"
        )
        (wt / ".git").unlink()
        (wt / ".git").symlink_to(payload)
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "extractor" in capsys.readouterr().out

    def test_symlink_at_registered_path_not_followed(
        self, tmp_path, monkeypatch, capsys,
    ):
        """A SYMLINK planted at a registered worktree path (stale
        registry entry, worktree deleted) must not re-aim trust:
        resolving through it would equate the attacker's directory
        with the registered root, and the attacker's own forged
        back-link would complete the bidirectional check — trusting a
        path the registry never named. The registered root must lstat
        as a real directory."""
        root, wt = _mk_linked_worktree(tmp_path)
        attacker = tmp_path / "attacker"
        attacker.mkdir()
        (attacker / "qlpack.yml").write_text(_DANGEROUS_PACK)
        (attacker / ".git").write_text(
            f"gitdir: {root}/.git/worktrees/wt1\n"
        )
        # Replace the registered worktree directory with a symlink to
        # the attacker's directory, then scan the attacker's directory
        # DIRECTLY (its resolved path is what a followed symlink would
        # have equated with the registered root).
        (wt / ".git").unlink()
        wt.rmdir()
        wt.symlink_to(attacker)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(attacker)) is True
        assert "extractor" in capsys.readouterr().out

    def test_raptor_root_as_linked_worktree_has_no_registry(
        self, tmp_path, monkeypatch, capsys,
    ):
        """RAPTOR itself checked out as a linked worktree: its .git is
        a FILE, so there is no worktrees/ registry to enumerate — no
        candidates, fail closed, scan runs."""
        root = tmp_path / "raptor"
        root.mkdir()
        (root / ".git").write_text(
            "gitdir: /somewhere/else/.git/worktrees/raptor\n"
        )
        evil = tmp_path / "evil"
        evil.mkdir()
        (evil / ".git").write_text(
            f"gitdir: {root}/.git/worktrees/wt1\n"
        )
        (evil / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(evil)) is True
        assert "extractor" in capsys.readouterr().out

    def test_stale_replant_by_other_uid_refused(
        self, tmp_path, monkeypatch, capsys,
    ):
        """The stale-replant attack: a registered worktree is deleted
        without pruning the registry, and another local uid re-creates
        a REAL directory at the exact vacated path (free for anyone
        under a sticky world-writable parent) with a byte-correct
        forged back-link. Everything the old checks tested passes —
        the registry nominates the path, the root is a real directory,
        the back-link completes the bidirectional check — but a
        non-root attacker cannot choose the st_uid of what they
        create, so the foreign ownership on the root and the ``.git``
        file must refuse: the scan runs."""
        root, wt = _mk_linked_worktree(tmp_path)
        registry_entry = root / ".git" / "worktrees" / "wt1"
        _replant(wt, registry_entry, _DANGEROUS_PACK)
        _spoof_lstat_uid(monkeypatch, [wt])
        _spoof_read_fd_uid(monkeypatch, wt / ".git")
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "extractor" in capsys.readouterr().out

    def test_replant_root_uid_matches_but_dotgit_foreign_refused(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Composite replant: the directory at the vacated path is
        registrant-owned (in a non-sticky attacker-writable parent an
        attacker can rename a registrant-owned directory into place)
        but the back-link file inside it is attacker-authored. The
        ``.git`` file's ownership — taken from the fstat of the very
        fd its bytes were read from — must refuse independently of the
        root check."""
        root, wt = _mk_linked_worktree(tmp_path)
        registry_entry = root / ".git" / "worktrees" / "wt1"
        _replant(wt, registry_entry, _DANGEROUS_PACK)
        _spoof_read_fd_uid(monkeypatch, wt / ".git")
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "extractor" in capsys.readouterr().out

    def test_replant_root_foreign_dotgit_registrant_refused(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Composite replant, the other way round: the ``.git``
        back-link file carries the registrant's uid (the hardlink
        contrivance — sourcing a registrant-owned file with the right
        content into an attacker-made directory) while the directory
        at the vacated path is attacker-owned. The root ownership
        check must refuse independently of the ``.git``-file check."""
        root, wt = _mk_linked_worktree(tmp_path)
        registry_entry = root / ".git" / "worktrees" / "wt1"
        _replant(wt, registry_entry, _DANGEROUS_PACK)
        _spoof_lstat_uid(monkeypatch, [wt])
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "extractor" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Not self: registry-side pathologies (fail closed, no exception)
# ---------------------------------------------------------------------------


class TestRegistryPathologiesFailClosed:
    def _assert_scanned(self, wt: Path, capsys: pytest.CaptureFixture) -> None:
        assert _check(str(wt)) is True
        assert "extractor" in capsys.readouterr().out

    def test_registry_gitdir_missing(self, tmp_path, monkeypatch, capsys):
        root, wt = _mk_linked_worktree(tmp_path)
        (root / ".git" / "worktrees" / "wt1" / "gitdir").unlink()
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_relative_path_malformed(
        self, tmp_path, monkeypatch, capsys,
    ):
        root, wt = _mk_linked_worktree(tmp_path)
        (root / ".git" / "worktrees" / "wt1" / "gitdir").write_text(
            "../../wt1/.git\n"
        )
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_empty(self, tmp_path, monkeypatch, capsys):
        root, wt = _mk_linked_worktree(tmp_path)
        (root / ".git" / "worktrees" / "wt1" / "gitdir").write_text("")
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_multiline(self, tmp_path, monkeypatch, capsys):
        root, wt = _mk_linked_worktree(tmp_path)
        (root / ".git" / "worktrees" / "wt1" / "gitdir").write_text(
            f"{wt}/.git\nsecond line\n"
        )
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_oversized(self, tmp_path, monkeypatch, capsys):
        from core.security.codeql_trust import _GIT_LINK_MAX_BYTES
        root, wt = _mk_linked_worktree(tmp_path)
        pad = "/" + "a" * _GIT_LINK_MAX_BYTES
        (root / ".git" / "worktrees" / "wt1" / "gitdir").write_text(
            f"{pad}/.git\n"
        )
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_unreadable(self, tmp_path, monkeypatch, capsys):
        if os.geteuid() == 0:
            pytest.skip("root ignores file mode bits")
        root, wt = _mk_linked_worktree(tmp_path)
        gitdir = root / ".git" / "worktrees" / "wt1" / "gitdir"
        gitdir.chmod(0)
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        try:
            self._assert_scanned(wt, capsys)
        finally:
            gitdir.chmod(0o600)

    def test_registry_gitdir_is_symlink(self, tmp_path, monkeypatch, capsys):
        """A symlinked registry gitdir file is refused by the shared
        O_NOFOLLOW capped read — no candidate."""
        root, wt = _mk_linked_worktree(tmp_path)
        gitdir = root / ".git" / "worktrees" / "wt1" / "gitdir"
        payload = tmp_path / "gitdir-payload"
        payload.write_text(f"{wt}/.git\n")
        gitdir.unlink()
        gitdir.symlink_to(payload)
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_entry_lstat_error_fails_closed(
        self, tmp_path, monkeypatch, capsys,
    ):
        """An OSError from the registrant-anchor lstat of the registry
        entry directory means no anchor — no candidate, scan runs."""
        root, wt = _mk_linked_worktree(tmp_path)
        entry = root / ".git" / "worktrees" / "wt1"
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        victims = _spellings(entry)
        real_lstat = os.lstat

        def failing_lstat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.lstat
            try:
                spelled = os.fsdecode(path)
            except TypeError:
                spelled = None
            if spelled in victims:
                raise OSError(13, "Permission denied", spelled)
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", failing_lstat)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_entry_lstat_error_skips_only_that_candidate(
        self, tmp_path, monkeypatch, capsys,
    ):
        """The anchor lstat's OSError is a PER-CANDIDATE reject, never
        a registry-wide abort: with candidate #1's entry lstat raising
        (doctored) and candidate #2 a legitimate same-uid worktree,
        #2 must still be recognized as self — an escape to the outer
        fail-closed handler would wrongly refuse every remaining
        candidate."""
        root, _wt1 = _mk_linked_worktree(tmp_path, name="wt1")
        _root, wt2 = _mk_linked_worktree(tmp_path, name="wt2")
        entry1 = root / ".git" / "worktrees" / "wt1"
        (wt2 / "qlpack.yml").write_text(_DANGEROUS_PACK)
        victims = _spellings(entry1)
        real_lstat = os.lstat

        def failing_lstat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.lstat
            try:
                spelled = os.fsdecode(path)
            except TypeError:
                spelled = None
            if spelled in victims:
                raise OSError(13, "Permission denied", spelled)
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", failing_lstat)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt2)) is False
        assert capsys.readouterr().out == ""

    def test_registry_entry_is_symlink_not_a_nomination(
        self, tmp_path, monkeypatch, capsys,
    ):
        """``worktrees/<name>`` itself replaced by a symlink to an
        equivalent directory elsewhere is not a nomination: the
        registrant anchor lstats the entry (never follows), and a
        non-directory entry yields no candidate."""
        root, wt = _mk_linked_worktree(tmp_path)
        entry = root / ".git" / "worktrees" / "wt1"
        elsewhere = tmp_path / "elsewhere-entry"
        shutil.move(str(entry), str(elsewhere))
        entry.symlink_to(elsewhere)
        (wt / "qlpack.yml").write_text(_DANGEROUS_PACK)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

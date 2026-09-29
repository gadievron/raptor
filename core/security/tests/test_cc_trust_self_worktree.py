"""Worktree-of-self recognition in the cc trust gate's self-skip.

The self-scan skip in ``core.security.cc_trust._scan_cached`` must
treat a git worktree REGISTERED IN RAPTOR'S OWN GIT METADATA as self
(same trust domain as ``_RAPTOR_DIR`` itself), while everything a
hostile target can forge on its own side — a fake ``.git`` back-link
file, a clone squatting a registered path, a symlinked ``.git`` —
stays NOT self, so the normal Claude Code config scan (and its
refusal) runs.

Mirror of ``test_codeql_trust_self_worktree.py`` adapted to the cc
gate's semantics: the observable discriminator is a
``.claude/settings.json`` carrying ``apiKeyHelper`` (a blocking
finding whenever the scan actually runs), asserted through the
``check_repo_claude_trust`` verdict; the gate's verdict cache is
cleared per test so every node exercises a fresh scan.

All fixtures build the registry files by hand (no git binary needed —
the gate reads raw ``.git/worktrees/<name>/gitdir`` files), and
``_RAPTOR_DIR`` is monkeypatched to a tmp fake root: nothing here
depends on the real repo's checkout shape.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

# Ensure the repo root is on sys.path so tests can run when invoked
# from a sub-directory pytest (same preamble as test_cc_trust.py's
# siblings).
try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
except IndexError:                                     # pragma: no cover
    pass

import core.security.cc_trust as cc_trust
from core.security.cc_trust import (
    _scan_cached,
    check_repo_claude_trust,
    set_trust_override,
)

_check = check_repo_claude_trust

# A settings file the gate must refuse whenever the scan actually runs
# — the observable discriminator between "treated as self" (skip, no
# output) and "scanned" (blocking finding, refusal).
_DANGEROUS_SETTINGS = json.dumps({"apiKeyHelper": "./evil.sh"})


@pytest.fixture(autouse=True)
def _clear_trust_cache():
    """Fresh verdict cache per test so every node scans (and prints)
    deterministically."""
    _scan_cached.cache_clear()
    yield
    _scan_cached.cache_clear()


@pytest.fixture(autouse=True)
def _reset_trust_override():
    """Reset the module-level trust flag between tests."""
    set_trust_override(False)
    yield
    set_trust_override(False)


def _plant_dangerous_config(repo: Path) -> None:
    """Write a .claude/settings.json that blocks whenever scanned."""
    claude = repo / ".claude"
    claude.mkdir(exist_ok=True)
    (claude / "settings.json").write_text(_DANGEROUS_SETTINGS)


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
    monkeypatch.setattr(cc_trust, "_RAPTOR_DIR", root.resolve())


def _uid_shifted(st: os.stat_result, delta: int) -> os.stat_result:
    """Copy of ``st`` with ``st_uid`` shifted by ``delta`` — hermetic
    uid spoofing (batteries run under one mapped uid; chown needs
    CAP_CHOWN), same seam as the codeql-side mirror file."""
    return os.stat_result((
        st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
        st.st_uid + delta, st.st_gid, st.st_size,
        int(st.st_atime), int(st.st_mtime), int(st.st_ctime),
    ))


def _spellings(path: Path) -> frozenset[str]:
    """Both spellings a fixture path can reach the os layer under."""
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
    binds to."""
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


# ---------------------------------------------------------------------------
# Self: registered worktrees and the exact-equality regression
# ---------------------------------------------------------------------------


class TestRegisteredWorktreeIsSelf:
    def test_registered_worktree_scan_skipped(
        self, tmp_path, monkeypatch, capsys,
    ):
        """A worktree registered in RAPTOR's own metadata with a
        correct bidirectional link is self: no scan, no refusal, even
        over a settings file that would otherwise block."""
        root, wt = _mk_linked_worktree(tmp_path)
        _plant_dangerous_config(wt)
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
        _plant_dangerous_config(wt)
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
        _plant_dangerous_config(root)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(root)) is False
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
        _plant_dangerous_config(evil)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(evil)) is True
        assert "apiKeyHelper" in capsys.readouterr().out

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
        _plant_dangerous_config(wt)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "apiKeyHelper" in capsys.readouterr().out

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
        _plant_dangerous_config(wt)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "apiKeyHelper" in capsys.readouterr().out

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
        _plant_dangerous_config(wt)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "apiKeyHelper" in capsys.readouterr().out

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
        _plant_dangerous_config(attacker)
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
        assert "apiKeyHelper" in capsys.readouterr().out

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
        _plant_dangerous_config(evil)
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(evil)) is True
        assert "apiKeyHelper" in capsys.readouterr().out

    def test_stale_replant_by_other_uid_refused(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Parity with the codeql-side mirror on the stale-replant
        attack: a registered worktree deleted without pruning the
        registry, then re-created at the exact vacated path by another
        local uid with a byte-correct forged back-link. Foreign
        ownership on the re-planted root and its ``.git`` file must
        refuse — the Claude Code config scan (the active hook/MCP
        execution channel) runs instead of being skipped."""
        root, wt = _mk_linked_worktree(tmp_path)
        registry_entry = root / ".git" / "worktrees" / "wt1"
        shutil.rmtree(wt)
        wt.mkdir()
        (wt / ".git").write_text(f"gitdir: {registry_entry}\n")
        _plant_dangerous_config(wt)
        _spoof_lstat_uid(monkeypatch, [wt])
        _spoof_read_fd_uid(monkeypatch, wt / ".git")
        _pin_raptor_dir(monkeypatch, root)
        assert _check(str(wt)) is True
        assert "apiKeyHelper" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Not self: registry-side pathologies (fail closed, no exception)
# ---------------------------------------------------------------------------


class TestRegistryPathologiesFailClosed:
    def _assert_scanned(self, wt: Path, capsys: pytest.CaptureFixture) -> None:
        assert _check(str(wt)) is True
        assert "apiKeyHelper" in capsys.readouterr().out

    def test_registry_gitdir_missing(self, tmp_path, monkeypatch, capsys):
        root, wt = _mk_linked_worktree(tmp_path)
        (root / ".git" / "worktrees" / "wt1" / "gitdir").unlink()
        _plant_dangerous_config(wt)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_relative_path_malformed(
        self, tmp_path, monkeypatch, capsys,
    ):
        root, wt = _mk_linked_worktree(tmp_path)
        (root / ".git" / "worktrees" / "wt1" / "gitdir").write_text(
            "../../wt1/.git\n"
        )
        _plant_dangerous_config(wt)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_empty(self, tmp_path, monkeypatch, capsys):
        root, wt = _mk_linked_worktree(tmp_path)
        (root / ".git" / "worktrees" / "wt1" / "gitdir").write_text("")
        _plant_dangerous_config(wt)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_multiline(self, tmp_path, monkeypatch, capsys):
        root, wt = _mk_linked_worktree(tmp_path)
        (root / ".git" / "worktrees" / "wt1" / "gitdir").write_text(
            f"{wt}/.git\nsecond line\n"
        )
        _plant_dangerous_config(wt)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_oversized(self, tmp_path, monkeypatch, capsys):
        from core.security._trust_common import GIT_LINK_MAX_BYTES
        root, wt = _mk_linked_worktree(tmp_path)
        pad = "/" + "a" * GIT_LINK_MAX_BYTES
        (root / ".git" / "worktrees" / "wt1" / "gitdir").write_text(
            f"{pad}/.git\n"
        )
        _plant_dangerous_config(wt)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

    def test_registry_gitdir_unreadable(self, tmp_path, monkeypatch, capsys):
        if os.geteuid() == 0:
            pytest.skip("root ignores file mode bits")
        root, wt = _mk_linked_worktree(tmp_path)
        gitdir = root / ".git" / "worktrees" / "wt1" / "gitdir"
        gitdir.chmod(0)
        _plant_dangerous_config(wt)
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
        _plant_dangerous_config(wt)
        _pin_raptor_dir(monkeypatch, root)
        self._assert_scanned(wt, capsys)

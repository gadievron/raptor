"""Swap-window regression for the worktree self-recognition root gate.

``core.security._trust_common.is_registered_worktree_of_self`` must
observe the registered worktree root ONCE, fd-bound: type, ownership,
and the identity matched against the vetted target all come from the
fstat of a single ``O_NOFOLLOW | O_DIRECTORY`` open. The pre-fix shape
lstat-gated the path and then ``resolve()``d it separately — a symlink
swapped in between the two walks was followed, equating a hostile
target with the registered root; the hostile side completes the
back-link half on its own (an operator-cloned repo's files carry the
operator's uid), so recognition as self skipped the cc/codeql config
scans entirely.

The same discipline covers the TARGET side: the vetted target is
opened once (O_NOFOLLOW | O_DIRECTORY, held for the whole walk), its
fstat is the identity candidates are matched against, the back-link is
read RELATIVE to that fd, and on top of the inode match the registered
path's resolved spelling must equal the target spelling (conjunctive,
refuse-only) — so a target spelling re-aimed mid-walk can substitute
neither the identity nor the trust evidence, and the self verdict
never attaches to an alias spelling a consumer would act on after the
gate returns.

The window tests interpose the swap at EVERY observation seam a shape
of the implementation could reach first — ``os.lstat``/``os.open`` on
the root, ``os.stat``/``os.open`` on the target, the first ``.git``
observation — fired immediately after the gate's first observation,
the deterministic equivalent of winning the race. Both directions:

  * swap raced in at an observation point → NOT self (the fd-bound
    identity/evidence cannot be re-aimed; on the two-walk shapes these
    tests red);
  * the legitimate registered worktree stays self through the
    fd-bound observation path.

Fixtures hand-build the registry files (no git binary), same shapes as
``test_cc_trust_self_worktree.py``.
"""

from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path

import pytest

from core.security import _trust_common
from core.security._trust_common import is_registered_worktree_of_self
from core.testing.module_bindings import patch_module_attribute


def _mk_linked_worktree(base: Path, name: str = "wt1") -> tuple[Path, Path, Path]:
    """Fake RAPTOR root plus one registered linked worktree with a
    correct bidirectional link. Returns
    ``(fake_raptor_root, worktree_root, registry_entry)``."""
    root = base / "raptor"
    entry = root / ".git" / "worktrees" / name
    entry.mkdir(parents=True)
    wt = base / name
    wt.mkdir()
    (entry / "gitdir").write_text(f"{wt}/.git\n")
    (wt / ".git").write_text(f"gitdir: {entry}\n")
    return root, wt, entry


def _mk_hostile(base: Path, entry: Path) -> Path:
    """A hostile target with a byte-correct forged back-link naming
    the registry entry — everything the target side can author alone
    (its files carry the operator's own uid after a clone/extract)."""
    hostile = base / "hostile"
    hostile.mkdir()
    (hostile / ".git").write_text(f"gitdir: {entry}\n")
    return hostile


def _arm_swap_after_first_root_observation(
    monkeypatch: pytest.MonkeyPatch, wt: Path, hostile: Path, base: Path,
) -> dict[str, bool]:
    """Interpose the root swap (rename the real root aside, plant a
    symlink to the hostile target) immediately after the gate's FIRST
    observation of the root — through ``os.lstat`` (the pre-fix seam)
    or ``os.open`` (the fd-bound seam), whichever the implementation
    reaches first."""
    wt_abs = wt.resolve()
    state = {"swapped": False}

    def _swap() -> None:
        state["swapped"] = True
        os.rename(wt_abs, base / "aside")
        os.symlink(hostile.resolve(), wt_abs)

    def _is_root(path: object) -> bool:
        try:
            return Path(os.fsdecode(path)) == wt_abs
        except TypeError:
            return False

    real_lstat = os.lstat
    real_open = os.open

    def fake_lstat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.lstat
        st = real_lstat(path, *args, **kwargs)
        if not state["swapped"] and _is_root(path):
            _swap()
        return st

    def fake_open(path, flags, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.open
        fd = real_open(path, flags, *args, **kwargs)
        if not state["swapped"] and _is_root(path):
            _swap()
        return fd

    patch_module_attribute(monkeypatch, _trust_common, "os", "lstat", fake_lstat)
    patch_module_attribute(monkeypatch, _trust_common, "os", "open", fake_open)
    return state


class TestRootSwapWindow:
    def test_swap_after_root_observation_is_not_self(
        self, tmp_path, monkeypatch,
    ):
        """THE WINDOW: the registered root swapped for a symlink to
        the hostile target immediately after the gate's observation of
        it. The verdict must stay NOT self — recognition bound to the
        observed inode, never to a re-walked path."""
        root, wt, entry = _mk_linked_worktree(tmp_path)
        hostile = _mk_hostile(tmp_path, entry)
        state = _arm_swap_after_first_root_observation(
            monkeypatch, wt, hostile, tmp_path)
        verdict = is_registered_worktree_of_self(
            hostile.resolve(), root.resolve())
        assert state["swapped"], (
            "probe wiring: the gate never observed the registered root"
        )
        assert verdict is False, (
            "swap window: the gate recognised a HOSTILE target as a "
            "registered worktree of self after the root was swapped "
            "for a symlink at its observation point"
        )

    def test_symlink_planted_before_any_observation_is_not_self(
        self, tmp_path,
    ):
        """At rest (no race needed): a symlink at the registered path
        is refused by the O_NOFOLLOW open — not a candidate."""
        root, wt, entry = _mk_linked_worktree(tmp_path)
        hostile = _mk_hostile(tmp_path, entry)
        os.rename(wt, tmp_path / "aside")
        os.symlink(hostile.resolve(), wt)
        assert is_registered_worktree_of_self(
            hostile.resolve(), root.resolve()) is False

    def test_fifo_at_registered_path_refused_without_hanging(
        self, tmp_path,
    ):
        """A FIFO planted at a vacated registered path must refuse
        (ENOTDIR / O_NONBLOCK), never block the gate's open."""
        root, wt, entry = _mk_linked_worktree(tmp_path)
        hostile = _mk_hostile(tmp_path, entry)
        (wt / ".git").unlink()
        wt.rmdir()
        os.mkfifo(wt)
        assert is_registered_worktree_of_self(
            hostile.resolve(), root.resolve()) is False
        assert stat_module.S_ISFIFO(os.lstat(wt).st_mode)

    def test_legitimate_worktree_still_self_through_fd_observation(
        self, tmp_path,
    ):
        """Direction two: the genuine registered worktree keeps its
        self verdict through the fd-bound observation path."""
        root, wt, _entry = _mk_linked_worktree(tmp_path)
        assert is_registered_worktree_of_self(
            wt.resolve(), root.resolve()) is True

    def test_vanished_target_fails_closed(self, tmp_path):
        """A target that cannot be observed (vanished between the
        caller's resolve and the gate) is never self."""
        root, _wt, _entry = _mk_linked_worktree(tmp_path)
        assert is_registered_worktree_of_self(
            tmp_path / "nonexistent", root.resolve()) is False


class TestTargetSwapWindow:
    """The TARGET-side mirror of the root swap: the gate must observe
    the vetted target once, fd-bound, and read the back-link through
    that fd — a stat-then-re-walk pair on the target leaves the same
    window the root fix closed, just on the other side of the
    bidirectional check."""

    def test_target_swap_after_identity_observation_is_not_self(
        self, tmp_path, monkeypatch,
    ):
        """THE TARGET WINDOW: the gate is aimed at a lure spelling
        that denotes the REAL registered worktree at observation time
        (renamed in); immediately after the gate's first observation
        of the lure, the real worktree is renamed back to its
        registered path and a hostile directory with a byte-correct
        forged back-link is planted at the lure. On a
        stat-then-re-walk shape the root and identity checks pass
        against the real worktree while the back-link is read from the
        hostile plant — minting self for a spelling the registry never
        named. The verdict must stay NOT self."""
        root, wt, entry = _mk_linked_worktree(tmp_path)
        hostile = _mk_hostile(tmp_path, entry)
        wt_abs = wt.resolve()
        lure_abs = tmp_path.resolve() / "lure"
        os.rename(wt_abs, lure_abs)
        state = {"swapped": False}

        def _swap() -> None:
            state["swapped"] = True
            os.rename(lure_abs, wt_abs)
            os.rename(hostile.resolve(), lure_abs)

        def _is_lure(path: object) -> bool:
            try:
                return Path(os.fsdecode(path)) == lure_abs
            except TypeError:
                return False

        real_stat = os.stat
        real_open = os.open

        def fake_stat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.stat
            st = real_stat(path, *args, **kwargs)
            if not state["swapped"] and _is_lure(path):
                _swap()
            return st

        def fake_open(path, flags, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.open
            fd = real_open(path, flags, *args, **kwargs)
            if not state["swapped"] and _is_lure(path):
                _swap()
            return fd

        patch_module_attribute(monkeypatch, _trust_common, "os", "stat", fake_stat)
        patch_module_attribute(monkeypatch, _trust_common, "os", "open", fake_open)
        verdict = is_registered_worktree_of_self(lure_abs, root.resolve())
        assert state["swapped"], (
            "probe wiring: the gate never observed the target"
        )
        assert verdict is False, (
            "target swap window: the gate minted a self verdict for a "
            "lure spelling after the real worktree was swapped out "
            "behind its first observation of the target"
        )

    def test_symlink_spelled_target_is_not_self(self, tmp_path):
        """A symlink spelling handed to the gate unresolved must not
        be recognised: the gate's contract says callers pass resolved
        paths, and the O_NOFOLLOW target open keeps it robust when one
        does not — a self verdict minted for a re-aimable spelling
        would be consumed against whatever that spelling denotes after
        the gate returns."""
        root, wt, _entry = _mk_linked_worktree(tmp_path)
        link = tmp_path / "link"
        link.symlink_to(wt.resolve())
        assert is_registered_worktree_of_self(link, root.resolve()) is False

    def test_backlink_bytes_bound_to_target_fd(
        self, tmp_path, monkeypatch,
    ):
        """The back-link bytes must come through the held target fd:
        here the real worktree's own back-link names the WRONG
        registry entry (legitimately not self), and the target
        directory is swapped for a hostile one carrying a
        byte-correct forged back-link immediately after the gate's
        first observation of ``.git``. A path re-walk reads the forged
        bytes and mints self; the fd-anchored read sees the real
        file's bytes and refuses."""
        root, wt, entry = _mk_linked_worktree(tmp_path)
        (wt / ".git").write_text(
            f"gitdir: {root}/.git/worktrees/other\n"
        )
        hostile = _mk_hostile(tmp_path, entry)
        wt_abs = wt.resolve()
        state = {"swapped": False}

        def _swap() -> None:
            state["swapped"] = True
            os.rename(wt_abs, tmp_path / "aside")
            os.rename(hostile.resolve(), wt_abs)

        def _is_dotgit(path: object, kwargs: dict) -> bool:
            try:
                spelled = os.fsdecode(path)
            except TypeError:
                return False
            if spelled == str(wt_abs / ".git"):
                return True
            return spelled == ".git" and kwargs.get("dir_fd") is not None

        real_lstat = os.lstat

        def fake_lstat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.lstat
            st = real_lstat(path, *args, **kwargs)
            if not state["swapped"] and _is_dotgit(path, kwargs):
                _swap()
            return st

        patch_module_attribute(monkeypatch, _trust_common, "os", "lstat", fake_lstat)
        verdict = is_registered_worktree_of_self(wt_abs, root.resolve())
        assert state["swapped"], (
            "probe wiring: the gate never observed the target's .git"
        )
        assert verdict is False, (
            "back-link window: the gate consumed forged back-link "
            "bytes from a directory swapped in after the target's "
            ".git was first observed"
        )

    def test_relative_backlink_walked_from_target_fd(
        self, tmp_path, monkeypatch,
    ):
        """A RELATIVE back-link must be walked from the held target
        fd, never resolved through the target spelling: the genuine
        relative-back-link worktree is renamed to a DIFFERENT depth
        and the spelling re-aimed at an attacker staging directory
        whose ``..`` chain leads straight back to the real registry
        entry — a spelling re-walk follows the attacker-chosen chain
        and mints self, while the fd-anchored walk sees the moved
        directory's own view (the ``..`` now leads elsewhere) and
        fails closed."""
        root, wt, entry = _mk_linked_worktree(tmp_path)
        rel = os.path.relpath(entry, wt)
        (wt / ".git").write_text(f"gitdir: {rel}\n")
        staging = tmp_path / "staging"
        staging.mkdir()
        deep = tmp_path / "deep"
        deep.mkdir()
        wt_abs = wt.resolve()
        state = {"swapped": False}

        def _swap() -> None:
            state["swapped"] = True
            os.rename(wt_abs, deep / "aside")
            os.symlink(staging.resolve(), wt_abs)

        def _is_dotgit(path: object, kwargs: dict) -> bool:
            try:
                spelled = os.fsdecode(path)
            except TypeError:
                return False
            if spelled == str(wt_abs / ".git"):
                return True
            return spelled == ".git" and kwargs.get("dir_fd") is not None

        real_lstat = os.lstat

        def fake_lstat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.lstat
            st = real_lstat(path, *args, **kwargs)
            if not state["swapped"] and _is_dotgit(path, kwargs):
                _swap()
            return st

        patch_module_attribute(monkeypatch, _trust_common, "os", "lstat", fake_lstat)
        verdict = is_registered_worktree_of_self(wt_abs, root.resolve())
        assert state["swapped"], (
            "probe wiring: the gate never observed the target's .git"
        )
        assert verdict is False, (
            "relative back-link window: the back-link's relative path "
            "was resolved through the re-aimed target spelling "
            "instead of being walked from the held target fd"
        )


class TestPerCandidateContainment:
    def test_root_fstat_error_skips_only_that_candidate(
        self, tmp_path, monkeypatch,
    ):
        """An fstat surprise on one candidate's root fd is a
        PER-CANDIDATE reject, never a registry-wide abort (same
        doctrine as the registry-entry anchor lstat): with candidate
        #1's root fstat raising and candidate #2 a legitimate
        worktree, #2 must still be self — and #1's fd must be closed
        on the error path."""
        root, wt, _entry = _mk_linked_worktree(tmp_path)
        decoy = tmp_path / "decoy"
        decoy.mkdir()
        bad_entry = root / ".git" / "worktrees" / "aa-bad"
        bad_entry.mkdir()
        (bad_entry / "gitdir").write_text(f"{decoy}/.git\n")
        live_decoy_fds: set[int] = set()
        opened = 0
        real_open = os.open
        real_fstat = os.fstat
        real_close = os.close

        def fake_open(path, flags, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.open
            nonlocal opened
            fd = real_open(path, flags, *args, **kwargs)
            try:
                if Path(os.fsdecode(path)) == decoy:
                    live_decoy_fds.add(fd)
                    opened += 1
            except TypeError:
                pass
            return fd

        def fake_fstat(fd: int) -> os.stat_result:
            if fd in live_decoy_fds:
                raise OSError(5, "Input/output error")
            return real_fstat(fd)

        def fake_close(fd: int) -> None:
            # fd numbers are reused after close: drop the decoy
            # marking so the raise stays pinned to the decoy's OPEN fd.
            live_decoy_fds.discard(fd)
            real_close(fd)

        patch_module_attribute(monkeypatch, _trust_common, "os", "open", fake_open)
        patch_module_attribute(monkeypatch, _trust_common, "os", "fstat", fake_fstat)
        patch_module_attribute(monkeypatch, _trust_common, "os", "close", fake_close)
        assert is_registered_worktree_of_self(
            wt.resolve(), root.resolve()) is True
        assert opened, (
            "probe wiring: the gate never opened the decoy candidate"
        )
        assert not live_decoy_fds, (
            "fd leak: the decoy candidate's root fd was not closed on "
            "the fstat error path"
        )

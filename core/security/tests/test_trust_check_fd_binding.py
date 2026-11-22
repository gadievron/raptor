"""Held-fd protocol for the consumer trust checks (cc + codeql).

``check_repo_claude_trust`` / ``check_repo_codeql_trust`` release a
verdict KEYED TO THE TARGET SPELLING — consumers dispatch against that
spelling after the check returns. The protocol under test:

  * one observation fd is opened on the resolved target and held for
    the whole check (``_trust_common.open_supplied_target``);
  * every piece of evidence binds to it — the cc config state is read
    ``dir_fd``-relative to the held fd, and self-recognition BORROWS
    the fd (``is_registered_worktree_of_self(..., target_fd=)``) so the
    trusted-self verdict and the evidence share one inode;
  * a REFUSE-ONLY identity bracket
    (``_trust_common.supplied_target_diverged``) closes the check: the
    spelling is lstat'ed once at the end and must still denote the held
    inode, else the verdict is refusal — a clean verdict never attaches
    to a directory the evidence did not come from;
  * the self-skip is evaluated per call in the check function, never
    inside the ``lru_cache``'d content scan — a registry entry pruned
    mid-process is honoured on the next check instead of leaving a
    trusted verdict cached for that (path, config-bytes) pair;
  * platforms whose ``os`` lacks ``dir_fd`` support fail CLOSED
    (``NotImplementedError`` → every candidate unreadable → blocking),
    never fall back to path re-walks.

Swap tests interpose at the module os seams
(``core.testing.module_bindings.patch_module_attribute``) immediately
after the check's FIRST observation of the target — the deterministic
equivalent of winning the race. Registry fixtures are hand-built (no
git binary), same shapes as ``test_trust_worktree_root_swap.py``.
"""

from __future__ import annotations

import json
import os
import shutil
import stat as stat_module
from functools import lru_cache
from pathlib import Path

import pytest

from core.security import _trust_common
from core.security import cc_trust as cc
from core.security import codeql_trust as codeql
from core.security._trust_common import is_registered_worktree_of_self
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state

_DANGEROUS_SETTINGS = json.dumps({"apiKeyHelper": "./evil.sh"})
_BENIGN_SETTINGS = json.dumps({"model": "sonnet"})


@pytest.fixture(autouse=True)
def _fresh_cc_scan_cache(monkeypatch):
    borrowed = cc._scan_cached
    fresh = lru_cache(**borrowed.cache_parameters())(borrowed.__wrapped__)
    with isolated_module_state(cc, {"_scan_cached": fresh}):
        try:
            yield
        finally:
            monkeypatch.undo()


@pytest.fixture(autouse=True)
def _strict_overrides(monkeypatch):
    with isolated_module_state(cc, {"_trust_override_set": False}):
        with isolated_module_state(codeql, {"_trust_override_set": False}):
            try:
                yield
            finally:
                monkeypatch.undo()


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


def _arm_swap_after_target_open(
    monkeypatch, resolved: Path, replacement: Path, base: Path,
) -> dict[str, bool]:
    """Interpose at ``_trust_common.os.open``: immediately after the
    check's held-fd open of the resolved target, rename the observed
    directory aside and rename ``replacement`` in at the spelling."""
    state = {"swapped": False}

    def _swap() -> None:
        state["swapped"] = True
        os.rename(resolved, base / "aside")
        os.rename(replacement, resolved)

    real_open = os.open

    def fake_open(path, flags, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.open
        fd = real_open(path, flags, *args, **kwargs)
        try:
            is_target = Path(os.fsdecode(path)) == resolved
        except TypeError:
            is_target = False
        if not state["swapped"] and is_target:
            _swap()
        return fd

    patch_module_attribute(monkeypatch, _trust_common, "os", "open", fake_open)
    return state


class TestCcDivergenceBracket:
    def test_target_swapped_mid_check_refuses(
        self, tmp_path, monkeypatch, capsys,
    ):
        """THE BRACKET: both directories are individually CLEAN, so a
        spelling-keyed scan of either returns a clean verdict — but the
        spelling stopped denoting the observed inode mid-check. The
        verdict must be refusal: a clean verdict released here would be
        consumed against a directory the check never examined."""
        repo = tmp_path / "repo"
        repo.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        state = _arm_swap_after_target_open(
            monkeypatch, repo.resolve(), other, tmp_path)
        verdict = cc.check_repo_claude_trust(str(repo), trust_override=False)
        assert state["swapped"], (
            "probe wiring: the check never opened the target"
        )
        assert verdict is True, (
            "divergence window: a clean verdict was released for a "
            "spelling that stopped denoting the observed inode "
            "mid-check"
        )
        assert "changed during" in capsys.readouterr().out

    def test_divergence_downgraded_by_trust_override(
        self, tmp_path, monkeypatch, capsys,
    ):
        """The override lane is warn-and-proceed, same as every other
        refusal this gate can emit."""
        repo = tmp_path / "repo"
        repo.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        state = _arm_swap_after_target_open(
            monkeypatch, repo.resolve(), other, tmp_path)
        verdict = cc.check_repo_claude_trust(str(repo), trust_override=True)
        assert state["swapped"]
        assert verdict is False
        out = capsys.readouterr().out
        assert "changed during" in out
        assert "proceeding" in out

    def test_config_evidence_bound_to_held_fd(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Evidence binding: the swapped-in directory carries a
        DANGEROUS settings file. The config bytes must come through the
        held fd (the clean directory observed at open), never from a
        path re-walk of the spelling — the refusal must be the
        divergence bracket, not findings harvested from a directory
        whose identity the verdict was never bound to."""
        repo = tmp_path / "repo"
        (repo / ".claude").mkdir(parents=True)
        (repo / ".claude" / "settings.json").write_text(_BENIGN_SETTINGS)
        hostile = tmp_path / "hostile"
        (hostile / ".claude").mkdir(parents=True)
        (hostile / ".claude" / "settings.json").write_text(
            _DANGEROUS_SETTINGS)
        state = _arm_swap_after_target_open(
            monkeypatch, repo.resolve(), hostile, tmp_path)
        verdict = cc.check_repo_claude_trust(str(repo), trust_override=False)
        assert state["swapped"], (
            "probe wiring: the check never opened the target"
        )
        assert verdict is True
        out = capsys.readouterr().out
        assert "apiKeyHelper" not in out, (
            "evidence re-walk: config bytes were read through the "
            "target SPELLING after the swap instead of through the "
            "held fd"
        )
        assert "changed during" in out


class TestCcConfigDirDiscipline:
    def test_symlinked_claude_dir_blocks_even_with_clean_link_target(
        self, tmp_path, capsys,
    ):
        """``.claude`` as a SYMLINK is a blocking finding in its own
        right, however clean the directory it currently aims at: CC
        itself follows the link at dispatch time, so the link can be
        re-aimed after the check and a verdict earned through it proves
        nothing about what CC will read."""
        repo = tmp_path / "repo"
        repo.mkdir()
        real = tmp_path / "real_claude"
        real.mkdir()
        (real / "settings.json").write_text(_BENIGN_SETTINGS)
        (repo / ".claude").symlink_to(real)
        verdict = cc.check_repo_claude_trust(str(repo), trust_override=False)
        assert verdict is True, (
            "a symlinked .claude config dir was trusted through its "
            "current link target"
        )
        assert "symlink" in capsys.readouterr().out

    def test_file_shaped_claude_entry_stays_absent(self, tmp_path, capsys):
        """Historical pin, kept under the fd walk: a regular FILE named
        ``.claude`` is nothing CC reads as a config dir — absent, no
        findings, clean verdict."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".claude").write_text("not a directory")
        assert cc.check_repo_claude_trust(
            str(repo), trust_override=False) is False
        assert capsys.readouterr().out == ""

    def test_dir_fd_unsupported_platform_fails_closed(
        self, tmp_path, monkeypatch, capsys,
    ):
        """A platform whose ``os.open`` lacks ``dir_fd`` support must
        refuse (every candidate unreadable → blocking), never crash and
        never fall back to path re-walks that would reopen the swap
        windows the held fd closes."""
        repo = tmp_path / "repo"
        repo.mkdir()
        real_open = os.open

        def fake_open(path, flags, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202 — delegating shim, signature mirrors os.open
            if kwargs.get("dir_fd") is not None:
                raise NotImplementedError(
                    "dir_fd unavailable on this platform")
            return real_open(path, flags, *args, **kwargs)

        patch_module_attribute(monkeypatch, cc, "os", "open", fake_open)
        verdict = cc.check_repo_claude_trust(str(repo), trust_override=False)
        assert verdict is True, (
            "dir_fd-less platform: the check waved the target through "
            "instead of failing closed"
        )
        assert "(malformed)" in capsys.readouterr().out


class TestCcSelfSkipPerCall:
    def test_pruned_registry_entry_is_honoured_same_process(
        self, tmp_path, monkeypatch, capsys,
    ):
        """The self-skip must be evaluated per call: a worktree trusted
        on the first check loses the skip the moment its registry entry
        is pruned — with the skip inside the lru-cached content scan, a
        pruned entry left a trusted verdict cached for that
        (path, config-bytes) pair for the rest of the process."""
        root, wt, entry = _mk_linked_worktree(tmp_path)
        (wt / ".claude").mkdir()
        (wt / ".claude" / "settings.json").write_text(_DANGEROUS_SETTINGS)
        monkeypatch.setattr(cc, "_RAPTOR_DIR", (tmp_path / "raptor").resolve())
        assert cc.check_repo_claude_trust(
            str(wt), trust_override=False) is False, (
            "fixture wiring: the registered worktree was not "
            "recognised as self"
        )
        shutil.rmtree(entry)
        verdict = cc.check_repo_claude_trust(str(wt), trust_override=False)
        assert verdict is True, (
            "stale cached trust: the registry entry was pruned but the "
            "same-process re-check reused the self verdict"
        )
        assert "apiKeyHelper" in capsys.readouterr().out


class TestGateBorrowedFd:
    def test_borrowed_fd_recognises_and_is_not_closed(self, tmp_path):
        root, wt, _entry = _mk_linked_worktree(tmp_path)
        fd = os.open(str(wt), os.O_RDONLY)
        try:
            assert is_registered_worktree_of_self(
                wt.resolve(), root.resolve(), target_fd=fd) is True
            # Borrowed, never closed: the caller's later bracket fstat
            # must still observe the same open fd.
            assert stat_module.S_ISDIR(os.fstat(fd).st_mode)
        finally:
            os.close(fd)

    def test_borrowed_fd_identity_is_authoritative(self, tmp_path):
        """The verdict binds to the BORROWED fd's inode, not to a
        re-open of the spelling: with the fd observing a hostile
        directory, the registered spelling (whose directory and
        back-link are genuine) must NOT be recognised — the caller's
        evidence reads are anchored to the hostile inode, and a self
        verdict here would skip scanning it."""
        root, wt, entry = _mk_linked_worktree(tmp_path)
        hostile = tmp_path / "hostile"
        hostile.mkdir()
        (hostile / ".git").write_text(f"gitdir: {entry}\n")
        fd = os.open(str(hostile), os.O_RDONLY)
        try:
            assert is_registered_worktree_of_self(
                wt.resolve(), root.resolve(), target_fd=fd) is False
        finally:
            os.close(fd)

    def test_borrowed_non_directory_fd_refused(self, tmp_path):
        root, wt, _entry = _mk_linked_worktree(tmp_path)
        probe = tmp_path / "probe.txt"
        probe.write_text("x")
        fd = os.open(str(probe), os.O_RDONLY)
        try:
            assert is_registered_worktree_of_self(
                wt.resolve(), root.resolve(), target_fd=fd) is False
            assert os.fstat(fd).st_size == 1  # still open — borrowed
        finally:
            os.close(fd)


class TestCodeqlFdBinding:
    def test_target_swapped_mid_check_refuses(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Same bracket as the cc gate: two individually clean
        directories, spelling re-aimed after the held-fd open → the
        clean verdict must not be released."""
        repo = tmp_path / "repo"
        repo.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        state = _arm_swap_after_target_open(
            monkeypatch, repo.resolve(), other, tmp_path)
        verdict = codeql.check_repo_codeql_trust(
            str(repo), trust_override=False)
        assert state["swapped"], (
            "probe wiring: the check never opened the target"
        )
        assert verdict is True
        assert "changed during" in capsys.readouterr().out

    def test_self_skip_bound_to_held_fd(self, tmp_path, monkeypatch, capsys):
        """The self-skip inside ``_scan_repo`` must key on the HELD
        fd's identity, not on a re-open of the spelling: with the fd
        observing a hostile directory, the registered spelling (real
        worktree, genuine back-link, a pack file planted inside) must
        be SCANNED — an own-open shape re-walks the spelling, sees the
        genuine worktree, and skips the scan entirely."""
        root, wt, _entry = _mk_linked_worktree(tmp_path)
        (wt / "qlpack.yml").write_text(
            "name: planted\nextractor: evil\n")
        hostile = tmp_path / "hostile"
        hostile.mkdir()
        monkeypatch.setattr(
            codeql, "_RAPTOR_DIR", (tmp_path / "raptor").resolve())
        fd = os.open(str(hostile), os.O_RDONLY)
        try:
            scans, any_blocking = codeql._scan_repo(
                str(wt.resolve()), target_fd=fd)
        finally:
            os.close(fd)
        assert any_blocking is True, (
            "self-skip re-opened the spelling: the gate trusted the "
            "directory at the registered path while the held fd — the "
            "identity the verdict is bracketed against — observed a "
            "different inode"
        )
        # Sanity, other direction: the same call with the fd genuinely
        # on the registered worktree is self → skipped.
        fd_wt = os.open(str(wt), os.O_RDONLY)
        try:
            scans, any_blocking = codeql._scan_repo(
                str(wt.resolve()), target_fd=fd_wt)
        finally:
            os.close(fd_wt)
        assert scans == () and any_blocking is False

"""Tests for core.git.dirty — the content-free dirtiness probe.

The load-bearing property: NO git invocation the probe makes may open
a worktree file, because a hostile target repo's clean-filter chain
(``filter.<name>.clean`` — repo-chosen key name, not blanket-
neutralisable) turns any content re-hash into command execution.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from core.git.dirty import probe_worktree_dirt


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        },
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("one\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "first")
    return repo


class TestVerdicts:
    def test_clean_tree_is_false(self, repo):
        dirt = probe_worktree_dirt(repo)
        assert dirt.tracked == ()
        assert dirt.untracked == ()
        assert dirt.dirty is False

    def test_worktree_edit_is_dirty(self, repo):
        (repo / "a.txt").write_text("changed content\n")
        dirt = probe_worktree_dirt(repo)
        assert dirt.tracked == ("a.txt",)
        assert dirt.dirty is True

    def test_staged_only_change_is_dirty(self, repo):
        (repo / "b.txt").write_text("new\n")
        _git(repo, "add", "b.txt")
        dirt = probe_worktree_dirt(repo)
        assert "b.txt" in (dirt.tracked or ())
        assert dirt.dirty is True

    def test_untracked_file_is_dirty(self, repo):
        (repo / "stray.txt").write_text("x\n")
        dirt = probe_worktree_dirt(repo)
        assert dirt.tracked == ()
        assert dirt.untracked == ("stray.txt",)
        assert dirt.dirty is True

    def test_deleted_tracked_file_is_dirty(self, repo):
        (repo / "a.txt").unlink()
        dirt = probe_worktree_dirt(repo)
        assert dirt.tracked == ("a.txt",)
        assert dirt.dirty is True

    def test_non_repo_degrades_to_none(self, tmp_path):
        dirt = probe_worktree_dirt(tmp_path)
        assert dirt.tracked is None
        assert dirt.untracked is None
        assert dirt.dirty is None

    def test_failed_channel_with_no_seen_dirt_never_claims_clean(self):
        from core.git.dirty import WorktreeDirt
        assert WorktreeDirt(tracked=None, untracked=()).dirty is None
        assert WorktreeDirt(tracked=(), untracked=None).dirty is None
        # Dirt seen on the surviving channel is still dirt.
        assert WorktreeDirt(tracked=None, untracked=("x",)).dirty is True


class TestNeverExecutesRepoConfiguredCode:
    def test_hostile_clean_filter_never_runs(self, repo, tmp_path):
        """A committed `* filter=evil` .gitattributes plus
        `filter.evil.clean=<cmd>` in .git/config: any probe that lets
        git re-hash worktree content (status's index refresh, or the
        racily-clean re-verification in `diff-index HEAD` /
        `ls-files -m`) executes that command at the operator's uid.
        The probe must see the dirt without the filter ever running —
        including for entries whose index timestamps make them racy
        (this fixture commits and probes within the racy window)."""
        marker = tmp_path / "filter-executed"
        (repo / ".gitattributes").write_text("* filter=evil\n")
        _git(repo, "add", ".gitattributes")
        _git(repo, "commit", "-q", "-m", "attrs")
        _git(repo, "config", "filter.evil.clean",
             f"touch {marker} && cat")
        (repo / "a.txt").write_text("edited after commit\n")

        dirt = probe_worktree_dirt(repo)

        assert dirt.dirty is True
        assert "a.txt" in (dirt.tracked or ())
        assert not marker.exists(), (
            "the repo-configured clean filter EXECUTED during the "
            "dirty probe — attacker-shipped .git config ran a command "
            "outside any sandbox"
        )


class TestStatComparison:
    def test_touch_without_edit_counts_dirty_not_clean(self, repo):
        """mtime-only churn may over-report dirty (documented
        conservative bias) — it must never under-report."""
        import os
        st = (repo / "a.txt").stat()
        os.utime(repo / "a.txt",
                 ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        dirt = probe_worktree_dirt(repo)
        assert dirt.dirty is True

    def test_unusual_filename_reported_exactly(self, repo):
        """-z listings carry raw path bytes — no quoting layer for a
        space-and-quote name to break the path accounting."""
        name = 'we ird "name.txt'
        (repo / name).write_text("v1\n")
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", "odd name")
        (repo / name).write_text("v2 longer\n")
        dirt = probe_worktree_dirt(repo)
        assert dirt.tracked == (name,)


class TestDebugParseFailsClosed:
    """The ls-files --debug parse must tile the buffer exactly with
    anchored matches: any unrecognised bytes — before, between, or
    after entries — mean an unknown format, and the channel degrades
    to None (unknowable) instead of guessing or rescanning."""

    ENTRY = (
        b"a.txt\0"
        b"  ctime: 1:2\n"
        b"  mtime: 3:4\n"
        b"  dev: 5\tino: 6\n"
        b"  uid: 7\tgid: 8\n"
        b"  size: 4\tflags: 0\n"
    )

    def _probe_with_output(
            self, monkeypatch: pytest.MonkeyPatch, repo: Path,
            out: bytes) -> set[bytes] | None:
        import core.git.dirty as dirty_mod

        def fake_run_git(repo_arg: Path, args: tuple[str, ...],
                         timeout: float) -> bytes:
            if args[:2] == ("ls-files", "--debug"):
                return out
            return b""

        monkeypatch.setattr(dirty_mod, "_run_git", fake_run_git)
        return dirty_mod._stat_dirty_paths(repo, 15)

    def test_wellformed_entry_parses(self, monkeypatch, repo):
        # The entry's cached mtime (second 3 of the epoch) can never
        # match the fixture file's real mtime, so the parsed entry is
        # deterministically stat-dirty.
        got = self._probe_with_output(monkeypatch, repo, self.ENTRY)
        assert got == {b"a.txt"}

    def test_garbage_prefix_fails_closed(self, monkeypatch, repo):
        # NUL-carrying junk cannot fold into a path token (a pure
        # non-NUL prefix would concatenate into the raw path —
        # newlines and all — which is the documented -z path format,
        # not a tiling gap).
        got = self._probe_with_output(
            monkeypatch, repo, b"junk\0not a stat block\n" + self.ENTRY)
        assert got is None

    def test_garbage_between_entries_fails_closed(
            self, monkeypatch, repo):
        got = self._probe_with_output(
            monkeypatch, repo,
            self.ENTRY + b"junk\0not a stat block\n" + self.ENTRY)
        assert got is None

    def test_trailing_bytes_fail_closed(self, monkeypatch, repo):
        got = self._probe_with_output(
            monkeypatch, repo, self.ENTRY + b"  trailing\n")
        assert got is None

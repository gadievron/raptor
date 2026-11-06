"""Argument-injection hardening for the evidence-kit git client.

SHAs and refs reaching ``GitClient`` are harvested from
attacker-authored sources (GH Archive payloads, vendor reports,
archived pages). A "sha" of ``--output=/path`` used to be passed
positionally to ``git show`` and became a file-write primitive. The
client must validate value shapes AND separate positionals with
``--end-of-options``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from contextlib import nullcontext as _path_nullcontext
from unittest.mock import patch as _path_patch
import pytest as _path_pytest

with (_path_patch.object(sys, "path", sys.path.copy())
      if __name__ != "__main__" else _path_nullcontext()):
    sys.path.insert(0, str(Path(__file__).parents[1]))

    from src.clients import git as git_mod
    from src.clients.git import (
        GitClient,
        _validate_ref,
        _validate_revision,
        _validate_sha,
    )

    # =============================================================================
    # VALUE-SHAPE VALIDATION (pure unit)
    # =============================================================================




@_path_pytest.fixture(autouse=True)
def _scoped_helper_import_path(monkeypatch):
    """Keep lazy helper imports available without modifying borrowed path lists."""
    monkeypatch.setattr(sys, "path", sys.path.copy())
    sys.path.insert(0, str(Path(__file__).parents[1]))


class TestShaValidation:
    @pytest.mark.parametrize(
        "good",
        ["a" * 40, "A" * 40, "deadbeef", "1234", "f" * 64],
    )
    def test_hex_accepted(self, good):
        assert _validate_sha(good) == good

    @pytest.mark.parametrize(
        "bad",
        [
            "--output=/tmp/pwn",
            "-p",
            "HEAD",
            "main",
            "abc",              # too short to be an abbreviation
            "a" * 65,
            "deadbeef; rm -rf",
            "",
        ],
    )
    def test_non_hex_rejected(self, bad):
        with pytest.raises(ValueError, match="invalid git object name"):
            _validate_sha(bad)


class TestRefValidation:
    @pytest.mark.parametrize(
        "good",
        ["HEAD", "main", "refs/heads/main", "feature/x-1", "v1.2.3",
         "a" * 40],
    )
    def test_reasonable_refs_accepted(self, good):
        assert _validate_ref(good) == good

    @pytest.mark.parametrize(
        "bad",
        [
            "--exec-path=/tmp",
            "-b",
            "",
            "@",
            "a..b",
            "a/../b",
            "refs/heads/",
            "/refs/heads/main",
            "a//b",
            ".hidden",
            "refs/.hidden/x",
            "branch.lock",
            "a b",
            "a~1",
            "a^",
            "a:b",
            "a?b",
            "a*b",
            "a[b",
            "a\\b",
            "a@{1}",
            "a\x01b",
            "trailing.",
        ],
    )
    def test_hostile_or_malformed_refs_rejected(self, bad):
        with pytest.raises(ValueError, match="invalid git ref"):
            _validate_ref(bad)


class TestRevisionValidation:
    @pytest.mark.parametrize("good", ["HEAD", "main", "a" * 40, "deadbeef"])
    def test_commitish_accepted(self, good):
        assert _validate_revision(good) == good

    @pytest.mark.parametrize("bad", ["--output=/tmp/pwn", "-p", "", "a..b"])
    def test_hostile_rejected(self, bad):
        with pytest.raises(ValueError, match="invalid git revision"):
            _validate_revision(bad)


class TestValidationPrecedesSubprocess:
    def test_option_shaped_sha_never_reaches_git(self, monkeypatch):
        def _boom(*args, **kwargs):  # pragma: no cover - must not run
            raise AssertionError("subprocess.run called for invalid sha")

        monkeypatch.setattr(git_mod.subprocess, "run", _boom)
        client = GitClient(".")
        with pytest.raises(ValueError):
            client.get_commit("--output=/tmp/pwn")
        with pytest.raises(ValueError):
            client.get_commit_files("--output=/tmp/pwn")
        with pytest.raises(ValueError):
            client.cat_file("--textconv")
        with pytest.raises(ValueError):
            client.get_log(ref="--exec-path=/tmp")


# =============================================================================
# REAL-GIT INTEGRATION (hermetic local repo — proves --end-of-options
# is accepted by every command shape the client uses)
# =============================================================================

_needs_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git required",
)


@_needs_git
class TestAgainstRealRepo:
    @pytest.fixture()
    def repo(self, tmp_path: Path) -> Path:
        def _git(*args: str) -> str:
            proc = subprocess.run(
                ["git", "-C", str(tmp_path),
                 "-c", "user.name=Test", "-c", "user.email=test@example.test",
                 *args],
                capture_output=True, text=True, check=True, timeout=30,
            )
            return proc.stdout.strip()

        _git("init", "-q", ".")
        _git("commit", "-q", "--allow-empty", "-m", "initial")
        # Second commit: diff-tree needs a parent to report changes.
        (tmp_path / "f.txt").write_text("hello\n", encoding="utf-8")
        _git("add", "f.txt")
        _git("commit", "-q", "-m", "subject line\n\nbody")
        return tmp_path

    def test_get_commit_round_trip(self, repo: Path):
        client = GitClient(str(repo))
        # Symbolic names stay accepted (existing caller contract).
        assert client.get_commit("HEAD")["author_name"] == "Test"
        head = client.get_log(ref="HEAD", limit=1)[0]["sha"]
        data = client.get_commit(head)
        assert data["sha"] == head
        assert data["author_name"] == "Test"
        assert data["message"].startswith("subject line")

        files = client.get_commit_files(head)
        assert files == [{"status": "added", "filename": "f.txt"}]

        blob = client.cat_file(head)
        assert "subject line" in blob

    def test_output_option_sha_is_refused_and_writes_nothing(
        self, repo: Path, tmp_path: Path,
    ):
        """The original file-write primitive: git show --output=<path>."""
        target = repo / "pwned"
        client = GitClient(str(repo))
        with pytest.raises(ValueError):
            client.get_commit(f"--output={target}")
        assert not target.exists()

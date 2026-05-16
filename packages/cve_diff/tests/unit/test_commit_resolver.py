from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from cve_diff.core.exceptions import IdenticalCommitsError
from cve_diff.diffing.commit_resolver import CommitResolver


class TestStripParent:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("abc123", "abc123"),
            ("abc123^", "abc123"),
            ("abc123^^", "abc123"),
            ("abc123^2", "abc123"),
            ("abc123~3", "abc123"),
        ],
    )
    def test_strip(self, raw: str, expected: str) -> None:
        assert CommitResolver().strip_parent_notation(raw) == expected


class TestIsValidShaFormat:
    @pytest.mark.parametrize("sha", ["abc1234", "0123456789abcdef0123456789abcdef01234567"])
    def test_valid(self, sha: str) -> None:
        assert CommitResolver().is_valid_sha_format(sha) is True

    @pytest.mark.parametrize(
        "sha",
        [None, "", "0", "none", "null", "abc", "abc123; rm -rf /", "gggggg"],
    )
    def test_invalid(self, sha: str | None) -> None:
        assert CommitResolver().is_valid_sha_format(sha) is False


class TestValidateDifferent:
    def test_passes_when_different(self) -> None:
        CommitResolver().validate_different("abc1234", "def5678")

    def test_none_is_allowed(self) -> None:
        CommitResolver().validate_different(None, "abc1234")
        CommitResolver().validate_different("abc1234", None)

    def test_raises_on_same_sha(self) -> None:
        with pytest.raises(IdenticalCommitsError):
            CommitResolver().validate_different("abc1234", "ABC1234")


def _init_tiny_repo(path: Path) -> tuple[str, str]:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True, timeout=15)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "t@t"], check=True
    )
    subprocess.run(["git", "-C", str(path), "config", "user.name", "t"], check=True, timeout=15)
    (path / "a").write_text("v1\n")
    subprocess.run(["git", "-C", str(path), "add", "a"], check=True, timeout=15)
    subprocess.run(
        ["git", "-C", str(path), "commit", "-q", "-m", "first"], check=True
    )
    first = subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()
    (path / "a").write_text("v2\n")
    subprocess.run(
        ["git", "-C", str(path), "commit", "-q", "-am", "second"], check=True
    )
    second = subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()
    return first, second


def test_expand_resolves_abbreviation(tmp_path: Path) -> None:
    first, _second = _init_tiny_repo(tmp_path)
    resolver = CommitResolver()
    expanded = resolver.expand(tmp_path, first[:8])
    assert expanded == first


def test_parent_of(tmp_path: Path) -> None:
    first, second = _init_tiny_repo(tmp_path)
    resolver = CommitResolver()
    assert resolver.parent_of(tmp_path, second) == first


EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def test_parent_of_root_commit_returns_empty_tree(tmp_path: Path) -> None:
    """Root commits have no parent. git's empty-tree SHA lets `diff` treat the
    fix as a full-file add — the correct semantics for CVE-2024-3094-style
    fixes landed as the repository's first commit.
    """
    first, _second = _init_tiny_repo(tmp_path)
    resolver = CommitResolver()
    assert resolver.parent_of(tmp_path, first) == EMPTY_TREE_SHA

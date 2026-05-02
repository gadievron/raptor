from __future__ import annotations

import pytest

from cve_diff.core.models import (
    CommitSha,
    DiffBundle,
    IntroducedMarker,
    PatchTuple,
    RepoRef,
)


class TestPatchTuple:
    def test_happy_path(self) -> None:
        tup = PatchTuple(
            repository_url="https://github.com/curl/curl",
            fix_commit=CommitSha("abcd1234"),
            introduced=CommitSha("deadbeef"),
        )
        assert tup.fix_commit == "abcd1234"

    def test_is_frozen(self) -> None:
        tup = PatchTuple(
            repository_url="https://github.com/curl/curl",
            fix_commit=CommitSha("abcd1234"),
        )
        with pytest.raises(Exception):
            tup.fix_commit = CommitSha("beef")  # type: ignore[misc]

    def test_empty_repo_rejected(self) -> None:
        with pytest.raises(ValueError):
            PatchTuple(repository_url="", fix_commit=CommitSha("abcd1234"))

    def test_empty_fix_rejected(self) -> None:
        with pytest.raises(ValueError):
            PatchTuple(
                repository_url="https://github.com/curl/curl",
                fix_commit=CommitSha(""),
            )

    def test_introduced_optional(self) -> None:
        tup = PatchTuple(
            repository_url="https://github.com/curl/curl",
            fix_commit=CommitSha("abcd1234"),
        )
        assert tup.introduced is None

    def test_introduced_marker_accepted(self) -> None:
        """OSV's version markers live in `introduced` without leaking into `fix_commit`."""
        tup = PatchTuple(
            repository_url="https://github.com/curl/curl",
            fix_commit=CommitSha("abcd1234"),
            introduced=IntroducedMarker("7.69.0"),
        )
        assert tup.introduced == "7.69.0"


class TestRepoRef:
    def test_requires_score(self) -> None:
        RepoRef(
            repository_url="https://github.com/curl/curl",
            fix_commit=CommitSha("abcd1234"),
            introduced=None,
            canonical_score=100,
        )

    def test_rejects_negative_score(self) -> None:
        with pytest.raises(ValueError):
            RepoRef(
                repository_url="https://github.com/curl/curl",
                fix_commit=CommitSha("abcd1234"),
                introduced=None,
                canonical_score=-1,
            )

    def test_requires_fix_commit(self) -> None:
        """Bug #12 guard: no implicit HEAD default."""
        with pytest.raises(ValueError):
            RepoRef(
                repository_url="https://github.com/curl/curl",
                fix_commit=CommitSha(""),
                introduced=None,
                canonical_score=100,
            )


def test_diff_bundle_construction() -> None:
    ref = RepoRef(
        repository_url="https://github.com/curl/curl",
        fix_commit=CommitSha("abcd1234"),
        introduced=None,
        canonical_score=100,
    )
    bundle = DiffBundle(
        cve_id="CVE-2023-38545",
        repo_ref=ref,
        commit_before=CommitSha("deadbeef"),
        commit_after=CommitSha("abcd1234"),
        diff_text="--- a/foo\n+++ b/foo\n",
        files_changed=1,
        bytes_size=22,
    )
    assert bundle.bytes_size == 22

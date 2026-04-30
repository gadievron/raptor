"""
Tests for the thin GitHub REST client. No live network — ``responses`` mocks
every HTTP round-trip.
"""

from __future__ import annotations

import pytest
import responses

from cve_diff.infra import github_client


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Each test starts with no cached state and no GITHUB_TOKEN."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    github_client.reset_for_tests()
    yield
    github_client.reset_for_tests()


class TestGetRepo:
    @responses.activate
    def test_200_returns_dict(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/torvalds/linux",
            json={"fork": False, "stargazers_count": 100000},
            status=200,
        )
        data = github_client.get_repo("torvalds/linux")
        assert data == {"fork": False, "stargazers_count": 100000}

    @responses.activate
    def test_404_returns_none(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/ghost/missing",
            json={"message": "Not Found"},
            status=404,
        )
        assert github_client.get_repo("ghost/missing") is None

    @responses.activate
    def test_403_rate_limited_returns_none(self, capsys) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y",
            json={"message": "API rate limit exceeded"},
            status=403,
        )
        assert github_client.get_repo("x/y") is None
        err = capsys.readouterr().err
        assert "403" in err

    @responses.activate
    def test_429_only_warns_once(self, capsys) -> None:
        responses.add(responses.GET, "https://api.github.com/repos/a/b", status=429)
        responses.add(responses.GET, "https://api.github.com/repos/c/d", status=429)
        github_client.get_repo("a/b")
        github_client.get_repo("c/d")
        err = capsys.readouterr().err
        assert err.count("warn:") == 1

    def test_empty_slug_returns_none(self) -> None:
        assert github_client.get_repo("") is None
        assert github_client.get_repo("no-slash") is None

    @responses.activate
    def test_memoized_one_call_per_slug(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y",
            json={"fork": False},
            status=200,
        )
        github_client.get_repo("x/y")
        github_client.get_repo("x/y")
        github_client.get_repo("x/y")
        assert len(responses.calls) == 1

    @responses.activate
    def test_500_retries_then_gives_up(self) -> None:
        responses.add(responses.GET, "https://api.github.com/repos/x/y", status=500)
        responses.add(responses.GET, "https://api.github.com/repos/x/y", status=500)
        assert github_client.get_repo("x/y") is None
        assert len(responses.calls) == 2

    @responses.activate
    def test_500_then_200_succeeds(self) -> None:
        responses.add(responses.GET, "https://api.github.com/repos/x/y", status=500)
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y",
            json={"fork": True},
            status=200,
        )
        assert github_client.get_repo("x/y") == {"fork": True}


class TestGetLanguages:
    @responses.activate
    def test_200_returns_languages(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/python/cpython/languages",
            json={"Python": 50000000, "C": 30000000},
            status=200,
        )
        data = github_client.get_languages("python/cpython")
        assert data == {"Python": 50000000, "C": 30000000}

    @responses.activate
    def test_404_returns_none(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y/languages",
            status=404,
        )
        assert github_client.get_languages("x/y") is None


class TestAuthHeader:
    @responses.activate
    def test_sends_authorization_when_token_set(self, monkeypatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake_token")
        github_client.reset_for_tests()
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y",
            json={"fork": False},
            status=200,
        )
        github_client.get_repo("x/y")
        sent = responses.calls[0].request.headers.get("Authorization")
        assert sent == "Bearer ghp_fake_token"

    @responses.activate
    def test_no_authorization_header_when_unset(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y",
            json={"fork": False},
            status=200,
        )
        github_client.get_repo("x/y")
        assert "Authorization" not in responses.calls[0].request.headers


class TestCommitExists:
    @responses.activate
    def test_200_returns_true(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/torvalds/linux/commits/abc123",
            json={"sha": "abc123"},
            status=200,
        )
        assert github_client.commit_exists("torvalds/linux", "abc123") is True

    @responses.activate
    def test_404_returns_false(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y/commits/deadbeef",
            json={"message": "Not Found"},
            status=404,
        )
        assert github_client.commit_exists("x/y", "deadbeef") is False

    @responses.activate
    def test_422_returns_false(self) -> None:
        """422 = GH can't parse the SHA as a valid commit ref."""
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y/commits/bogus",
            json={"message": "Invalid"},
            status=422,
        )
        assert github_client.commit_exists("x/y", "bogus") is False

    @responses.activate
    def test_403_rate_limited_returns_none(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y/commits/abc",
            status=403,
        )
        assert github_client.commit_exists("x/y", "abc") is None

    @responses.activate
    def test_memoizes_per_slug_sha_pair(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y/commits/abc",
            json={"sha": "abc"},
            status=200,
        )
        github_client.commit_exists("x/y", "abc")
        github_client.commit_exists("x/y", "abc")
        assert len(responses.calls) == 1

    def test_empty_slug_or_sha_returns_none(self) -> None:
        assert github_client.commit_exists("", "abc") is None
        assert github_client.commit_exists("x/y", "") is None


class TestGetCommitFiles:
    @responses.activate
    def test_200_extracts_filenames(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/curl/curl/commits/abc123",
            json={
                "sha": "abc123",
                "files": [
                    {"filename": "lib/cookie.c", "status": "modified"},
                    {"filename": "lib/cookie.h", "status": "modified"},
                ],
            },
            status=200,
        )
        files = github_client.get_commit_files("curl/curl", "abc123")
        assert files == ["lib/cookie.c", "lib/cookie.h"]

    @responses.activate
    def test_404_returns_none(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y/commits/deadbeef",
            status=404,
        )
        assert github_client.get_commit_files("x/y", "deadbeef") is None

    @responses.activate
    def test_missing_files_key_returns_empty_list(self) -> None:
        """A commit with no file changes (rare but valid) returns []."""
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y/commits/abc",
            json={"sha": "abc"},
            status=200,
        )
        assert github_client.get_commit_files("x/y", "abc") == []

    @responses.activate
    def test_403_returns_none(self) -> None:
        responses.add(
            responses.GET,
            "https://api.github.com/repos/x/y/commits/abc",
            status=403,
        )
        assert github_client.get_commit_files("x/y", "abc") is None

    def test_empty_slug_or_sha_returns_none(self) -> None:
        assert github_client.get_commit_files("", "abc") is None
        assert github_client.get_commit_files("x/y", "") is None


class TestWarnIfTokenMissing:
    def test_prints_once_when_unset(self) -> None:
        calls: list[str] = []
        github_client.warn_if_token_missing(echo=calls.append)
        github_client.warn_if_token_missing(echo=calls.append)
        assert len(calls) == 1
        assert "GITHUB_TOKEN" in calls[0]

    def test_silent_when_set(self, monkeypatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
        github_client.reset_for_tests()
        calls: list[str] = []
        github_client.warn_if_token_missing(echo=calls.append)
        assert calls == []

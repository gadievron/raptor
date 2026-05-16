"""
Tests for the thin GitHub REST client.

No live network — a ``_FakeClient`` stand-in for ``core.http.EgressClient``
records URLs and returns canned responses or raises ``HttpError`` to
exercise the 4xx / 5xx / 429 branches. Pre-rewire these tests used the
``responses`` library to mock ``requests``; with the transport now on
urllib3 (via EgressClient), an EgressClient stub is a closer match to
the call shape and avoids pulling in a transport-specific mock library.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest

from core.http import HttpError

from cve_diff.infra import github_client


class _FakeClient:
    """Records calls and returns sequenced canned responses per URL.

    Each call to ``get_json(url)`` consumes one queued response for that
    URL. A queued ``HttpError`` is raised; a queued ``dict`` is returned.
    Lets us simulate retry sequences (e.g. 500-then-200) by queueing
    multiple responses for the same URL — but note that with EgressClient
    handling retries internally, transient 5xx → success would be one
    ``get_json`` call from the consumer's view, not two. Tests that
    previously asserted retry-call-count are now redundant and dropped.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._queues: dict[str, list[Any]] = {}

    def queue(self, url: str, response: Any) -> None:
        self._queues.setdefault(url, []).append(response)

    def get_json(
        self, url: str,
        timeout: Optional[int] = None,
        *,
        headers: Optional[dict] = None,
        total_timeout: Optional[int] = None,
        retries: Optional[int] = None,
    ) -> Any:
        self.calls.append((url, dict(headers or {})))
        queue = self._queues.get(url)
        if not queue:
            raise HttpError(f"no mock queued for {url}", status=599)
        response = queue.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture
def fake(monkeypatch) -> _FakeClient:
    """Replace ``_client()`` with an in-process fake for the test."""
    f = _FakeClient()
    monkeypatch.setattr(github_client, "_client", lambda: f)
    return f


@pytest.fixture(autouse=True)
def _isolate(monkeypatch) -> None:
    """Each test starts with no cached state and no GITHUB_TOKEN."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    github_client.reset_for_tests()
    yield
    github_client.reset_for_tests()


class TestGetRepo:
    def test_200_returns_dict(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/torvalds/linux",
            {"fork": False, "stargazers_count": 100000},
        )
        data = github_client.get_repo("torvalds/linux")
        assert data == {"fork": False, "stargazers_count": 100000}

    def test_404_returns_none(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/ghost/missing",
            HttpError("Not Found", status=404),
        )
        assert github_client.get_repo("ghost/missing") is None

    def test_403_rate_limited_returns_none(
        self, fake: _FakeClient, capsys,
    ) -> None:
        fake.queue(
            "https://api.github.com/repos/x/y",
            HttpError("API rate limit exceeded", status=403),
        )
        assert github_client.get_repo("x/y") is None
        err = capsys.readouterr().err
        assert "403" in err

    def test_429_only_warns_once(
        self, fake: _FakeClient, capsys,
    ) -> None:
        fake.queue(
            "https://api.github.com/repos/a/b",
            HttpError("rate limited", status=429),
        )
        fake.queue(
            "https://api.github.com/repos/c/d",
            HttpError("rate limited", status=429),
        )
        github_client.get_repo("a/b")
        github_client.get_repo("c/d")
        err = capsys.readouterr().err
        assert err.count("warn:") == 1

    def test_empty_slug_returns_none(self, fake: _FakeClient) -> None:
        # Reach this without queuing a response — get_repo should
        # short-circuit before any transport call.
        assert github_client.get_repo("") is None
        assert github_client.get_repo("no-slash") is None
        assert fake.calls == []

    def test_memoized_one_call_per_slug(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/x/y", {"fork": False},
        )
        github_client.get_repo("x/y")
        github_client.get_repo("x/y")
        github_client.get_repo("x/y")
        assert len(fake.calls) == 1

    def test_500_returns_none(self, fake: _FakeClient) -> None:
        """5xx surfaces as None after EgressClient's internal retries
        exhaust. Pre-rewire two tests here counted call-attempts; the
        retry semantics are now EgressClient-internal, covered by
        ``core/http/tests/test_urllib_backend.py``:
        ``TestErrors::test_500_retries_then_raises`` (gives up after
        the schedule) and ``test_429_retries_with_backoff`` (recovers
        after transient errors)."""
        fake.queue(
            "https://api.github.com/repos/x/y",
            HttpError("server error", status=500),
        )
        assert github_client.get_repo("x/y") is None


class TestGetLanguages:
    def test_200_returns_languages(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/python/cpython/languages",
            {"Python": 50000000, "C": 30000000},
        )
        data = github_client.get_languages("python/cpython")
        assert data == {"Python": 50000000, "C": 30000000}

    def test_404_returns_none(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/x/y/languages",
            HttpError("Not Found", status=404),
        )
        assert github_client.get_languages("x/y") is None


class TestAuthHeader:
    def test_sends_authorization_when_token_set(
        self, fake: _FakeClient, monkeypatch,
    ) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake_token")
        github_client.reset_for_tests()
        fake.queue(
            "https://api.github.com/repos/x/y", {"fork": False},
        )
        github_client.get_repo("x/y")
        sent = fake.calls[0][1].get("Authorization")
        assert sent == "Bearer ghp_fake_token"

    def test_no_authorization_header_when_unset(
        self, fake: _FakeClient,
    ) -> None:
        fake.queue(
            "https://api.github.com/repos/x/y", {"fork": False},
        )
        github_client.get_repo("x/y")
        assert "Authorization" not in fake.calls[0][1]


class TestCommitExists:
    def test_200_returns_true(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/torvalds/linux/commits/abc123",
            {"sha": "abc123"},
        )
        assert github_client.commit_exists("torvalds/linux", "abc123") is True

    def test_404_returns_false(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/x/y/commits/deadbeef",
            HttpError("Not Found", status=404),
        )
        assert github_client.commit_exists("x/y", "deadbeef") is False

    def test_422_returns_false(self, fake: _FakeClient) -> None:
        """422 = GH can't parse the SHA as a valid commit ref."""
        fake.queue(
            "https://api.github.com/repos/x/y/commits/bogus",
            HttpError("Invalid", status=422),
        )
        assert github_client.commit_exists("x/y", "bogus") is False

    def test_403_rate_limited_returns_none(
        self, fake: _FakeClient,
    ) -> None:
        fake.queue(
            "https://api.github.com/repos/x/y/commits/abc",
            HttpError("rate limited", status=403),
        )
        assert github_client.commit_exists("x/y", "abc") is None

    def test_memoizes_per_slug_sha_pair(
        self, fake: _FakeClient,
    ) -> None:
        fake.queue(
            "https://api.github.com/repos/x/y/commits/abc",
            {"sha": "abc"},
        )
        github_client.commit_exists("x/y", "abc")
        github_client.commit_exists("x/y", "abc")
        assert len(fake.calls) == 1

    def test_empty_slug_or_sha_returns_none(
        self, fake: _FakeClient,
    ) -> None:
        assert github_client.commit_exists("", "abc") is None
        assert github_client.commit_exists("x/y", "") is None
        assert fake.calls == []


class TestGetCommitFiles:
    def test_200_extracts_filenames(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/curl/curl/commits/abc123",
            {
                "sha": "abc123",
                "files": [
                    {"filename": "lib/cookie.c", "status": "modified"},
                    {"filename": "lib/cookie.h", "status": "modified"},
                ],
            },
        )
        files = github_client.get_commit_files("curl/curl", "abc123")
        assert files == ["lib/cookie.c", "lib/cookie.h"]

    def test_404_returns_none(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/x/y/commits/deadbeef",
            HttpError("Not Found", status=404),
        )
        assert github_client.get_commit_files("x/y", "deadbeef") is None

    def test_missing_files_key_returns_empty_list(
        self, fake: _FakeClient,
    ) -> None:
        """A commit with no file changes (rare but valid) returns []."""
        fake.queue(
            "https://api.github.com/repos/x/y/commits/abc",
            {"sha": "abc"},
        )
        assert github_client.get_commit_files("x/y", "abc") == []

    def test_403_returns_none(self, fake: _FakeClient) -> None:
        fake.queue(
            "https://api.github.com/repos/x/y/commits/abc",
            HttpError("rate limited", status=403),
        )
        assert github_client.get_commit_files("x/y", "abc") is None

    def test_empty_slug_or_sha_returns_none(
        self, fake: _FakeClient,
    ) -> None:
        assert github_client.get_commit_files("", "abc") is None
        assert github_client.get_commit_files("x/y", "") is None
        assert fake.calls == []


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

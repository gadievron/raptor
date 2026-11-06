"""Every kit HTTP request must carry a timeout.

A ``session.get`` without ``timeout=`` waits forever in requests; a
stalled connection then hangs the collector (and the investigator agent
driving it) indefinitely, and the retry adapter never engages because
the first attempt never returns.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from contextlib import nullcontext as _path_nullcontext
from unittest.mock import patch as _path_patch
import pytest as _path_pytest

with (_path_patch.object(sys, "path", sys.path.copy())
      if __name__ != "__main__" else _path_nullcontext()):
    sys.path.insert(0, str(Path(__file__).parents[1]))

    from src.clients.github import GitHubClient
    from src.clients.wayback import WaybackClient




@_path_pytest.fixture(autouse=True)
def _scoped_helper_import_path(monkeypatch):
    """Keep lazy helper imports available without modifying borrowed path lists."""
    monkeypatch.setattr(sys, "path", sys.path.copy())
    sys.path.insert(0, str(Path(__file__).parents[1]))


class _Response:
    status_code = 200
    text = "body"

    def __init__(self, url: str = "https://api.github.com/stub") -> None:
        # The GitHub client verifies the response's final URL stayed
        # on the canonical API host, so the stub must model it.
        self.url = url

    @staticmethod
    def raise_for_status() -> None:
        return None

    @staticmethod
    def json():
        return []


class _RecordingSession:
    """Stub session that records the kwargs of every get()."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def get(self, url, **kwargs):
        self.calls.append(kwargs)
        return _Response(url)


_GITHUB_CALLS = [
    ("get_commit", ("o", "r", "a" * 40)),
    ("get_issue", ("o", "r", 1)),
    ("get_pull_request", ("o", "r", 1)),
    ("get_file", ("o", "r", "p")),
    ("get_branch", ("o", "r", "main")),
    ("get_tag", ("o", "r", "v1")),
    ("get_release", ("o", "r", "v1")),
    ("get_forks", ("o", "r")),
    ("get_repo", ("o", "r")),
]


@pytest.mark.parametrize("method,args", _GITHUB_CALLS, ids=[m for m, _ in _GITHUB_CALLS])
def test_github_client_requests_carry_timeout(method, args):
    client = GitHubClient()
    session = _RecordingSession()
    client._session = session
    getattr(client, method)(*args)
    assert session.calls, "no request recorded"
    for kwargs in session.calls:
        assert kwargs.get("timeout"), f"{method} sent a request without a timeout"


@pytest.mark.parametrize(
    "method,args",
    [("search_cdx", ("https://example.com",)), ("get_snapshot", ("https://example.com", "20240101"))],
)
def test_wayback_client_requests_carry_timeout(method, args):
    client = WaybackClient()
    session = _RecordingSession()
    client._session = session
    getattr(client, method)(*args)
    assert session.calls, "no request recorded"
    for kwargs in session.calls:
        assert kwargs.get("timeout"), f"{method} sent a request without a timeout"

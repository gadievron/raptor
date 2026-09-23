"""
GitHub API Client (Unauthenticated).
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlsplit

from ..schema.common import EvidenceSource

# Per-request timeout. Without one, requests waits forever and a stalled
# connection hangs the collector (the retry adapter never engages because
# the first attempt never returns). Matches the verifier's URL-fetch posture.
_TIMEOUT_S = 30

# The only authority this client may talk to. Verification legs built
# from observation fields must resolve against the CANONICAL source
# identity — a URL that ends up addressing any other host (path
# injection, userinfo tricks, off-site redirects) is a forged
# verification, not a network preference.
_API_HOST = "api.github.com"


def _segment(value: str, what: str) -> str:
    """Canonicalise one URL path segment from a typed component.

    Observation fields (owner, repo, sha, ref, path components) are
    attacker-influenced free text; string-joining them into a URL let a
    value like ``../../../attacker/arepo/contents/f.txt`` re-address the
    request to a different repository (requests resolves dot-segments
    client-side, so the server never even sees them). Every segment is
    therefore validated (non-empty, no dot-segments, no control bytes)
    and percent-encoded with nothing exempt — ``/``, ``?``, ``#``,
    ``@`` and non-ASCII all become data, never URL structure.
    """
    if not value:
        raise ValueError(f"empty {what} in GitHub API path")
    if value in (".", ".."):
        raise ValueError(f"dot-segment {what} in GitHub API path: {value!r}")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"control character in {what}: {value!r}")
    return quote(value, safe="")


def _multi_segment(value: str, what: str) -> str:
    """Canonicalise a slash-separated path (file paths, hierarchical
    branch/tag names): literal ``/`` separates components, every
    component individually passes :func:`_segment` (so ``..``, empty
    components, and absolute paths fail closed)."""
    if not value:
        raise ValueError(f"empty {what} in GitHub API path")
    if value.startswith("/"):
        raise ValueError(f"absolute {what} in GitHub API path: {value!r}")
    return "/".join(_segment(part, f"{what} component")
                    for part in value.split("/"))


class GitHubClient:
    """Client for GitHub REST API (unauthenticated OSINT).

    Rate limits: 60 requests/hour unauthenticated.
    All public repository data is accessible without authentication.
    """

    BASE_URL = f"https://{_API_HOST}"

    def __init__(self) -> None:
        self._session: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GITHUB

    def _get_session(self) -> Any:
        if self._session is None:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            self._session = requests.Session()
            self._session.headers.update({"Accept": "application/vnd.github+json"})

            # Add retry logic
            retries = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET"]
            )
            adapter = HTTPAdapter(max_retries=retries)
            self._session.mount("https://", adapter)
            self._session.mount("http://", adapter)

        return self._session

    def _url(self, *segments: str) -> str:
        """Assemble an API URL from already-canonicalised segments and
        re-check the resulting authority (belt-and-braces: encoding
        makes an authority change structurally impossible, and this
        check keeps it that way under future edits)."""
        url = f"{self.BASE_URL}/{'/'.join(segments)}"
        split = urlsplit(url)
        if split.hostname != _API_HOST or "@" in split.netloc:
            raise ValueError(
                f"constructed GitHub API URL escaped the canonical host: {url!r}")
        return url

    def _get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        """GET *url* and return the decoded JSON body, refusing any
        response whose final URL (after redirects) left the canonical
        API host — a redirect off-host would let the "verification"
        compare against content the redirect target chose."""
        session = self._get_session()
        resp = session.get(url, params=params, timeout=_TIMEOUT_S)
        final_host = urlsplit(resp.url).hostname
        if final_host != _API_HOST:
            raise ValueError(
                "GitHub API response resolved outside the canonical host: "
                f"{resp.url!r}")
        resp.raise_for_status()
        return resp.json()

    def get_commit(self, owner: str, repo: str, sha: str) -> dict[str, Any]:
        """Fetch commit from GitHub API."""
        url = self._url("repos", _segment(owner, "owner"),
                        _segment(repo, "repo"), "commits",
                        _segment(sha, "sha"))
        return self._get_json(url)

    def get_issue(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch issue from GitHub API."""
        url = self._url("repos", _segment(owner, "owner"),
                        _segment(repo, "repo"), "issues",
                        _segment(str(int(number)), "issue number"))
        return self._get_json(url)

    def get_pull_request(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch PR from GitHub API."""
        url = self._url("repos", _segment(owner, "owner"),
                        _segment(repo, "repo"), "pulls",
                        _segment(str(int(number)), "PR number"))
        return self._get_json(url)

    def get_file(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> dict[str, Any]:
        """Fetch file content from GitHub API."""
        url = self._url("repos", _segment(owner, "owner"),
                        _segment(repo, "repo"), "contents",
                        _multi_segment(path, "file path"))
        params = {"ref": ref}
        return self._get_json(url, params=params)

    def get_branch(self, owner: str, repo: str, branch: str) -> dict[str, Any]:
        """Fetch branch from GitHub API."""
        url = self._url("repos", _segment(owner, "owner"),
                        _segment(repo, "repo"), "branches",
                        _multi_segment(branch, "branch name"))
        return self._get_json(url)

    def get_tag(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch tag from GitHub API."""
        url = self._url("repos", _segment(owner, "owner"),
                        _segment(repo, "repo"), "git", "refs", "tags",
                        _multi_segment(tag, "tag name"))
        return self._get_json(url)

    def get_release(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch release by tag from GitHub API."""
        url = self._url("repos", _segment(owner, "owner"),
                        _segment(repo, "repo"), "releases", "tags",
                        _multi_segment(tag, "tag name"))
        return self._get_json(url)

    def get_forks(self, owner: str, repo: str, per_page: int = 100) -> list[dict[str, Any]]:
        """Fetch forks from GitHub API."""
        url = self._url("repos", _segment(owner, "owner"),
                        _segment(repo, "repo"), "forks")
        params = {"per_page": per_page}
        return self._get_json(url, params=params)

    def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        """Fetch repository info from GitHub API."""
        url = self._url("repos", _segment(owner, "owner"),
                        _segment(repo, "repo"))
        return self._get_json(url)

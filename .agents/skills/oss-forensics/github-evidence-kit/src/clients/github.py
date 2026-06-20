"""
GitHub API Client (Unauthenticated).
"""
from __future__ import annotations

from typing import Any

from ..schema.common import EvidenceSource


class GitHubClient:
    """Client for GitHub REST API (unauthenticated OSINT).

    Rate limits: 60 requests/hour unauthenticated.
    All public repository data is accessible without authentication.
    """

    BASE_URL = "https://api.github.com"

    def __init__(self):
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

    def get_commit(self, owner: str, repo: str, sha: str) -> dict[str, Any]:
        """Fetch commit from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{sha}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_issue(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch issue from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/issues/{number}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_pull_request(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch PR from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{number}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_file(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> dict[str, Any]:
        """Fetch file content from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref}
        resp = session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_branch(self, owner: str, repo: str, branch: str) -> dict[str, Any]:
        """Fetch branch from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/branches/{branch}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_tag(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch tag from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/git/refs/tags/{tag}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_release(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch release by tag from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/releases/tags/{tag}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_forks(self, owner: str, repo: str, per_page: int = 100) -> list[dict[str, Any]]:
        """Fetch forks from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/forks"
        params = {"per_page": per_page}
        resp = session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        """Fetch repository info from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

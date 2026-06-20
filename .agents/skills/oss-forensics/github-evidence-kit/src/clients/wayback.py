"""
Wayback Machine Client.
"""
from __future__ import annotations

from typing import Any

from ..schema.common import EvidenceSource


class WaybackClient:
    """Client for Wayback Machine CDX API."""

    CDX_URL = "https://web.archive.org/cdx/search/cdx"
    AVAILABILITY_URL = "https://archive.org/wayback/available"
    ARCHIVE_URL = "https://web.archive.org/web"

    def __init__(self):
        self._session: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.WAYBACK

    def _get_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def search_cdx(
        self,
        url: str,
        match_type: str = "exact",
        from_date: str | None = None,
        to_date: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, str]]:
        """Search CDX API for archived snapshots."""
        session = self._get_session()
        params: dict[str, Any] = {
            "url": url,
            "output": "json",
            "matchType": match_type,
            "filter": "statuscode:200",
            "limit": limit,
        }
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date

        resp = session.get(self.CDX_URL, params=params)
        resp.raise_for_status()
        data = resp.json()

        if len(data) <= 1:
            return []

        headers = data[0]
        return [dict(zip(headers, row)) for row in data[1:]]

    def get_snapshot(self, url: str, timestamp: str) -> str | None:
        """Fetch archived page content."""
        session = self._get_session()
        archive_url = f"{self.ARCHIVE_URL}/{timestamp}/{url}"
        resp = session.get(archive_url)
        if resp.status_code == 200:
            return resp.text
        return None

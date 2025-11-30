"""
Wayback Machine Collector.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import HttpUrl

from ..clients.wayback import WaybackClient
from ..schema.common import EvidenceSource, VerificationInfo
from ..schema.observations import SnapshotObservation, WaybackSnapshot
from ..helpers import generate_evidence_id


class WaybackCollector:
    """Collects evidence from Wayback Machine."""

    def __init__(self, client: WaybackClient | None = None):
        self.client = client or WaybackClient()

    def collect_snapshots(
        self,
        url: str,
        from_date: str | None = None,
        to_date: str | None = None,
        limit: int = 1000,
    ) -> SnapshotObservation:
        """
        Collect archived snapshots for a URL.

        Args:
            url: The URL to search for in Wayback Machine
            from_date: Start date filter (YYYYMMDD format)
            to_date: End date filter (YYYYMMDD format)
            limit: Maximum number of snapshots to return

        Returns:
            SnapshotObservation with list of archived snapshots
        """
        results = self.client.search_cdx(
            url=url,
            from_date=from_date,
            to_date=to_date,
            limit=limit,
        )

        now = datetime.now(timezone.utc)

        snapshots = [
            WaybackSnapshot(
                timestamp=row.get("timestamp", ""),
                original=row.get("original", url),
                digest=row.get("digest", ""),
                mimetype=row.get("mimetype", ""),
                statuscode=row.get("statuscode", "200"),
                length=row.get("length", ""),
            )
            for row in results
        ]

        return SnapshotObservation(
            evidence_id=generate_evidence_id("wayback", url),
            observed_when=now,
            observed_by=EvidenceSource.WAYBACK,
            observed_what=f"Found {len(snapshots)} Wayback snapshots for {url}",
            verification=VerificationInfo(
                source=EvidenceSource.WAYBACK,
                url=HttpUrl(f"https://web.archive.org/web/*/{url}"),
            ),
            original_url=HttpUrl(url),
            snapshots=snapshots,
            total_snapshots=len(snapshots),
        )

    def collect_snapshot_content(
        self, url: str, timestamp: str
    ) -> str | None:
        """
        Fetch the actual content of an archived snapshot.

        Args:
            url: The original URL
            timestamp: Wayback Machine timestamp (YYYYMMDDHHMMSS format)

        Returns:
            HTML content of the archived page, or None if not found
        """
        return self.client.get_snapshot(url, timestamp)

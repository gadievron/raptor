"""
GH Archive Collector.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from ..clients.gharchive import GHArchiveClient
from ..schema.common import EvidenceSource, VerificationInfo
from ..schema.observations import CommitAuthor, CommitObservation, IssueObservation
from ..helpers import (
    generate_evidence_id,
    make_actor,
    make_repo,
    parse_datetime_strict,
)
from ..parsers import is_supported_event_type, parse_gharchive_event
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..schema.events import AnyEvent


def _gharchive_day(timestamp: str) -> str:
    """Derive the 8-digit ``YYYYMMDD`` day for the GH Archive day table
    from a caller-supplied timestamp.

    Accepts ISO forms ("2024-01-15T10:30:00Z", "2024-01-15 10:30:00")
    and digit-only forms ("20240115", "202401151030"). The previous
    inline derivation (``timestamp[:10].replace("-", "")``) produced
    the wrong digit count for anything but a dash-separated date and
    the 8-digit result was then rejected by the client's 12-digit
    validation, so every recover_* call raised before querying.
    """
    digits = "".join(ch for ch in timestamp if ch.isdigit())
    if len(digits) < 8:
        msg = (
            f"timestamp {timestamp!r} does not contain a YYYYMMDD date "
            "(need at least 8 digits, e.g. '2024-01-15T10:30:00Z' or "
            "'20240115')"
        )
        raise ValueError(msg)
    return digits[:8]


def _parse_query_timestamp(timestamp: str) -> tuple[datetime, bool]:
    """Parse a caller-supplied recover_* timestamp.

    Returns ``(dt, day_only)`` where ``day_only`` is True when the
    caller gave date granularity only. Accepts the documented shapes:
    ISO forms ("2024-01-15T10:30:00Z", "2024-01-15 10:30:00",
    "2024-01-15") and digit-only forms ("20240115", "202401151030",
    "20240115103000"). Naive values are taken as UTC (GH Archive is
    UTC throughout). Raises ValueError on anything else — a query
    timestamp that cannot be parsed must fail loudly, not miss rows.
    """
    ts = timestamp.strip()
    if ts.isdigit():
        formats = {8: "%Y%m%d", 12: "%Y%m%d%H%M", 14: "%Y%m%d%H%M%S"}
        fmt = formats.get(len(ts))
        if fmt is None:
            msg = (
                f"digit-only timestamp {timestamp!r} must be 8 (YYYYMMDD), "
                "12 (YYYYMMDDHHMM) or 14 (YYYYMMDDHHMMSS) digits"
            )
            raise ValueError(msg)
        return (
            datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc),
            len(ts) == 8,
        )
    parsed = parse_datetime_strict(ts)
    if parsed is None:  # unreachable for str input; narrows the type
        msg = f"Unable to parse timestamp: {timestamp!r}"
        raise ValueError(msg)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    # Date-only ISO form ("2024-01-15"): day granularity.
    return parsed.astimezone(timezone.utc), len(ts) == 10 and ts.count("-") == 2


def _as_int(value: object) -> int | None:
    """GH Archive numerics are JSON numbers on modern rows, strings on
    some pre-2015 rows — a string-numbered issue/PR row silently
    missed the ``== number`` comparison. Mirrors the verifier's
    coercion (verifiers/consistency._num)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _timestamp_matches(timestamp: str, row_created_at: object) -> bool:
    """True when a BigQuery row's ``created_at`` falls at the caller's
    recovery timestamp.

    The BigQuery client returns TIMESTAMP columns as tz-aware
    ``datetime`` objects, which stringify as "2025-07-13 20:30:24+00:00"
    — the previous substring probe (``timestamp in str(created_at)``)
    could therefore never match the documented call shapes
    ("2025-07-13T20:30:24Z", "202401151030") on the live transport.
    Compare parsed datetimes at explicit granularity instead: whole day
    for date-only queries, exact minute otherwise (the finest filter
    the 12-digit collect_events contract offers; recover_* callers
    additionally match discriminating payload fields).

    An unparseable ROW skips that row (malformed archive data must not
    abort recovery); an unparseable QUERY timestamp raises.
    """
    query_dt, day_only = _parse_query_timestamp(timestamp)
    if isinstance(row_created_at, datetime):
        row_dt = row_created_at
    elif isinstance(row_created_at, str):
        try:
            row_dt = parse_datetime_strict(row_created_at)
        except ValueError:
            return False
    else:
        return False
    if row_dt.tzinfo is None:
        row_dt = row_dt.replace(tzinfo=timezone.utc)
    row_dt = row_dt.astimezone(timezone.utc)

    if day_only:
        return row_dt.date() == query_dt.date()
    return row_dt.replace(second=0, microsecond=0) == query_dt.replace(
        second=0, microsecond=0,
    )


# Row cap for recovery queries. A result that HITS this cap is
# truncated: "no match among the first N rows" is not evidence of
# absence, and recover_* must say so instead of raising "not found".
_RECOVERY_ROW_LIMIT = GHArchiveClient.DEFAULT_LIMIT


class GHArchiveCollector:
    """Collects evidence from GH Archive (BigQuery)."""

    def __init__(self, client: GHArchiveClient | None = None) -> None:
        self.client = client or GHArchiveClient()

    def _recovery_query_rows(
        self, repo: str, event_type: str, timestamp: str
    ) -> tuple[list[dict], bool]:
        """Query candidate rows for a recover_* call.

        When the caller's timestamp carries minute granularity, filter
        at the SQL layer to that exact minute (the scan then stays far
        below the row cap even on busy repos); day-only timestamps scan
        the whole day table. Returns ``(rows, truncated)`` where
        ``truncated`` means the result hit the row cap.
        """
        query_dt, day_only = _parse_query_timestamp(timestamp)
        from_date = query_dt.strftime("%Y%m%d" if day_only else "%Y%m%d%H%M")
        rows = self.client.query_events(
            repo=repo,
            event_type=event_type,
            from_date=from_date,
            limit=_RECOVERY_ROW_LIMIT,
        )
        return rows, len(rows) >= _RECOVERY_ROW_LIMIT

    @staticmethod
    def _absence_error(what: str, repo: str, timestamp: str, truncated: bool) -> ValueError:
        """Build the terminal error for a recovery miss.

        A truncated result set must never be presented as forensic
        evidence of absence.
        """
        if truncated:
            return ValueError(
                f"{what} not found in the first {_RECOVERY_ROW_LIMIT} GH Archive "
                f"rows for {repo} at {timestamp} — results truncated at the row "
                "cap, so absence cannot be concluded; narrow the timestamp to "
                "minute granularity (YYYYMMDDHHMM / full ISO) and retry"
            )
        return ValueError(f"{what} not found in GH Archive for {repo} at {timestamp}")

    def collect_events(
        self,
        timestamp: str,
        repo: str | None = None,
        actor: str | None = None,
        event_type: str | None = None,
    ) -> list[AnyEvent]:
        """Collect events from GH Archive."""
        if len(timestamp) != 12 or not timestamp.isdigit():
            msg = f"timestamp must be YYYYMMDDHHMM format (12 digits), got: {timestamp}"
            raise ValueError(msg)

        if not repo and not actor:
            msg = "Must specify at least 'repo' or 'actor' to avoid expensive full-table scans"
            raise ValueError(msg)

        rows = self.client.query_events(
            repo=repo,
            actor=actor,
            event_type=event_type,
            from_date=timestamp,
            to_date=timestamp,
        )

        # Unsupported GH Archive event types (GollumEvent, the
        # PR-review events, CommitCommentEvent, ...) are ROUTINE in an
        # unfiltered repo-minute; one of them must not abort the whole
        # collection — the same one-event-kills-ingest class the
        # member-edited action fix closed, left open for type
        # dispatch. Skip-and-log those per row (the ingest script does
        # the same); malformed rows of SUPPORTED types still raise,
        # per the comment below.
        supported_rows = []
        skipped: dict[str, int] = {}
        for row in rows:
            etype = row.get("type", "") if isinstance(row, dict) else ""
            if not is_supported_event_type(etype):
                key = etype or "<missing type>"
                skipped[key] = skipped.get(key, 0) + 1
                continue
            supported_rows.append(row)
        if skipped:
            detail = ", ".join(
                f"{k} x{v}" for k, v in sorted(skipped.items())
            )
            logger.warning(
                "collect_events: skipped %d unsupported event row(s): %s",
                sum(skipped.values()), detail,
            )

        # Raise error on malformed rows instead of silently skipping
        events = [parse_gharchive_event(row) for row in supported_rows]

        return events

    def recover_issue(self, repo: str, issue_number: int, timestamp: str) -> IssueObservation:
        """Recover deleted issue content from GH Archive."""
        return self._recover_from_gharchive("issue", repo, issue_number, timestamp)

    def recover_pr(self, repo: str, pr_number: int, timestamp: str) -> IssueObservation:
        """Recover deleted PR content from GH Archive."""
        return self._recover_from_gharchive("pr", repo, pr_number, timestamp)

    def recover_commit(self, repo: str, sha: str, timestamp: str) -> CommitObservation:
        """Recover commit metadata from GH Archive."""
        owner, name = repo.split("/", 1)
        date = _gharchive_day(timestamp)

        rows, truncated = self._recovery_query_rows(repo, "PushEvent", timestamp)

        for row in rows:
            if not _timestamp_matches(timestamp, row.get("created_at")):
                continue

            payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
            for commit in payload.get("commits", []):
                # .get, not [..]: one malformed commit entry (no sha)
                # must skip that entry, not abort the whole recovery.
                row_sha = commit.get("sha") if isinstance(commit, dict) else None
                if not isinstance(row_sha, str) or not row_sha:
                    continue
                if row_sha.startswith(sha) or sha.startswith(row_sha):
                    return CommitObservation(
                        evidence_id=generate_evidence_id("commit-gharchive", repo, row_sha),
                        original_when=parse_datetime_strict(row["created_at"]),
                        original_who=make_actor(commit.get("author", {}).get("name", "")),
                        original_what=commit.get("message", "").split("\n")[0],
                        observed_when=parse_datetime_strict(row["created_at"]),
                        observed_by=EvidenceSource.GHARCHIVE,
                        observed_what=f"Commit {commit['sha'][:8]} recovered from GH Archive",
                        repository=make_repo(owner, name),
                        verification=VerificationInfo(
                            source=EvidenceSource.GHARCHIVE,
                            bigquery_table=f"githubarchive.day.{date}",
                            query=f"repo.name='{repo}' AND type='PushEvent' AND created_at='{timestamp}'",
                        ),
                        sha=row_sha,
                        message=commit.get("message", ""),
                        author=CommitAuthor(
                            name=commit.get("author", {}).get("name", ""),
                            email=commit.get("author", {}).get("email", ""),
                            date=parse_datetime_strict(row["created_at"]),
                        ),
                        committer=CommitAuthor(
                            name=commit.get("author", {}).get("name", ""),
                            email=commit.get("author", {}).get("email", ""),
                            date=parse_datetime_strict(row["created_at"]),
                        ),
                        parents=[],
                        files=[],
                        is_dangling=True,
                    )

        raise self._absence_error(f"Commit {sha}", repo, timestamp, truncated)

    def recover_force_push(self, repo: str, timestamp: str) -> CommitObservation:
        """Recover force-pushed commit from GH Archive."""
        owner, name = repo.split("/", 1)
        date = _gharchive_day(timestamp)

        rows, truncated = self._recovery_query_rows(repo, "PushEvent", timestamp)

        for row in rows:
            if not _timestamp_matches(timestamp, row.get("created_at")):
                continue

            payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
            size = int(payload.get("size", 0))
            before_sha = payload.get("before", "0" * 40)

            if size == 0 and before_sha != "0" * 40:
                return CommitObservation(
                    evidence_id=generate_evidence_id("forcepush-gharchive", repo, before_sha, timestamp),
                    original_when=parse_datetime_strict(row["created_at"]),
                    original_who=make_actor(row["actor_login"]),
                    original_what="Commit overwritten by force push",
                    observed_when=parse_datetime_strict(row["created_at"]),
                    observed_by=EvidenceSource.GHARCHIVE,
                    observed_what=f"Force push detected, before SHA: {before_sha[:8]}",
                    repository=make_repo(owner, name),
                    verification=VerificationInfo(
                        source=EvidenceSource.GHARCHIVE,
                        bigquery_table=f"githubarchive.day.{date}",
                        query=f"repo.name='{repo}' AND type='PushEvent' AND created_at='{timestamp}' AND size=0",
                    ),
                    sha=before_sha,
                    message="[Force pushed - fetch content via GitHub API]",
                    author=CommitAuthor(
                        name="unknown",
                        email="unknown",
                        date=parse_datetime_strict(row["created_at"]),
                    ),
                    committer=CommitAuthor(
                        name="unknown",
                        email="unknown",
                        date=parse_datetime_strict(row["created_at"]),
                    ),
                    parents=[],
                    files=[],
                    is_dangling=True,
                )

        raise self._absence_error("Force push", repo, timestamp, truncated)

    def _recover_from_gharchive(
        self, item_type: str, repo: str, number: int, timestamp: str
    ) -> IssueObservation:
        """Internal: Recover issue or PR from GH Archive."""
        owner, name = repo.split("/", 1)
        date = _gharchive_day(timestamp)
        event_type = "PullRequestEvent" if item_type == "pr" else "IssuesEvent"
        payload_key = "pull_request" if item_type == "pr" else "issue"

        rows, truncated = self._recovery_query_rows(repo, event_type, timestamp)

        for row in rows:
            payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
            item = payload.get(payload_key, {})

            if _as_int(item.get("number")) == number and _timestamp_matches(
                timestamp, row.get("created_at"),
            ):
                state = item.get("state", "open")
                if item.get("merged"):
                    state = "merged"

                is_pr = item_type == "pr"
                prefix = "pr-gharchive" if is_pr else "issue-gharchive"

                return IssueObservation(
                    evidence_id=generate_evidence_id(prefix, repo, str(number), timestamp),
                    original_when=parse_datetime_strict(item.get("created_at")),
                    original_who=make_actor(item.get("user", {}).get("login", row["actor_login"])),
                    original_what=f"{'PR' if is_pr else 'Issue'} #{number} created",
                    observed_when=parse_datetime_strict(row["created_at"]),
                    observed_by=EvidenceSource.GHARCHIVE,
                    observed_what=f"{'PR' if is_pr else 'Issue'} #{number} recovered from GH Archive",
                    repository=make_repo(owner, name),
                    verification=VerificationInfo(
                        source=EvidenceSource.GHARCHIVE,
                        bigquery_table=f"githubarchive.day.{date}",
                        query=f"repo.name='{repo}' AND type='{event_type}' AND created_at='{timestamp}'",
                    ),
                    issue_number=number,
                    is_pull_request=is_pr,
                    title=item.get("title"),
                    body=item.get("body"),
                    state=state,
                    is_deleted=True,
                )

        label = "PR" if item_type == "pr" else "Issue"
        raise self._absence_error(f"{label} #{number}", repo, timestamp, truncated)

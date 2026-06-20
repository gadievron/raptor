"""
GH Archive Collector.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..clients.gharchive import GHArchiveClient
from ..schema.common import EvidenceSource, VerificationInfo
from ..schema.events import AnyEvent
from ..schema.observations import CommitAuthor, CommitObservation, IssueObservation
from ..helpers import (
    generate_evidence_id,
    make_actor,
    make_repo,
    parse_datetime_strict,
)
from ..parsers import parse_gharchive_event


class GHArchiveCollector:
    """Collects evidence from GH Archive (BigQuery)."""

    def __init__(self, client: GHArchiveClient | None = None):
        self.client = client or GHArchiveClient()

    def collect_events(
        self,
        timestamp: str,
        repo: str | None = None,
        actor: str | None = None,
        event_type: str | None = None,
    ) -> list[AnyEvent]:
        """Collect events from GH Archive."""
        if len(timestamp) != 12 or not timestamp.isdigit():
            raise ValueError(f"timestamp must be YYYYMMDDHHMM format (12 digits), got: {timestamp}")

        if not repo and not actor:
            raise ValueError("Must specify at least 'repo' or 'actor' to avoid expensive full-table scans")

        rows = self.client.query_events(
            repo=repo,
            actor=actor,
            event_type=event_type,
            from_date=timestamp,
            to_date=timestamp,
        )

        events = []
        for row in rows:
            # Raise error on malformed rows instead of silently skipping
            events.append(parse_gharchive_event(row))

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
        date = timestamp[:10].replace("-", "")

        rows = self.client.query_events(repo=repo, event_type="PushEvent", from_date=date)

        for row in rows:
            row_ts = str(row.get("created_at", ""))
            if timestamp not in row_ts:
                continue

            payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
            for commit in payload.get("commits", []):
                if commit["sha"].startswith(sha) or sha.startswith(commit["sha"]):
                    return CommitObservation(
                        evidence_id=generate_evidence_id("commit-gharchive", repo, commit["sha"]),
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
                        sha=commit["sha"],
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

        raise ValueError(f"Commit {sha} not found in GH Archive for {repo} at {timestamp}")

    def recover_force_push(self, repo: str, timestamp: str) -> CommitObservation:
        """Recover force-pushed commit from GH Archive."""
        owner, name = repo.split("/", 1)
        date = timestamp[:10].replace("-", "")

        rows = self.client.query_events(repo=repo, event_type="PushEvent", from_date=date)

        for row in rows:
            row_ts = str(row.get("created_at", ""))
            if timestamp not in row_ts:
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

        raise ValueError(f"Force push not found in GH Archive for {repo} at {timestamp}")

    def _recover_from_gharchive(
        self, item_type: str, repo: str, number: int, timestamp: str
    ) -> IssueObservation:
        """Internal: Recover issue or PR from GH Archive."""
        owner, name = repo.split("/", 1)
        date = timestamp[:10].replace("-", "")
        event_type = "PullRequestEvent" if item_type == "pr" else "IssuesEvent"
        payload_key = "pull_request" if item_type == "pr" else "issue"

        rows = self.client.query_events(repo=repo, event_type=event_type, from_date=date)

        for row in rows:
            payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
            item = payload.get(payload_key, {})
            row_ts = str(row.get("created_at", ""))

            if item.get("number") == number and timestamp in row_ts:
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
        raise ValueError(f"{label} #{number} not found in GH Archive for {repo} at {timestamp}")

#!/usr/bin/env python3
"""
Regression tests for the GH Archive deleted-content recovery path.

The recover_* collectors derived an 8-digit day from the caller's
timestamp and passed it to ``GHArchiveClient.query_events``, which
only accepted 12-digit ``YYYYMMDDHHMM`` — every recover_* call raised
before issuing a query. The integration test below drives
``recover_issue`` through the real client code path (mocked BigQuery
transport only) so the day-granularity contract between collector and
client stays pinned.

No network, no credentials: the BigQuery client object is stubbed at
``GHArchiveClient._get_client``.
"""


import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# .claude/skills/oss-forensics/github-evidence-kit/tests/... -> .claude/skills/oss-forensics/github-evidence-kit
sys.path.insert(0, str(Path(__file__).parents[1]))

from src.clients.gharchive import GHArchiveClient
from src.collectors.archive import (
    GHArchiveCollector,
    _gharchive_day,
    _timestamp_matches,
)
from src.schema.common import EvidenceSource
from src.schema.observations import CommitObservation, IssueObservation

# =============================================================================
# BIGQUERY TRANSPORT STUB
# =============================================================================


class _StubBigQueryClient:
    """Captures the query text + job config and returns canned rows."""

    def __init__(self, rows):
        self.rows = rows
        self.queries: list[str] = []
        self.job_configs: list = []

    def query(self, query, job_config=None):
        self.queries.append(query)
        self.job_configs.append(job_config)
        return list(self.rows)


def _bq_row(*, created_at: datetime, payload: dict, event_type: str,
            actor_login: str = "actor") -> dict:
    """A row shaped like the REAL BigQuery transport emits it.

    ``[dict(row) for row in results]`` yields TIMESTAMP columns as
    tz-aware ``datetime`` objects (which stringify as
    "2025-07-13 07:52:37+00:00", NOT ISO-with-Z) and ``payload`` as a
    JSON STRING. Earlier stubs used ISO strings for created_at, which
    masked a matcher that could never match live rows — keep every
    stubbed row in the real shape.
    """
    assert created_at.tzinfo is not None, "BigQuery TIMESTAMPs are tz-aware"
    return {
        "type": event_type,
        "created_at": created_at,
        "actor_login": actor_login,
        "actor_id": 1,
        "repo_name": "owner/repo",
        "repo_id": 2,
        "payload": json.dumps(payload),
    }


def _client_with_rows(monkeypatch, rows) -> tuple[GHArchiveClient, _StubBigQueryClient]:
    """GHArchiveClient whose BigQuery transport is the stub — everything
    from ``query_events`` down runs the real code."""
    client = GHArchiveClient()
    stub = _StubBigQueryClient(rows)
    monkeypatch.setattr(client, "_get_client", lambda: stub)
    return client, stub


def _param_names(job_config) -> list[str]:
    return [p.name for p in (job_config.query_parameters or [])]


# =============================================================================
# QUERY_EVENTS DATE GRANULARITY
# =============================================================================


class TestQueryEventsDateGranularity:
    def test_8_digit_day_accepted_without_hour_minute_filter(self, monkeypatch):
        client, stub = _client_with_rows(monkeypatch, [])
        client.query_events(repo="owner/repo", from_date="20250713")

        assert "`githubarchive.day.20250713`" in stub.queries[0]
        assert "EXTRACT(HOUR" not in stub.queries[0]
        assert "EXTRACT(MINUTE" not in stub.queries[0]
        names = _param_names(stub.job_configs[0])
        assert "hour" not in names and "minute" not in names
        assert "repo" in names

    def test_12_digit_minute_filter_preserved(self, monkeypatch):
        client, stub = _client_with_rows(monkeypatch, [])
        client.query_events(repo="owner/repo", from_date="202507130752")

        assert "`githubarchive.day.20250713`" in stub.queries[0]
        assert "EXTRACT(HOUR FROM created_at) = @hour" in stub.queries[0]
        assert "EXTRACT(MINUTE FROM created_at) = @minute" in stub.queries[0]
        params = {p.name: p.value for p in stub.job_configs[0].query_parameters}
        assert params["hour"] == 7
        assert params["minute"] == 52

    @pytest.mark.parametrize(
        "bad",
        ["2025071307", "2025-07-13", "202507", "", "20250713075299x"],
    )
    def test_other_shapes_rejected(self, monkeypatch, bad):
        client, _ = _client_with_rows(monkeypatch, [])
        with pytest.raises(ValueError, match="Invalid date format"):
            client.query_events(repo="owner/repo", from_date=bad)


# =============================================================================
# DAY DERIVATION HELPER
# =============================================================================


class TestGHArchiveDay:
    @pytest.mark.parametrize(
        ("timestamp", "expected"),
        [
            ("2025-07-13T07:52:37Z", "20250713"),
            ("2025-07-13 07:52:37", "20250713"),
            ("2025-07-13", "20250713"),
            ("20250713", "20250713"),
            ("202507130752", "20250713"),
        ],
    )
    def test_accepted_forms(self, timestamp, expected):
        assert _gharchive_day(timestamp) == expected

    @pytest.mark.parametrize("bad", ["", "2025-07", "not-a-date"])
    def test_rejected_forms(self, bad):
        with pytest.raises(ValueError, match="YYYYMMDD"):
            _gharchive_day(bad)


# =============================================================================
# RECOVER_ISSUE INTEGRATION (collector -> real client -> stub transport)
# =============================================================================


class TestRecoverIssueThroughClient:
    def test_recover_issue_end_to_end(self, monkeypatch):
        """The documented deleted-content recovery API works against the
        real ``query_events`` — the 8-vs-12-digit regression raised here
        before any query was issued, and the substring timestamp match
        never matched a real (datetime-valued) BigQuery row at all."""
        timestamp = "2025-07-13T07:52:37Z"  # SKILL.md-documented shape
        payload = {
            "action": "opened",
            "issue": {
                "number": 42,
                "state": "open",
                "title": "Deleted issue title",
                "body": "Deleted issue body",
                "created_at": "2025-07-13T07:52:37Z",
                "user": {"login": "reporter"},
            },
        }
        row = _bq_row(
            created_at=datetime(2025, 7, 13, 7, 52, 37, tzinfo=timezone.utc),
            payload=payload,
            event_type="IssuesEvent",
            actor_login="reporter",
        )
        client, stub = _client_with_rows(monkeypatch, [row])

        obs = GHArchiveCollector(client).recover_issue("owner/repo", 42, timestamp)

        assert isinstance(obs, IssueObservation)
        assert obs.is_deleted is True
        assert obs.issue_number == 42
        assert obs.title == "Deleted issue title"
        assert obs.verification.source == EvidenceSource.GHARCHIVE
        assert obs.verification.bigquery_table == "githubarchive.day.20250713"

        # Minute-precise timestamp: the query filters to the exact
        # hour/minute at the SQL layer (keeps busy-repo scans far below
        # the row cap that would otherwise truncate recovery).
        assert "`githubarchive.day.20250713`" in stub.queries[0]
        assert "EXTRACT(HOUR" in stub.queries[0]
        assert "EXTRACT(MINUTE" in stub.queries[0]
        names = _param_names(stub.job_configs[0])
        assert "hour" in names and "minute" in names

    def test_recover_issue_matches_string_numbered_row(self, monkeypatch):
        """Pre-2015 GH Archive rows carry numbers as JSON strings — a
        string-numbered row silently missed the == comparison and
        recovery reported a false "not found"."""
        timestamp = "2025-07-13T07:52:37Z"
        payload = {
            "action": "opened",
            "issue": {
                "number": "42",
                "state": "open",
                "title": "Deleted issue title",
                "body": "b",
                "created_at": "2025-07-13T07:52:37Z",
                "user": {"login": "reporter"},
            },
        }
        row = _bq_row(
            created_at=datetime(2025, 7, 13, 7, 52, 37, tzinfo=timezone.utc),
            payload=payload,
            event_type="IssuesEvent",
            actor_login="reporter",
        )
        client, _ = _client_with_rows(monkeypatch, [row])
        obs = GHArchiveCollector(client).recover_issue("owner/repo", 42, timestamp)
        assert obs.issue_number == 42

    def test_recover_commit_skips_sha_less_commit_entry(self, monkeypatch):
        """One malformed commits[] entry (no sha) must skip that entry,
        not abort the whole recovery with a KeyError."""
        timestamp = "2025-07-13T07:52:37Z"
        payload = {
            "ref": "refs/heads/main",
            "commits": [
                {"message": "corrupt entry, no sha"},
                {"sha": "a" * 40,
                 "message": "real commit",
                 "author": {"name": "n", "email": "e@example.org"}},
            ],
        }
        row = _bq_row(
            created_at=datetime(2025, 7, 13, 7, 52, 37, tzinfo=timezone.utc),
            payload=payload,
            event_type="PushEvent",
            actor_login="reporter",
        )
        client, _ = _client_with_rows(monkeypatch, [row])
        obs = GHArchiveCollector(client).recover_commit(
            "owner/repo", "a" * 40, timestamp)
        assert obs.sha == "a" * 40

    def test_recover_issue_not_found_raises(self, monkeypatch):
        client, _ = _client_with_rows(monkeypatch, [])
        with pytest.raises(ValueError, match="not found in GH Archive"):
            GHArchiveCollector(client).recover_issue(
                "owner/repo", 42, "2025-07-13T07:52:37",
            )

    def test_same_day_different_minute_does_not_match(self, monkeypatch):
        payload = {
            "action": "opened",
            "issue": {"number": 42, "state": "open", "title": "t",
                      "created_at": "2025-07-13T09:00:00Z",
                      "user": {"login": "reporter"}},
        }
        row = _bq_row(
            created_at=datetime(2025, 7, 13, 9, 0, 0, tzinfo=timezone.utc),
            payload=payload,
            event_type="IssuesEvent",
        )
        client, _ = _client_with_rows(monkeypatch, [row])
        with pytest.raises(ValueError, match="not found in GH Archive"):
            GHArchiveCollector(client).recover_issue(
                "owner/repo", 42, "2025-07-13T07:52:37Z",
            )

    def test_recover_commit_matches_real_row_shape(self, monkeypatch):
        """recover_commit with the documented digit timestamp against a
        datetime-valued row (the live-transport shape)."""
        sha = "678851b" + "0" * 33
        payload = {
            "ref": "refs/heads/main",
            "before": "b" * 40,
            "size": 1,
            "commits": [{"sha": sha, "message": "msg",
                         "author": {"name": "A", "email": "a@x.test"}}],
        }
        row = _bq_row(
            created_at=datetime(2025, 7, 13, 20, 30, 24, tzinfo=timezone.utc),
            payload=payload,
            event_type="PushEvent",
        )
        client, _ = _client_with_rows(monkeypatch, [row])

        obs = GHArchiveCollector(client).recover_commit(
            "owner/repo", "678851b", "202507132030",
        )
        assert isinstance(obs, CommitObservation)
        assert obs.sha == sha
        assert obs.is_dangling is True


# =============================================================================
# TIMESTAMP MATCHING GRANULARITY
# =============================================================================


class TestTimestampMatches:
    _ROW_DT = datetime(2025, 7, 13, 20, 30, 24, tzinfo=timezone.utc)

    @pytest.mark.parametrize(
        "query",
        [
            "2025-07-13T20:30:24Z",   # SKILL.md-documented shape
            "2025-07-13T20:30:00Z",   # same minute, different second
            "2025-07-13 20:30:24",    # naive form, taken as UTC
            "202507132030",           # 12-digit collect_events shape
            "20250713203024",         # 14-digit
            "2025-07-13",             # day granularity
            "20250713",               # day granularity, digits
        ],
    )
    def test_matching_shapes(self, query):
        assert _timestamp_matches(query, self._ROW_DT)

    @pytest.mark.parametrize(
        "query",
        [
            "2025-07-13T20:31:24Z",   # next minute
            "202507132029",           # previous minute
            "2025-07-14",             # next day
            "20250714",
        ],
    )
    def test_non_matching_shapes(self, query):
        assert not _timestamp_matches(query, self._ROW_DT)

    def test_string_row_from_json_transport_still_matches(self):
        # raptor-bq-query serialises rows to JSON, so created_at can be
        # a string on that path.
        assert _timestamp_matches(
            "2025-07-13T20:30:24Z", "2025-07-13 20:30:24+00:00",
        )

    def test_malformed_row_skipped_not_fatal(self):
        assert not _timestamp_matches("2025-07-13T20:30:24Z", "garbage")
        assert not _timestamp_matches("2025-07-13T20:30:24Z", None)
        assert not _timestamp_matches("2025-07-13T20:30:24Z", 12345)

    def test_malformed_query_raises(self):
        with pytest.raises(ValueError):
            _timestamp_matches("not-a-date", self._ROW_DT)
        with pytest.raises(ValueError):
            _timestamp_matches("2025071320", self._ROW_DT)  # 10 digits


# =============================================================================
# DELETED-CLAIM VERIFICATION FAILS CLOSED
# =============================================================================

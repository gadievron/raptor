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
from pathlib import Path

import pytest

# .claude/skills/oss-forensics/github-evidence-kit/tests/... -> .claude/skills/oss-forensics/github-evidence-kit
sys.path.insert(0, str(Path(__file__).parents[1]))

from src.clients.gharchive import GHArchiveClient
from src.collectors.archive import GHArchiveCollector, _gharchive_day
from src.schema.common import EvidenceSource
from src.schema.observations import IssueObservation

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
        before any query was issued."""
        timestamp = "2025-07-13T07:52:37"
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
        row = {
            "type": "IssuesEvent",
            "created_at": "2025-07-13T07:52:37Z",
            "actor_login": "reporter",
            "actor_id": 1,
            "repo_name": "owner/repo",
            "repo_id": 2,
            "payload": json.dumps(payload),
        }
        client, stub = _client_with_rows(monkeypatch, [row])

        obs = GHArchiveCollector(client).recover_issue("owner/repo", 42, timestamp)

        assert isinstance(obs, IssueObservation)
        assert obs.is_deleted is True
        assert obs.issue_number == 42
        assert obs.title == "Deleted issue title"
        assert obs.verification.source == EvidenceSource.GHARCHIVE
        assert obs.verification.bigquery_table == "githubarchive.day.20250713"

        # Day-granularity query: whole-day table, no hour/minute filter.
        assert "`githubarchive.day.20250713`" in stub.queries[0]
        assert "EXTRACT(HOUR" not in stub.queries[0]
        assert "EXTRACT(MINUTE" not in stub.queries[0]
        names = _param_names(stub.job_configs[0])
        assert "hour" not in names and "minute" not in names

    def test_recover_issue_not_found_raises(self, monkeypatch):
        client, _ = _client_with_rows(monkeypatch, [])
        with pytest.raises(ValueError, match="not found in GH Archive"):
            GHArchiveCollector(client).recover_issue(
                "owner/repo", 42, "2025-07-13T07:52:37",
            )


# =============================================================================
# DELETED-CLAIM VERIFICATION FAILS CLOSED
# =============================================================================

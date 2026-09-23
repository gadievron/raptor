"""GH Archive row-cap honesty: truncated results are not absence.

``query_events`` always capped results at LIMIT 1000; day-granularity
recover_* calls then searched only those rows and raised "not found"
past row 1000 — a false negative presented as forensic evidence of
absence, on exactly the busy repos the kit targets.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.clients.gharchive import GHArchiveClient
from src.collectors.archive import _RECOVERY_ROW_LIMIT, GHArchiveCollector


class _StubBigQueryClient:
    def __init__(self, rows):
        self.rows = rows
        self.queries: list[str] = []
        self.job_configs: list = []

    def query(self, query, job_config=None):
        self.queries.append(query)
        self.job_configs.append(job_config)
        return list(self.rows)


def _client_with_rows(rows) -> tuple[GHArchiveClient, _StubBigQueryClient]:
    client = GHArchiveClient(project_id="test")
    stub = _StubBigQueryClient(rows)
    client._client = stub
    return client, stub


def _push_row(minute: int) -> dict:
    return {
        "type": "PushEvent",
        "created_at": datetime(2025, 7, 13, 7, minute % 60, tzinfo=timezone.utc),
        "actor_login": "actor",
        "actor_id": 1,
        "repo_name": "owner/repo",
        "repo_id": 2,
        "payload": json.dumps({"ref": "refs/heads/main", "before": "b" * 40,
                               "size": 1, "commits": []}),
    }


class TestQueryEventsBillingCap:
    def test_query_carries_maximum_bytes_billed(self):
        """Every query_events call must cap billed bytes, mirroring
        the typed wrapper's default: the verify_all lane runs one
        whole-day scan per evidence item through this client
        DIRECTLY, so an uncapped job config here billed unbounded
        bytes per verification leg."""
        client, stub = _client_with_rows([])
        client.query_events(repo="owner/repo", from_date="20250713")
        cfg = stub.job_configs[0]
        assert cfg is not None
        assert getattr(cfg, "maximum_bytes_billed", None) == 200 * 1000**3


class TestQueryEventsLimit:
    def test_limit_is_parameterised(self):
        client, stub = _client_with_rows([])
        client.query_events(repo="owner/repo", from_date="20250713", limit=37)
        assert "LIMIT 37" in stub.queries[0]

    def test_default_limit_unchanged(self):
        client, stub = _client_with_rows([])
        client.query_events(repo="owner/repo", from_date="20250713")
        assert "LIMIT 1000" in stub.queries[0]

    @pytest.mark.parametrize("bad", [0, -1, 100_001])
    def test_out_of_range_limit_refused(self, bad):
        client, _ = _client_with_rows([])
        with pytest.raises(ValueError, match="limit"):
            client.query_events(repo="owner/repo", from_date="20250713", limit=bad)


class TestRecoveryTruncationHonesty:
    def test_capped_result_raises_truncation_not_absence(self):
        rows = [_push_row(i) for i in range(_RECOVERY_ROW_LIMIT)]
        client, _ = _client_with_rows(rows)
        with pytest.raises(ValueError, match="truncated at the row cap"):
            GHArchiveCollector(client).recover_commit(
                "owner/repo", "a" * 40, "20250713",
            )

    def test_uncapped_miss_still_raises_not_found(self):
        rows = [_push_row(i) for i in range(3)]
        client, _ = _client_with_rows(rows)
        with pytest.raises(ValueError, match="not found in GH Archive"):
            GHArchiveCollector(client).recover_commit(
                "owner/repo", "a" * 40, "20250713",
            )

    def test_day_only_timestamp_keeps_day_granularity(self):
        client, stub = _client_with_rows([])
        with pytest.raises(ValueError, match="not found"):
            GHArchiveCollector(client).recover_force_push("owner/repo", "20250713")
        assert "EXTRACT(HOUR" not in stub.queries[0]

    def test_minute_timestamp_filters_at_sql_layer(self):
        client, stub = _client_with_rows([])
        with pytest.raises(ValueError, match="not found"):
            GHArchiveCollector(client).recover_force_push(
                "owner/repo", "2025-07-13T07:52:37Z",
            )
        assert "EXTRACT(HOUR" in stub.queries[0]
        assert "EXTRACT(MINUTE" in stub.queries[0]

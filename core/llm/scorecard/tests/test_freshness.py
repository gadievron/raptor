"""Unit tests for the scorecard freshness-weighting core (pure functions)."""
from __future__ import annotations

from datetime import datetime, timezone

from core.llm.scorecard.freshness import (
    bucket_age_days,
    bucket_key,
    decay_weight,
    flatten_counts,
    is_bucketed,
    weighted_counts,
)

NOW = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)


def test_bucket_key_from_iso_and_datetime():
    assert bucket_key("2026-05-29T12:00:00+00:00") == "2026-05"
    assert bucket_key(datetime(2026, 1, 3, tzinfo=timezone.utc)) == "2026-01"
    # Degraded-but-parseable prefix.
    assert bucket_key("2026-05-29 weird") == "2026-05"


def test_bucket_age_days():
    assert bucket_age_days("2026-05", NOW) == 0.0          # current month = 0
    assert round(bucket_age_days("2026-04", NOW)) == 30    # one month ≈ 30d
    assert round(bucket_age_days("2025-05", NOW)) == 365   # one year ≈ 365d
    assert bucket_age_days("2026-06", NOW) == 0.0          # future floors to 0
    # Unparseable -> huge age (decays away, never raises).
    assert bucket_age_days("garbage", NOW) > 1e8


def test_decay_weight():
    assert decay_weight(0, 90) == 1.0
    assert decay_weight(90, 90) == 0.5                      # one half-life
    assert decay_weight(180, 90) == 0.25                    # two half-lives
    # Disabled forms all return 1.0 (no decay).
    assert decay_weight(1000, None) == 1.0
    assert decay_weight(1000, 0) == 1.0
    assert decay_weight(1000, -5) == 1.0


def test_flatten_counts_sums_all_buckets():
    buckets = {
        "2026-05": {"correct": 10, "incorrect": 1},
        "2026-04": {"correct": 5, "incorrect": 2},
    }
    assert flatten_counts(buckets) == (15, 3)
    assert flatten_counts({}) == (0, 0)


def test_weighted_disabled_equals_flatten():
    buckets = {
        "2026-05": {"correct": 10, "incorrect": 1},
        "2026-01": {"correct": 5, "incorrect": 2},
    }
    assert weighted_counts(buckets, None, NOW) == (15.0, 3.0)
    assert weighted_counts(buckets, 0, NOW) == (15.0, 3.0)


def test_weighted_recent_dominates():
    # Old data is mostly-correct; recent data is mostly-incorrect. With a short
    # half-life, the weighted miss-rate should be driven by the recent bucket.
    buckets = {
        "2026-05": {"correct": 0, "incorrect": 10},   # recent: all wrong
        "2025-05": {"correct": 100, "incorrect": 0},  # a year stale: all right
    }
    # Unweighted: miss-rate = 10/110 ≈ 0.09 (stale data dilutes the regression).
    c0, i0 = flatten_counts(buckets)
    assert i0 / (c0 + i0) < 0.10
    # Weighted (30-day half-life): the year-old correct counts decay to ~0,
    # so the weighted miss-rate is dominated by the recent failures.
    c, i = weighted_counts(buckets, 30, NOW)
    assert i / (c + i) > 0.90


def test_is_bucketed_discriminates_v1_v2():
    assert is_bucketed({"2026-05": {"correct": 1, "incorrect": 0}}) is True
    assert is_bucketed({}) is True                          # empty == empty buckets
    assert is_bucketed({"correct": 5, "incorrect": 1}) is False  # v1 flat shape

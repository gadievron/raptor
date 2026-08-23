"""Tests for pool pruning."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from core.labeled_attempts import (  # noqa: E402
    CodeQLEvidence,
    LabeledAttempt,
    PruneReport,
    SandboxEvidence,
    compute_finding_signature,
    prune_pool,
    read_all,
    write,
)


def _attempt(
    *, finding_id: str = "FND-X",
    code: str = "abort();",
    model: str = "claude-haiku-4-5",
    days_old: int = 0,
    cwe: str = "CWE-787",
    function: str = "f",
    outcome: str = "success",
) -> LabeledAttempt:
    now = datetime(2026, 6, 5, tzinfo=timezone.utc)
    ts = (now - timedelta(days=days_old)).isoformat()
    return LabeledAttempt(
        finding_id=finding_id,
        finding_signature=compute_finding_signature(
            cwe=cwe, file_path="x.c", function=function, line=0,
        ),
        cwe=cwe, outcome=outcome,
        sandbox_evidence=SandboxEvidence(
            bytes_hash="a"*64, bytes_len=len(code),
            observed_outcome=(
                "sanitizer_report" if outcome == "success"
                else "no_obvious_effect"
            ),
            exploit_code=code, exploit_language="c",
        ),
        producing_model=model, prompt_version="v3",
        iterations=1, cost_usd=0.01,
        timestamp=ts,
    )


@pytest.fixture
def pool(tmp_path):
    d = tmp_path / "proj"
    d.mkdir()
    return d


# --------------------------------------------------------------------------
# Empty / no-op cases
# --------------------------------------------------------------------------


def test_empty_pool_returns_empty_report(tmp_path):
    rep = prune_pool(tmp_path)
    assert rep == PruneReport()


def test_under_cap_keeps_everything(pool):
    # 3 records, same bucket. N=5 → all kept.
    for d in (0, 1, 2):
        write(_attempt(days_old=d), project_dir=pool)
    rep = prune_pool(pool, n_per_bucket=5)
    assert rep.records_seen == 3
    assert rep.buckets == 1
    assert rep.records_kept == 3
    assert rep.records_removed == 0
    # All 3 still on disk.
    records = list(read_all(project_dir=pool, include_bundled=False))
    assert len(records) == 3


# --------------------------------------------------------------------------
# Per-bucket cap
# --------------------------------------------------------------------------


def test_same_bucket_keeps_n_most_recent(pool):
    # 7 records, same bucket. N=3 → keep 3 most recent.
    for d in range(7):
        write(_attempt(days_old=d), project_dir=pool)
    rep = prune_pool(pool, n_per_bucket=3)
    assert rep.records_seen == 7
    assert rep.records_kept == 3
    assert rep.records_removed == 4
    records = list(read_all(project_dir=pool, include_bundled=False))
    assert len(records) == 3
    # Days 0, 1, 2 (most recent) survive.
    ages = sorted(
        (datetime(2026, 6, 5, tzinfo=timezone.utc)
         - datetime.fromisoformat(r.timestamp)).days
        for r in records
    )
    assert ages == [0, 1, 2]


def test_distinct_buckets_each_get_their_own_cap(pool):
    """3 buckets (different exploit_code) × 4 records each, N=2.
    Each bucket keeps its 2 most recent."""
    for bucket_code in ("a();", "b();", "c();"):
        for d in range(4):
            write(_attempt(code=bucket_code, days_old=d), project_dir=pool)
    rep = prune_pool(pool, n_per_bucket=2)
    assert rep.records_seen == 12
    assert rep.buckets == 3
    assert rep.records_kept == 6        # 2 per bucket × 3 buckets
    assert rep.records_removed == 6


def test_bucket_key_finding_id(pool):
    """Different finding_id → different buckets."""
    for fid in ("FND-A", "FND-B"):
        for d in range(4):
            write(_attempt(finding_id=fid, days_old=d), project_dir=pool)
    rep = prune_pool(pool, n_per_bucket=2)
    assert rep.buckets == 2
    assert rep.records_removed == 4     # 2 per bucket pruned


def test_bucket_key_exploit_code(pool):
    """Same finding_id but different exploit_code → different buckets.
    This is the dedup semantic the plan calls for: an operator who
    re-fired and got a NEW exploit shouldn't lose the old one even
    though they share a finding_id."""
    for code in ("attempt-1", "attempt-2"):
        for d in range(4):
            write(_attempt(code=code, days_old=d), project_dir=pool)
    rep = prune_pool(pool, n_per_bucket=2)
    assert rep.buckets == 2
    assert rep.records_kept == 4


def test_bucket_key_model(pool):
    """Same finding + same exploit but different model → different
    buckets. A Haiku exploit and an Opus exploit don't dedup
    together — comparing models is part of why the corpus exists."""
    for model in ("claude-haiku-4-5", "claude-opus-4-7"):
        for d in range(4):
            write(_attempt(model=model, days_old=d), project_dir=pool)
    rep = prune_pool(pool, n_per_bucket=2)
    assert rep.buckets == 2
    assert rep.records_kept == 4


# --------------------------------------------------------------------------
# Non-sandbox records (CodeQL)
# --------------------------------------------------------------------------


def test_codeql_records_bucket_by_finding_id(pool):
    """CodeQL records have no exploit_code; bucket key uses '' for the
    code SHA, so multiple CodeQL records on the same finding+model
    bucket together."""
    for d in range(4):
        a = LabeledAttempt(
            finding_id="QL-FND",
            finding_signature=compute_finding_signature(
                cwe="CWE-787", file_path="x.c", function="f", line=0,
            ),
            cwe="CWE-787", outcome="success",
            codeql_evidence=CodeQLEvidence(
                query_ql=f"import x; /* attempt {d} */",
                before_count=1, after_count=0,
                is_sound=True,
            ),
            producing_model="m", prompt_version="v3",
            iterations=0, cost_usd=0.00,
            timestamp=(datetime(2026, 6, 5, tzinfo=timezone.utc)
                       - timedelta(days=d)).isoformat(),
        )
        write(a, project_dir=pool)
    rep = prune_pool(pool, n_per_bucket=2)
    assert rep.buckets == 1
    assert rep.records_kept == 2


# --------------------------------------------------------------------------
# Dry run
# --------------------------------------------------------------------------


def test_dry_run_does_not_touch_disk(pool):
    for d in range(7):
        write(_attempt(days_old=d), project_dir=pool)
    rep = prune_pool(pool, n_per_bucket=3, dry_run=True)
    # Stats reflect what WOULD have happened.
    assert rep.records_removed == 4
    assert len(rep.removed_paths) == 4
    # Disk untouched.
    records = list(read_all(project_dir=pool, include_bundled=False))
    assert len(records) == 7
    # Listed paths still exist.
    for p in rep.removed_paths:
        assert p.exists()


# --------------------------------------------------------------------------
# Corrupt records skipped
# --------------------------------------------------------------------------


def test_corrupt_records_skipped_not_counted(pool):
    # 4 good + 1 corrupt; cap N=2 → kept 2, removed 2 from the 4.
    for d in range(4):
        write(_attempt(days_old=d), project_dir=pool)
    # Plant a junk file in some sig dir.
    sig_dir = next(
        (pool / "labeled_attempts").iterdir()
    )
    (sig_dir / "sandbox-corrupt.json").write_text("{nope")

    rep = prune_pool(pool, n_per_bucket=2)
    # Only the 4 readable records counted.
    assert rep.records_seen == 4
    assert rep.records_removed == 2
    # Corrupt file untouched — pruning doesn't garbage-collect arbitrary
    # garbage, only known-good records.
    assert (sig_dir / "sandbox-corrupt.json").exists()


# --------------------------------------------------------------------------
# Empty signature-dirs cleaned up
# --------------------------------------------------------------------------


def test_empty_signature_dirs_removed_after_prune(pool):
    """A signature-dir that has all its records pruned away gets its
    directory removed — keeps the pool tidy as it grows."""
    # 4 records in a single signature dir, cap N=0 → all removed.
    for d in range(4):
        write(_attempt(days_old=d), project_dir=pool)
    sig_dir_count_before = sum(
        1 for p in (pool / "labeled_attempts").iterdir() if p.is_dir()
    )
    assert sig_dir_count_before == 1

    prune_pool(pool, n_per_bucket=0)
    sig_dirs_after = [
        p for p in (pool / "labeled_attempts").iterdir() if p.is_dir()
    ]
    assert sig_dirs_after == []


# --------------------------------------------------------------------------
# Removed paths returned
# --------------------------------------------------------------------------


def test_removed_paths_returned_and_match_disk(pool):
    for d in range(5):
        write(_attempt(days_old=d), project_dir=pool)
    rep = prune_pool(pool, n_per_bucket=2)
    # 3 oldest removed.
    assert len(rep.removed_paths) == 3
    for p in rep.removed_paths:
        assert not p.exists()
    # The 2 newest still on disk.
    remaining = sorted(
        next(iter((pool / "labeled_attempts").iterdir())).glob("*.json")
    )
    assert len(remaining) == 2

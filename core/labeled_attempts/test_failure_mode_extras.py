"""Tests for recent_failure_summary + operator-annotation populator."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from core.labeled_attempts import (  # noqa: E402
    FailureMode,
    LabeledAttempt,
    SandboxEvidence,
    compute_finding_signature,
    recent_failure_summary,
    set_failure_mode,
    write,
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _attempt(
    *, finding_id: str = "FND-X",
    cwe: str = "CWE-787",
    outcome: str = "reasoned_failure",
    failure_mode: FailureMode | None = FailureMode.MODEL_REASONING_CEILING,
    days_old: int = 0,
    function: str = "f",
) -> LabeledAttempt:
    now = datetime(2026, 6, 4, tzinfo=timezone.utc)
    ts = (now - timedelta(days=days_old)).isoformat()
    return LabeledAttempt(
        finding_id=finding_id,
        finding_signature=compute_finding_signature(
            cwe=cwe, file_path="x.c", function=function, line=0,
        ),
        cwe=cwe,
        outcome=outcome,
        sandbox_evidence=SandboxEvidence(
            bytes_hash="a"*64, bytes_len=8,
            observed_outcome=(
                "sanitizer_report" if outcome == "success"
                else "no_obvious_effect"
            ),
            exploit_code=f"// {finding_id}",
            exploit_language="c",
        ),
        producing_model="m", prompt_version="v3",
        iterations=1, cost_usd=0.01,
        failure_mode=failure_mode,
        timestamp=ts,
    )


@pytest.fixture
def project_dir(tmp_path):
    d = tmp_path / "proj"
    d.mkdir()
    return d


# --------------------------------------------------------------------------
# recent_failure_summary
# --------------------------------------------------------------------------


def test_empty_pool_returns_empty_dict(project_dir):
    assert recent_failure_summary(
        "CWE-787", project_dir=project_dir, include_bundled=False,
    ) == {}


def test_only_classified_failures_counted(project_dir):
    """Successes don't count; unclassified failures (failure_mode=None)
    don't count either."""
    now = datetime(2026, 6, 4, tzinfo=timezone.utc)
    write(_attempt(
        finding_id="WIN", outcome="success",
        failure_mode=None,
    ), project_dir=project_dir)
    write(_attempt(
        finding_id="UNCLASSIFIED", function="g",
        outcome="reasoned_failure", failure_mode=None,
    ), project_dir=project_dir)
    write(_attempt(
        finding_id="A", function="h",
        failure_mode=FailureMode.COMPILE_FAILED,
    ), project_dir=project_dir)
    write(_attempt(
        finding_id="B", function="i",
        failure_mode=FailureMode.COMPILE_FAILED,
    ), project_dir=project_dir)
    write(_attempt(
        finding_id="C", function="j",
        failure_mode=FailureMode.MODEL_REASONING_CEILING,
    ), project_dir=project_dir)

    counts = recent_failure_summary(
        "CWE-787", project_dir=project_dir,
        include_bundled=False, now=now,
    )
    assert counts == {
        FailureMode.COMPILE_FAILED: 2,
        FailureMode.MODEL_REASONING_CEILING: 1,
    }


def test_cwe_filter(project_dir):
    """Only the requested CWE is counted."""
    now = datetime(2026, 6, 4, tzinfo=timezone.utc)
    write(_attempt(
        finding_id="A", cwe="CWE-787",
        failure_mode=FailureMode.COMPILE_FAILED,
    ), project_dir=project_dir)
    write(_attempt(
        finding_id="B", cwe="CWE-416", function="g",
        failure_mode=FailureMode.COMPILE_FAILED,
    ), project_dir=project_dir)

    counts_787 = recent_failure_summary(
        "CWE-787", project_dir=project_dir,
        include_bundled=False, now=now,
    )
    counts_416 = recent_failure_summary(
        "CWE-416", project_dir=project_dir,
        include_bundled=False, now=now,
    )
    assert counts_787 == {FailureMode.COMPILE_FAILED: 1}
    assert counts_416 == {FailureMode.COMPILE_FAILED: 1}


def test_recency_window_filters_old_records(project_dir):
    """Records older than window_days are not counted."""
    now = datetime(2026, 6, 4, tzinfo=timezone.utc)
    write(_attempt(
        finding_id="OLD", function="a",
        failure_mode=FailureMode.COMPILE_FAILED,
        days_old=60,
    ), project_dir=project_dir)
    write(_attempt(
        finding_id="RECENT", function="b",
        failure_mode=FailureMode.COMPILE_FAILED,
        days_old=5,
    ), project_dir=project_dir)

    # Default window is 30 days.
    counts = recent_failure_summary(
        "CWE-787", project_dir=project_dir,
        include_bundled=False, now=now,
    )
    assert counts == {FailureMode.COMPILE_FAILED: 1}


def test_cwe_case_insensitive(project_dir):
    now = datetime(2026, 6, 4, tzinfo=timezone.utc)
    write(_attempt(failure_mode=FailureMode.NETWORK_RACE),
           project_dir=project_dir)
    counts = recent_failure_summary(
        "cwe-787", project_dir=project_dir,
        include_bundled=False, now=now,
    )
    assert counts == {FailureMode.NETWORK_RACE: 1}


# --------------------------------------------------------------------------
# set_failure_mode
# --------------------------------------------------------------------------


def test_set_failure_mode_refines_classification(project_dir):
    """An UNKNOWN failure mode gets refined to MISSING_INIT by an
    operator after triage."""
    a = _attempt(failure_mode=FailureMode.UNKNOWN)
    [path] = write(a, project_dir=project_dir)

    updated = set_failure_mode(path, FailureMode.MISSING_INIT)
    assert updated.failure_mode == FailureMode.MISSING_INIT

    # Persisted to disk.
    blob = json.loads(path.read_text())
    assert blob["failure_mode"] == "missing_init"


def test_set_failure_mode_can_clear_to_none(project_dir):
    """An operator can clear a misclassification by setting None."""
    a = _attempt(failure_mode=FailureMode.NETWORK_RACE)
    [path] = write(a, project_dir=project_dir)

    updated = set_failure_mode(path, None)
    assert updated.failure_mode is None
    blob = json.loads(path.read_text())
    assert blob["failure_mode"] is None


def test_set_failure_mode_rejects_on_success_record(project_dir):
    """Cannot annotate a success record with a failure_mode — the
    schema's consistency check fires through from_dict before any
    write happens."""
    a = _attempt(outcome="success", failure_mode=None)
    [path] = write(a, project_dir=project_dir)
    original = path.read_text()

    with pytest.raises(ValueError, match="success.*failure_mode"):
        set_failure_mode(path, FailureMode.COMPILE_FAILED)

    # On-disk file must not be modified after a rejected annotation.
    assert path.read_text() == original


def test_set_failure_mode_nonexistent_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        set_failure_mode(tmp_path / "no-such-file.json", FailureMode.UNKNOWN)


def test_set_failure_mode_write_is_atomic(project_dir):
    """The temp-file dance leaves no .tmp residue after a successful
    update."""
    a = _attempt(failure_mode=FailureMode.UNKNOWN)
    [path] = write(a, project_dir=project_dir)

    set_failure_mode(path, FailureMode.SIZE_MISMATCH)
    # The signature directory should hold the record and nothing else.
    leftovers = [
        p for p in path.parent.iterdir()
        if p.name.endswith(".tmp") or ".tmp" in p.name
    ]
    assert leftovers == []


def test_set_failure_mode_preserves_other_fields(project_dir):
    """Annotation must not alter spine / oracle / provenance fields."""
    a = _attempt(
        finding_id="ORIG", failure_mode=FailureMode.UNKNOWN,
    )
    [path] = write(a, project_dir=project_dir)
    before = json.loads(path.read_text())

    set_failure_mode(path, FailureMode.PROTOCOL_GUESS)
    after = json.loads(path.read_text())

    # All fields except failure_mode unchanged.
    for key in before:
        if key == "failure_mode":
            continue
        assert before[key] == after[key], (
            f"field {key!r} mutated by set_failure_mode"
        )


# --------------------------------------------------------------------------
# Adversarial-review regressions (session 2026-06-04)
# --------------------------------------------------------------------------


def test_recent_failure_summary_rejects_nan_window(project_dir):
    """NaN comparisons return False, which would silently include
    every record in the pool. Defended at the entry."""
    import math
    write(_attempt(failure_mode=FailureMode.COMPILE_FAILED),
           project_dir=project_dir)
    with pytest.raises(ValueError, match="NaN"):
        recent_failure_summary(
            "CWE-787", project_dir=project_dir,
            include_bundled=False, window_days=math.nan,
        )


def test_recent_failure_summary_accepts_positive_inf(project_dir):
    """+inf is the legitimate 'no window' value — every record passes."""
    import math
    now = datetime(2026, 6, 4, tzinfo=timezone.utc)
    write(_attempt(
        days_old=1000, failure_mode=FailureMode.COMPILE_FAILED,
    ), project_dir=project_dir)
    counts = recent_failure_summary(
        "CWE-787", project_dir=project_dir,
        include_bundled=False, window_days=math.inf, now=now,
    )
    assert counts == {FailureMode.COMPILE_FAILED: 1}


def test_set_failure_mode_malformed_json_clean_error(project_dir):
    """A corrupt on-disk record (e.g. partial write from an interrupted
    operator) surfaces as ValueError, not raw JSONDecodeError. The
    file is NOT modified on rejection."""
    a = _attempt(failure_mode=FailureMode.UNKNOWN)
    [path] = write(a, project_dir=project_dir)
    path.write_text("{not valid json")
    pre = path.read_text()

    with pytest.raises(ValueError, match="not valid JSON"):
        set_failure_mode(path, FailureMode.COMPILE_FAILED)
    assert path.read_text() == pre


def test_set_failure_mode_symlink_does_not_overwrite_victim(
    project_dir, tmp_path,
):
    """A symlink at the annotation path resolves through the chain
    BUT os.replace at the end of _atomic_replace replaces the
    SYMLINK itself, not its target. Confirms the victim file the
    symlink points at stays intact."""
    a = _attempt(failure_mode=FailureMode.UNKNOWN)
    [real_path] = write(a, project_dir=project_dir)

    # Plant a legitimate-looking second record file (the "victim")
    # in a separate dir so it doesn't collide with the real one.
    other_attempt = _attempt(
        finding_id="OTHER", function="g",
        failure_mode=FailureMode.NETWORK_RACE,
    )
    [victim_path] = write(other_attempt, project_dir=project_dir)
    victim_original = victim_path.read_text()

    # Plant a symlink at a new path pointing at the victim.
    decoy_dir = (
        project_dir / "labeled_attempts" / ("c" * 32)
    )
    decoy_dir.mkdir()
    sym = decoy_dir / "link.json"
    os.symlink(victim_path, sym)

    set_failure_mode(sym, FailureMode.MISSING_INIT)

    # The victim file's contents are unchanged.
    assert victim_path.read_text() == victim_original
    # The symlink path is now a regular file with the updated content
    # (os.replace replaced the symlink itself).
    assert sym.is_file() and not sym.is_symlink()


def test_set_failure_mode_round_trip_through_read_all(project_dir):
    a = _attempt(failure_mode=FailureMode.UNKNOWN)
    [path] = write(a, project_dir=project_dir)

    set_failure_mode(path, FailureMode.MISSING_INIT)

    from core.labeled_attempts import read_all
    [restored] = list(read_all(
        project_dir=project_dir, include_bundled=False,
    ))
    assert restored.failure_mode == FailureMode.MISSING_INIT

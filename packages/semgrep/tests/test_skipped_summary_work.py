"""Skipped-path summaries preserve exact output without formatting discarded paths."""

import random
from collections import defaultdict

import pytest

from packages.semgrep import models


def reference_summary(entries):
    """Simple materialized reference, used only on small generated inputs."""
    grouped = defaultdict(list)
    counts = defaultdict(int)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        reason = models.escape_nonprintable(str(entry.get("reason") or "unspecified"))[:100]
        path = models.escape_nonprintable(str(entry.get("path") or ""))[:300]
        counts[reason] += 1
        if path:
            grouped[reason].append(path)
    if not counts:
        return {}
    selected = sorted(counts, key=lambda reason: (-counts[reason], reason))[:12]
    return {"total": sum(counts.values()),
            "reasons": {reason: {"count": counts[reason], "sample": grouped[reason][:5]}
                        for reason in selected},
            "reasons_truncated": max(0, len(counts) - 12)}


@pytest.mark.parametrize("seed", [0, 1, 17, 999])
def test_generated_metadata_matches_exact_reference_without_mutation(seed):
    rng = random.Random(seed)
    reasons = [None, "", "same\n", "same\\x0a", "x" * 110,
               *(f"reason-{i}" for i in range(25))]
    entries = []
    for i in range(400):
        if i % 19 == 0:
            entries.append(None)
        else:
            entries.append({"reason": rng.choice(reasons),
                            "path": rng.choice([None, "", f"file-{i}\x1b.py", "é" * 350])})
    import copy
    original = copy.deepcopy(entries)
    assert models._summarise_skipped(entries) == reference_summary(entries)
    assert entries == original


def track_path_formatting(monkeypatch):
    original = models.escape_nonprintable
    formatted = []

    def escape(value):
        if value.startswith("/target/"):
            formatted.append(value)
        return original(value)

    monkeypatch.setattr(models, "escape_nonprintable", escape)
    return formatted


def test_full_sample_bucket_does_not_format_remaining_paths(monkeypatch):
    entries = [{"reason": "excluded", "path": f"/target/file-{i}.py"} for i in range(2000)]
    formatted = track_path_formatting(monkeypatch)
    result = models._summarise_skipped(entries)
    assert result == {"total": 2000, "reasons_truncated": 0,
                      "reasons": {"excluded": {"count": 2000,
                      "sample": [f"/target/file-{i}.py" for i in range(5)]}}}
    assert formatted == [entry["path"] for entry in entries[:5]]


def test_discarded_reasons_never_format_their_paths(monkeypatch):
    entries = [{"reason": f"reason-{i:03d}", "path": f"/target/{i}/" + "x" * 400}
               for i in reversed(range(64))]
    expected = reference_summary(entries)
    formatted = track_path_formatting(monkeypatch)
    result = models._summarise_skipped(entries)
    assert list(result["reasons"]) == [f"reason-{i:03d}" for i in range(12)]
    assert result["total"] == 64 and result["reasons_truncated"] == 52
    selected = [entry["path"] for entry in entries if entry["reason"] in result["reasons"]]
    assert formatted == [path[:300] for path in selected]
    assert result == expected


def test_late_frequent_reason_keeps_earliest_samples():
    entries = [{"reason": f"rare-{i:03d}", "path": f"r{i}.py"} for i in range(100)]
    entries += [{"reason": "common", "path": f"c{i}.py"} for i in range(7)]
    result = models._summarise_skipped(entries)
    assert next(iter(result["reasons"])) == "common"
    assert result["reasons"]["common"] == {"count": 7, "sample": [f"c{i}.py" for i in range(5)]}
    assert result["total"] == 107 and result["reasons_truncated"] == 89

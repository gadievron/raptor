"""Invalid API budgets must refuse before any corpus work is selected."""
from contextlib import closing
import sqlite3

import pytest

from core.dataflow import cvefix_walk as module


def test_nan_limit_cannot_process_the_entire_walk(tmp_path, monkeypatch):
    pairs = [module.CveFixPair("CVE-FIXTURE", "CWE-79", "https://example.invalid/fixture", "Python", str(i), "parent") for i in range(3)]
    monkeypatch.setattr(module, "load_pairs", lambda *a, **k: pairs)
    processed = []

    def owned_process(pair, **kwargs):
        processed.append(pair.fix_hash)
        return module.WalkResult(pair.fix_hash, "ok", 1, 0)

    monkeypatch.setattr(module, "process_pair", owned_process)
    failure = None
    try:
        module.walk(tmp_path / "metadata", tmp_path / "results.sqlite", work_dir=tmp_path / "work", limit=float("nan"), log=lambda *_args: None)
    except ValueError as exc:
        failure = exc
    assert processed == [], "invalid budget processed every available pair"
    assert failure is not None


@pytest.mark.parametrize("limit", [float("nan"), float("inf"), -1, 1.5, True, "1"],
                         ids=["nan", "infinite", "negative", "fractional", "boolean", "text"])
@pytest.mark.parametrize("entry", ["walk", "promote"])
def test_invalid_limits_refuse_before_database_access(tmp_path, limit, entry):
    results = tmp_path / "missing-parent" / "results.sqlite"
    work = tmp_path / "work"
    with pytest.raises(ValueError, match="limit"):
        if entry == "walk":
            module.walk(tmp_path / "missing-metadata", results, work_dir=work, limit=limit)
        else:
            module.promote_misses(results, work_dir=work, limit=limit)
    assert not results.exists() and not work.exists()


@pytest.mark.parametrize("limit,expected", [(0, 0), (1, 1), (None, 3)], ids=["zero", "one", "unlimited"])
@pytest.mark.parametrize("entry", ["walk", "promote"])
def test_integer_budgets_keep_existing_processing_counts(tmp_path, monkeypatch, limit, expected, entry):
    pairs = [module.CveFixPair("CVE-FIXTURE", "CWE-79", "https://example.invalid/fixture", "Java", str(i), "parent") for i in range(3)]
    processed = []

    def owned_process(pair, **kwargs):
        processed.append(pair.fix_hash)
        return module.WalkResult(pair.fix_hash, "ok", 1, 0)

    monkeypatch.setattr(module, "process_pair", owned_process)
    results = tmp_path / "results.sqlite"
    if entry == "walk":
        monkeypatch.setattr(module, "load_pairs", lambda *a, **k: pairs)
        summary = module.walk(tmp_path / "unused-metadata", results, work_dir=tmp_path / "work", limit=limit, log=lambda *_: None)
        assert summary["total"] == expected
    else:
        with closing(sqlite3.connect(results)) as connection:
            connection.execute(module._SCHEMA)
            for pair in pairs:
                module._record(connection, pair, module.WalkResult(pair.fix_hash, "ok", 0, 0))
        summary = module.promote_misses(results, work_dir=tmp_path / "work", limit=limit, log=lambda *_: None)
        assert summary == {"candidates": 3, "promoted": expected}
    assert len(processed) == expected

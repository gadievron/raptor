"""Coverage-store budget class: over-budget load degradation is loud
and save-refusing; compaction is the remedial path."""

from __future__ import annotations

import json
import logging

import pytest

import core.coverage.store as store_mod
from core.coverage.store import (
    CoverageStore,
    StoreWriteOverBudget,
    compact_store_file,
)


def _store_doc(n_files: int = 3) -> dict:
    return {
        "version": 1,
        "target": "/t",
        "files": {
            f"src/f{i}.c": {
                "total_lines": 100,
                "sloc": 80,
                "tools": {"semgrep": [[1, 50]]},
                "findings": [],
                "provenance": {},
            }
            for i in range(n_files)
        },
    }


def test_over_budget_load_is_loud_and_refuses_save(tmp_path, monkeypatch,
                                                   caplog):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(), indent=2))
    monkeypatch.setattr(store_mod, "_MAX_STORE_BYTES", 64)
    original = path.read_bytes()
    with caplog.at_level(logging.ERROR, logger="core.coverage.store"):
        store = CoverageStore(path)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "read budget" in joined
    assert "raptor-audit coverage compact" in joined
    # Degraded to empty, and the durable union is protected: save
    # refuses instead of replacing it with the empty view.
    assert store.files() == []
    with pytest.raises(StoreWriteOverBudget) as exc:
        store.save()
    assert "compact" in str(exc.value)
    assert path.read_bytes() == original


def test_corrupt_store_keeps_recovery_semantics(tmp_path):
    path = tmp_path / "coverage.json"
    path.write_text("{broken json")
    store = CoverageStore(path)
    # Corrupt (not over-budget) stores keep the historical contract:
    # degrade to empty and remain saveable (backfill reconstructs).
    store.mark("src/a.c", 1, 5, "semgrep")
    store.save()
    assert json.loads(path.read_text())["files"]["src/a.c"]


def test_save_emits_compact_form(tmp_path):
    path = tmp_path / "coverage.json"
    store = CoverageStore(path, target="/t")
    store.mark("src/a.c", 1, 5, "semgrep")
    store.save()
    text = path.read_text()
    assert "\n  " not in text          # no indented lines
    assert json.loads(text)["files"]["src/a.c"]


def test_compact_store_file_shrinks_and_backs_up(tmp_path):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(8), indent=2))
    before, after = compact_store_file(path)
    assert after < before
    backup = tmp_path / "coverage.json.pre-compact"
    assert backup.is_file()
    # Compacted store loads healthy.
    store = CoverageStore(path)
    assert len(store.files()) == 8


def test_compact_refuses_when_still_over_budget(tmp_path, monkeypatch):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_store_doc(8), indent=2))
    original = path.read_bytes()
    monkeypatch.setattr(store_mod, "_MAX_STORE_BYTES", 64)
    with pytest.raises(StoreWriteOverBudget):
        compact_store_file(path)
    assert path.read_bytes() == original
    assert not (tmp_path / "coverage.json.pre-compact").exists()


def test_compact_missing_file_raises_value_error(tmp_path):
    with pytest.raises(ValueError):
        compact_store_file(tmp_path / "coverage.json")

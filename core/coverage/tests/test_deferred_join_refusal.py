"""Deferred scanner-overlay joins are target-bound (fail-closed).

A ``scanner_coverage.join == "deferred"`` record carries RAW rows a
project-less scan never validated against any inventory. Importing
them by name into an arbitrary checklist would let a record from one
tree mint marks in a different project whose inventory shares
``(file, function)`` names — so the import refuses unless the
record's recorded ``target_path`` names the same tree as the joining
checklist's, and refuses when either side is missing.
"""

from __future__ import annotations

import json

from core.coverage.importer import _deferred_join_refused, import_run_dir
from core.coverage.store import CoverageStore

_CHECKLIST = {
    "target_path": "/scanned/tree",
    "files": [
        {"path": "src/a.c", "lines": 100, "items": [
            {"name": "f1", "line_start": 1, "line_end": 20,
             "kind": "function"},
        ]},
    ],
}


def _record(join: str, target: str | None) -> dict:
    sc: dict = {"join": join, "units_analyzed": 1}
    if target is not None:
        sc["target_path"] = target
    return {
        "tool": "openant", "timestamp": "t",
        "functions_analysed": [{"file": "src/a.c", "function": "f1"}],
        "scanner_coverage": sc,
    }


def test_matching_target_joins():
    assert not _deferred_join_refused(
        _record("deferred", "/scanned/tree"), "/scanned/tree")
    # normpath-equivalent spellings bind too.
    assert not _deferred_join_refused(
        _record("deferred", "/scanned//tree/"), "/scanned/tree")


def test_wrong_target_refused():
    assert _deferred_join_refused(
        _record("deferred", "/other/project"), "/scanned/tree")


def test_missing_provenance_refused_fail_closed():
    # Record without a target, and checklist without one: both refuse.
    assert _deferred_join_refused(_record("deferred", None), "/scanned/tree")
    assert _deferred_join_refused(
        _record("deferred", "/scanned/tree"), None)


def test_inventory_joined_and_plain_records_pass_through():
    assert not _deferred_join_refused(
        _record("inventory", "/other/project"), "/scanned/tree")
    assert not _deferred_join_refused(
        {"tool": "llm", "functions_analysed": []}, "/scanned/tree")


def test_import_run_dir_enforces_the_refusal(tmp_path):
    run = tmp_path / "run1"
    run.mkdir()
    (run / "coverage-openant.json").write_text(
        json.dumps(_record("deferred", "/other/project")),
        encoding="utf-8")
    store = CoverageStore(tmp_path / "cov.json", target="zip:x")
    marks = import_run_dir(store, run, _CHECKLIST)
    assert marks == 0
    assert store.tool_coverage_of_range("src/a.c", 1, 20) == {}

    # Control: the same record bound to THIS tree joins.
    (run / "coverage-openant.json").write_text(
        json.dumps(_record("deferred", "/scanned/tree")),
        encoding="utf-8")
    store2 = CoverageStore(tmp_path / "cov2.json", target="zip:x")
    assert import_run_dir(store2, run, _CHECKLIST) == 1
    assert "openant" in store2.tool_coverage_of_range("src/a.c", 1, 20)

"""Store-lane row-authority tiering in ``import_functions_analysed``.

The store mark is the OTHER durable review-suppression surface beside
the audit gap fold, and coverage records live in target-writable
run/project directories. Pre-fix the importer marked every
``functions_analysed`` row under the record's review-grade tool label
— one planted ``coverage-llm.json`` row cleared its function from
every store-derived gap view. These tests pin the fold's three tiers
at the importer seam: verified rows import under the tool label,
unstamped rows only behind the exact current-source-hash gate (never
finding-class), everything else demotes to ``<tool>:machine`` —
examination extent kept, review credit withheld. Zero LLM calls.
"""

from __future__ import annotations

import pytest

from core.coverage import journal_mac
from core.coverage.importer import (
    _function_ranges,
    _inventory_paths,
    import_functions_analysed,
)
from core.coverage.journal import now_iso
from core.coverage.registry import classify
from core.coverage.store import CoverageStore
from core.coverage.store_summary import store_view
from core.staleness import hash_span

_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}
"""

_CHECKLIST = {
    "files": [
        {"path": "auth.c", "lines": 5, "items": [
            {"name": "check_pw", "line_start": 1, "line_end": 5,
             "kind": "function"},
        ]},
    ],
}


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture()
def target(tmp_path):
    t = tmp_path / "target"
    t.mkdir()
    (t / "auth.c").write_text(_SOURCE, encoding="utf-8")
    return t


def _import(tmp_path, target, rows, tool="llm"):
    store = CoverageStore(tmp_path / "coverage.json", target="zip:abc")
    record = {"tool": tool, "timestamp": now_iso(),
              "functions_analysed": rows}
    marked = import_functions_analysed(
        store, record, _function_ranges(_CHECKLIST),
        _inventory_paths(_CHECKLIST),
        checklist_target=str(target))
    return store, marked


def _reviewed(store):
    return store_view(store, _CHECKLIST)["functions_reviewed"]


def test_verified_row_imports_under_tool_label(tmp_path, target):
    row = {"file": "auth.c", "function": "check_pw"}
    row[journal_mac.TOKEN_KEY] = journal_mac.mint_coverage_row(row, "llm")
    store, marked = _import(tmp_path, target, [row])
    assert marked == 1
    assert "llm" in store.tool_coverage_of_range("auth.c", 1, 5)
    assert _reviewed(store) == 1


def test_planted_hashless_row_demotes_to_machine_tier(tmp_path, target):
    """The PoC at the store seam: extent survives (the residual view
    sees the mark), review credit does not."""
    store, marked = _import(
        tmp_path, target, [{"file": "auth.c", "function": "check_pw"}])
    assert marked == 1
    tools = store.tool_coverage_of_range("auth.c", 1, 5)
    assert "llm:machine" in tools
    assert "llm" not in tools
    assert _reviewed(store) == 0


def test_unstamped_row_with_exact_hash_keeps_tool_label(tmp_path, target):
    """The tolerant-reader compromise, same as the fold: pre-MAC
    legacy rows keep credit behind positive source evidence."""
    row = {"file": "auth.c", "function": "check_pw",
           "hash": hash_span(target / "auth.c", 1, 5)}
    store, _ = _import(tmp_path, target, [row])
    assert "llm" in store.tool_coverage_of_range("auth.c", 1, 5)
    assert _reviewed(store) == 1


def test_unstamped_row_with_hash_prefix_demotes(tmp_path, target):
    full = hash_span(target / "auth.c", 1, 5)
    row = {"file": "auth.c", "function": "check_pw", "hash": full[:8]}
    store, _ = _import(tmp_path, target, [row])
    assert "llm:machine" in store.tool_coverage_of_range("auth.c", 1, 5)
    assert _reviewed(store) == 0


def test_unstamped_finding_class_row_demotes_despite_hash(
    tmp_path, target,
):
    """Same rule as both gap-fold lanes: a finding-class row earns
    review credit only when verified — hash-tier credit would retire
    a function whose claimed finding no consumer surfaces."""
    for status in ("finding", "suspicious"):
        row = {"file": "auth.c", "function": "check_pw",
               "status": status,
               "hash": hash_span(target / "auth.c", 1, 5)}
        store, _ = _import(tmp_path, target, [row])
        assert "llm:machine" in store.tool_coverage_of_range(
            "auth.c", 1, 5), status
        assert _reviewed(store) == 0, status


def test_tampered_row_demotes(tmp_path, target):
    row = {"file": "auth.c", "function": "check_pw", "status": "error"}
    row[journal_mac.TOKEN_KEY] = journal_mac.mint_coverage_row(row, "llm")
    row["status"] = "clean"  # content no longer matches the token
    store, _ = _import(tmp_path, target, [row])
    assert "llm:machine" in store.tool_coverage_of_range("auth.c", 1, 5)
    assert _reviewed(store) == 0


def test_scanned_grade_records_are_not_tiered(tmp_path, target):
    """Only review-grade labels tier — a scanned-depth label grants
    no review credit anyway, so demotion would be label churn."""
    store, marked = _import(
        tmp_path, target,
        [{"file": "auth.c", "function": "check_pw"}], tool="openant")
    assert marked == 1
    tools = store.tool_coverage_of_range("auth.c", 1, 5)
    assert "openant" in tools
    assert "openant:machine" not in tools


def test_machine_suffix_classifies_scanned_generically():
    """The demotion label the importer emits must never grade above
    scanned depth, for ANY review-grade base."""
    for base in ("llm", "audit", "journal", "mark"):
        assert classify(f"{base}:machine") == ("llm", "scanned"), base
    # Non-analysed bases are untouched by the suffix rule.
    assert classify("openant:machine") == ("llm", "scanned")
    assert classify("gcov:machine") == classify("gcov")

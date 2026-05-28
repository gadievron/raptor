"""Tests for tolerant coverage-store payload validation (schema.py)."""

from __future__ import annotations

import json

from core.coverage.schema import (
    check_version,
    normalise_loaded_files,
)
from core.coverage.store import CoverageStore


def test_valid_payload_passes_through():
    files = {
        "a.c": {
            "total_lines": 100, "sloc": 80,
            "tools": {"semgrep": [[1, 100]], "claude:audit": [[10, 20]]},
            "findings": [{"id": "F1", "line": 12, "retained": True}],
            "provenance": {"semgrep": {"version": "1.2"}},
        },
    }
    out = normalise_loaded_files(files)
    assert out == files


def test_canonical_shape_drops_unknown_keys():
    out = normalise_loaded_files({"a.c": {"junk": 1, "tools": {}}})
    assert set(out["a.c"]) == {
        "total_lines", "sloc", "tools", "findings", "provenance"}
    assert "junk" not in out["a.c"]


def test_malformed_intervals_dropped_good_kept():
    files = {"a.c": {"tools": {"semgrep": [[1, 10], [5], "x", [2, 3], [1, "y"]]}}}
    out = normalise_loaded_files(files)
    assert out["a.c"]["tools"]["semgrep"] == [[1, 10], [2, 3]]


def test_bool_interval_bound_rejected():
    # bool is an int subclass — must not be accepted as a line number.
    out = normalise_loaded_files({"a.c": {"tools": {"t": [[True, 5]]}}})
    assert out["a.c"]["tools"] == {}


def test_non_dict_tools_dropped():
    out = normalise_loaded_files({"a.c": {"tools": ["not", "a", "dict"]}})
    assert out["a.c"]["tools"] == {}


def test_tool_with_only_bad_intervals_omitted():
    out = normalise_loaded_files({"a.c": {"tools": {"t": ["bad"], "u": [[1, 2]]}}})
    assert out["a.c"]["tools"] == {"u": [[1, 2]]}


def test_finding_without_id_dropped():
    files = {"a.c": {"findings": [{"line": 5}, {"id": "F1", "line": 5}]}}
    out = normalise_loaded_files(files)
    assert out["a.c"]["findings"] == [{"id": "F1", "line": 5, "retained": True}]


def test_finding_id_coerced_and_line_validated():
    out = normalise_loaded_files(
        {"a.c": {"findings": [{"id": 7, "line": "nope"}]}})
    assert out["a.c"]["findings"] == [
        {"id": "7", "line": None, "retained": True}]


def test_non_int_line_counts_become_none():
    out = normalise_loaded_files(
        {"a.c": {"total_lines": "100", "sloc": True}})
    assert out["a.c"]["total_lines"] is None
    assert out["a.c"]["sloc"] is None


def test_non_dict_entry_dropped():
    out = normalise_loaded_files({"a.c": "garbage", "b.c": {"tools": {}}})
    assert "a.c" not in out
    assert "b.c" in out


def test_non_dict_files_returns_empty():
    assert normalise_loaded_files(["not", "a", "dict"]) == {}
    assert normalise_loaded_files(None) == {}


def test_non_string_path_key_dropped():
    out = normalise_loaded_files({5: {"tools": {}}, "a.c": {"tools": {}}})
    assert list(out) == ["a.c"]


def test_non_dict_provenance_defaults_empty():
    out = normalise_loaded_files({"a.c": {"provenance": "x"}})
    assert out["a.c"]["provenance"] == {}


def test_check_version_tolerates_newer(caplog):
    # Never raises; warns for a newer schema version.
    check_version(99, 1, "store.json")
    check_version(1, 1, "store.json")
    check_version("bad", 1, "store.json")  # non-int: ignored, no raise


# --- integration: the store loads through the validator ---------------------


def test_store_loads_corrupt_json_as_empty(tmp_path):
    p = tmp_path / "coverage.json"
    p.write_text("{ this is not valid json ")
    s = CoverageStore(p)                       # must not raise
    assert s.files() == []
    assert s.who_checked("a.c", 1) == []


def test_store_loads_malformed_entry_keeps_valid(tmp_path):
    p = tmp_path / "coverage.json"
    p.write_text(json.dumps({
        "version": 1,
        "files": {
            "a.c": {"total_lines": 50, "tools": {"semgrep": [[1, 50]]},
                    "findings": [], "provenance": {}},
            "b.c": {"tools": {"semgrep": [[1, "oops"]]}},   # malformed interval
            "c.c": "not-an-object",                          # dropped entirely
        },
    }))
    s = CoverageStore(p)
    assert s.who_checked("a.c", 10) == ["semgrep"]
    assert s.who_checked("b.c", 10) == []      # malformed interval dropped
    assert "c.c" not in s.files()


def test_store_roundtrip_after_validation(tmp_path):
    p = tmp_path / "coverage.json"
    s = CoverageStore(p, target="git:abc")
    s.mark("a.c", 1, 20, "semgrep")
    s.set_file_meta("a.c", total_lines=40)
    s.save()
    reloaded = CoverageStore(p)
    assert reloaded.file_coverage("a.c") == 50.0
    assert reloaded.who_checked("a.c", 5) == ["semgrep"]

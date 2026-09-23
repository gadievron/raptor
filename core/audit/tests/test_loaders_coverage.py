"""load_coverage_records: per-tool records + legacy single-file.

Pre-fix the orchestrator's loader read only the legacy
``coverage-record.json`` (which no modern producer writes), so record
priority tiers and ``--mark`` suppression were inert on every modern run.
"""

from __future__ import annotations

import json

from core.audit.loaders import load_coverage_records


def test_loads_per_tool_records(tmp_path):
    (tmp_path / "coverage-llm.json").write_text(json.dumps({
        "tool": "llm",
        "functions_analysed": [{"file": "src/a.c", "function": "parse"}],
    }))
    (tmp_path / "coverage-read.json").write_text(json.dumps({
        "tool": "read", "files_examined": ["src/a.c"],
    }))
    records = load_coverage_records(tmp_path)
    assert {r["tool"] for r in records} == {"llm", "read"}


def test_legacy_record_still_loads(tmp_path):
    (tmp_path / "coverage-record.json").write_text(json.dumps({
        "tool": "semgrep",
        "files": {"src/a.c": {"functions": {"parse": {}}}},
    }))
    records = load_coverage_records(tmp_path)
    assert len(records) == 1
    assert records[0]["tool"] == "semgrep"


def test_list_shaped_legacy_splices_flat(tmp_path):
    (tmp_path / "coverage-record.json").write_text(json.dumps([
        {"tool": "semgrep", "files": {}},
        {"tool": "codeql", "files": {}},
    ]))
    records = load_coverage_records(tmp_path)
    assert {r["tool"] for r in records} == {"semgrep", "codeql"}


def test_per_tool_records_shadow_legacy(tmp_path):
    # load_records semantics: the legacy single file is a FALLBACK —
    # it is not merged when per-tool records exist (avoids the
    # double-count its glob exclusion exists to prevent).
    (tmp_path / "coverage-llm.json").write_text(json.dumps({
        "tool": "llm",
        "functions_analysed": [{"file": "src/a.c", "function": "parse"}],
    }))
    (tmp_path / "coverage-record.json").write_text(json.dumps(
        {"tool": "semgrep", "files": {}},
    ))
    records = load_coverage_records(tmp_path)
    assert {r["tool"] for r in records} == {"llm"}


def test_empty_and_malformed_tolerated(tmp_path):
    assert load_coverage_records(tmp_path) == []
    (tmp_path / "coverage-record.json").write_text("{not json")
    assert load_coverage_records(tmp_path) == []


class TestFuzzCoverageShapeGate:
    """coverage-fuzz.json is a run-dir artifact (LLM-adjacent,
    tamperable, or simply malformed) — one list-shaped file made
    every review of a paid run raise AttributeError at per-function
    context assembly. Shape-gate at the loader and tolerate non-dict
    containers in the per-function reader."""

    def test_list_shaped_artifact_loads_as_none(self, tmp_path):
        from core.audit.loaders import load_fuzz_coverage
        (tmp_path / "coverage-fuzz.json").write_text('["oops"]')
        assert load_fuzz_coverage(tmp_path) is None

    def test_scalar_artifact_loads_as_none(self, tmp_path):
        from core.audit.loaders import load_fuzz_coverage
        (tmp_path / "coverage-fuzz.json").write_text('"oops"')
        assert load_fuzz_coverage(tmp_path) is None

    def test_reader_tolerates_list_root(self):
        from core.audit.loaders import fuzz_coverage_for
        assert fuzz_coverage_for(["oops"], "a.c", "f") is None

    def test_reader_tolerates_non_dict_containers(self):
        from core.audit.loaders import fuzz_coverage_for
        assert fuzz_coverage_for({"files": ["oops"]}, "a.c", "f") is None
        assert fuzz_coverage_for(
            {"files": {"a.c": ["oops"]}}, "a.c", "f",
        ) is None
        assert fuzz_coverage_for(
            {"files": {"a.c": {"functions": ["oops"]}}}, "a.c", "f",
        ) is None

    def test_sibling_fallback_skips_list_shaped_artifact(self, tmp_path):
        from core.audit.loaders import load_fuzz_coverage_any
        own = tmp_path / "own"
        sib_bad = tmp_path / "sib_bad"
        sib_good = tmp_path / "sib_good"
        for d in (own, sib_bad, sib_good):
            d.mkdir()
        (sib_bad / "coverage-fuzz.json").write_text('["oops"]')
        (sib_good / "coverage-fuzz.json").write_text(
            '{"files": {"a.c": {"functions": {"f": {"hits": 3}}}}}',
        )
        data = load_fuzz_coverage_any(own, [sib_bad, sib_good])
        assert data and data["files"]["a.c"]["functions"]["f"]["hits"] == 3

    def test_well_shaped_artifact_still_reads(self, tmp_path):
        from core.audit.loaders import fuzz_coverage_for, load_fuzz_coverage
        (tmp_path / "coverage-fuzz.json").write_text(
            '{"files": {"a.c": {"functions": {"f": {"hits": 2}}}}}',
        )
        data = load_fuzz_coverage(tmp_path)
        assert fuzz_coverage_for(data, "a.c", "f") == {"hits": 2}

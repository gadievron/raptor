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

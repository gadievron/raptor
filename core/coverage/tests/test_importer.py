"""Tests for the Phase 3 backfill importer (per-run records + checked_by)."""

from __future__ import annotations

import json

from core.coverage.importer import (
    backfill,
    import_checked_by,
    import_findings,
    import_record,
    import_run_dir,
)
from core.coverage.store import CoverageStore


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc")


_CHECKLIST = {
    "files": [
        {"path": "a.c", "total_lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60,
             "checked_by": ["validate:stage-a"]},
        ]},
        {"path": "b.c", "total_lines": 50, "functions": [
            {"name": "g1", "line_start": 0, "line_end": 10},
        ]},
    ],
}


def test_import_checked_by_is_function_level_and_llm(tmp_path):
    s = _store(tmp_path)
    assert import_checked_by(s, _CHECKLIST) == 1     # only f2 has checked_by
    assert s.who_checked_function("a.c", 30, 60) == {"validate:stage-a": "full"}
    # validate:* classifies as llm, so f2 is NOT an llm gap; f1/g1 are.
    assert s.function_covered("a.c", 30, 60, category="llm") is True


def test_import_record_is_whole_file_and_skips_unknown(tmp_path):
    s = _store(tmp_path)
    tl = {"a.c": 100}
    rec = {"tool": "semgrep", "files_examined": ["a.c", "vendor/x.c"]}
    assert import_record(s, rec, tl) == 1            # a.c marked; vendor/x.c skipped (no extent)
    assert s.who_checked("a.c", 50) == ["semgrep"]
    assert s.who_checked("a.c", 99) == ["semgrep"]   # whole file [0, 99]
    assert s.who_checked("vendor/x.c", 0) == []


def test_load_run_findings_discovers_validation_excludes_sca(tmp_path):
    from core.coverage.importer import load_run_findings

    run = tmp_path / "agentic-1"
    (run / "validation").mkdir(parents=True)
    (run / "sca").mkdir()
    # agentic's validated code findings live under validation/
    (run / "validation" / "findings.json").write_text(json.dumps(
        {"findings": [{"id": "SARIF-0", "file": "/tmp/clone/parse.c", "line": 5}]}))
    # SCA (dependency-class) findings must NOT be pulled into source-function
    # coverage — they don't map to a function range.
    (run / "sca" / "findings.json").write_text(json.dumps(
        [{"finding_id": "CVE-2021-1", "file_path": "requirements.txt", "line": 3}]))
    found = load_run_findings(run)
    ids = {f.get("id") or f.get("finding_id") for f in found}
    assert "SARIF-0" in ids
    assert "CVE-2021-1" not in ids        # sca excluded by design


def test_absolute_scanner_paths_join_to_relative_inventory(tmp_path):
    # Regression: real scanners (semgrep) emit ABSOLUTE files_examined paths,
    # while the inventory keys on target-relative paths. Without normalisation
    # the join misses every file -> 0 marks. Findings carry absolute paths too.
    s = _store(tmp_path)
    checklist = {"files": [
        {"path": "src/auth.py", "lines": 40, "items": [
            {"name": "f1", "line_start": 1, "line_end": 20}]},
    ]}
    run = tmp_path / "scan-1"
    run.mkdir()
    (run / "coverage-semgrep.json").write_text(json.dumps({
        "tool": "semgrep",
        "files_examined": ["/abs/target/src/auth.py"],     # absolute
        "timestamp": "t"}))
    (run / "findings.json").write_text(json.dumps(
        [{"id": "SG1", "file": "/abs/target/src/auth.py", "line": 10}]))
    backfill(s, [run], checklist)
    assert s.who_checked("src/auth.py", 10) == ["semgrep"]          # joined
    assert s.function_verdict("src/auth.py", 1, 20) == "open"        # finding joined too


def test_file_level_coverage_uses_real_inventory_lines_field(tmp_path):
    # Regression: the inventory emits per-file `lines`, not `total_lines`
    # (the latter only appears in hand-built test checklists). Reading the
    # wrong key silently drops ALL file-level scanner coverage — caught only
    # against a real checklist. backfill must place whole-file marks here.
    s = _store(tmp_path)
    checklist = {"files": [
        {"path": "a.c", "lines": 40, "sloc": 30, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20}]},
    ]}
    run = tmp_path / "scan-1"
    run.mkdir()
    (run / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
    (run / "findings.json").write_text("[]")
    backfill(s, [run], checklist)
    assert s.who_checked("a.c", 10) == ["semgrep"]    # whole file marked
    # 1-based: the last inventory line (tl) is covered; phantom line 0 is not.
    assert s.who_checked("a.c", 40) == ["semgrep"]
    assert s.who_checked("a.c", 0) == []
    assert s.function_covered("a.c", 1, 20, category="static") is True


def test_import_run_dir_reads_per_tool_records(tmp_path):
    s = _store(tmp_path)
    run = tmp_path / "scan-1"
    run.mkdir()
    (run / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
    (run / "coverage-codeql.json").write_text(json.dumps(
        {"tool": "codeql", "files_examined": ["b.c"], "timestamp": "t"}))
    assert import_run_dir(s, run, _CHECKLIST) == 2
    assert s.who_checked("a.c", 10) == ["semgrep"]
    assert s.who_checked("b.c", 5) == ["codeql"]


def test_import_findings_sets_open_verdict(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 30, 60, "semgrep")         # f2 examined
    findings = [
        {"id": "F1", "file": "a.c", "line": 42},          # in f2
        {"file_path": "a.c", "start_line": 5},            # variant field names
        {"note": "no file"},                              # skipped
    ]
    assert import_findings(s, findings) == 2
    assert s.function_verdict("a.c", 30, 60) == "open"    # retained by default


def test_import_findings_retained_false_is_found_then_lost(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 30, 60, "semgrep")
    import_findings(s, [{"id": "F1", "file": "a.c", "line": 42}], retained=False)
    assert s.function_verdict("a.c", 30, 60) == "found_then_lost"


def test_backfill_imports_findings_for_verdict(tmp_path):
    s = _store(tmp_path)
    run = tmp_path / "scan-1"
    run.mkdir()
    (run / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
    (run / "findings.json").write_text(json.dumps(
        [{"id": "F1", "file": "a.c", "line": 42}]))      # lands in f2 [30,60]
    backfill(s, [run], _CHECKLIST)
    assert s.function_verdict("a.c", 30, 60) == "open"   # f2 has a retained finding
    assert s.function_verdict("a.c", 0, 20) == "clean"   # f1 examined, no finding


def test_backfill_unions_checked_by_and_records_then_gap(tmp_path):
    s = _store(tmp_path)
    run = tmp_path / "scan-1"
    run.mkdir()
    (run / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["a.c", "b.c"], "timestamp": "t"}))

    marks = backfill(s, [run], _CHECKLIST)
    assert marks == 3        # 1 checked_by (f2) + 2 record files (a.c, b.c)

    # file-level meta imported -> coverage % defined.
    assert s.file_coverage("a.c") == 100.0    # semgrep marked whole file

    # The /audit gap: f2 was LLM-reviewed (validate); f1 and g1 only have
    # static (semgrep) coverage -> they ARE the llm gap.
    assert s.unchecked_functions(_CHECKLIST, category="llm") == [
        ("a.c", "f1", 0),
        ("b.c", "g1", 0),
    ]
    # Nothing is a *total* gap -- semgrep touched every file.
    assert s.unchecked_functions(_CHECKLIST) == []

    # Persists.
    s.save()
    assert CoverageStore(tmp_path / "coverage.json").who_checked("a.c", 40) == [
        "semgrep", "validate:stage-a",
    ]

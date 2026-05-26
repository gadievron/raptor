"""Tests for the provenance feed (Phase 3, step e): stamping coverage with
who/what-version/when from a run's .raptor-run.json manifest."""

from __future__ import annotations

import json

from core.coverage.importer import backfill, run_provenance
from core.coverage.store import CoverageStore

_CHECKLIST = {
    "files": [
        {"path": "a.c", "total_lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
        ]},
    ],
}

_MANIFEST = {
    "timestamp": "2026-05-26T10:00:00Z",
    "manifest": {
        "engines": {"semgrep": "1.67.0"},
        "models": [{"provider": "google", "alias": "gemini-2.5-pro",
                    "resolved": "gemini-2.5-pro-002", "role": "analysis"}],
        "target": {"source": "archive", "archive_sha256": "abc123",
                   "archive_name": "proj.zip"},
        "source_control": {"base_sha": "deadbeef"},
        "deterministically_reproducible": True,
    },
}


def _run(tmp_path, name, tool, files, manifest=None):
    d = tmp_path / name
    d.mkdir()
    (d / f"coverage-{tool}.json").write_text(json.dumps(
        {"tool": tool, "files_examined": files, "timestamp": "t"}))
    if manifest is not None:
        (d / ".raptor-run.json").write_text(json.dumps(manifest))
    return d


def test_run_provenance_reads_manifest(tmp_path):
    run = _run(tmp_path, "scan-1", "semgrep", ["a.c"], manifest=_MANIFEST)
    prov = run_provenance(run)
    assert prov["engines"] == {"semgrep": "1.67.0"}
    assert prov["models"] == ["gemini-2.5-pro-002"]      # resolved snapshot
    assert prov["timestamp"] == "2026-05-26T10:00:00Z"
    assert prov["target"]["source"] == "archive"
    assert prov["framework_sha"] == "deadbeef"


def test_no_manifest_degrades_gracefully(tmp_path):
    run = _run(tmp_path, "scan-1", "semgrep", ["a.c"])   # no .raptor-run.json
    assert run_provenance(run) == {}


def test_scanner_coverage_stamped_with_engine_version(tmp_path):
    s = CoverageStore(tmp_path / "coverage.json")
    run = _run(tmp_path, "scan-1", "semgrep", ["a.c"], manifest=_MANIFEST)
    backfill(s, [run], _CHECKLIST)
    p = s.tool_provenance("a.c", "semgrep")
    assert p["version"] == "1.67.0"                      # engine version
    assert p["timestamp"] == "2026-05-26T10:00:00Z"
    assert p["target"]["source"] == "archive"
    assert p["framework_sha"] == "deadbeef"
    assert "models" not in p                             # scanner -> no model


def test_llm_coverage_stamped_with_resolved_model(tmp_path):
    s = CoverageStore(tmp_path / "coverage.json")
    run = _run(tmp_path, "agentic-1", "llm", ["a.c"], manifest=_MANIFEST)
    backfill(s, [run], _CHECKLIST)
    p = s.tool_provenance("a.c", "llm")
    assert p["models"] == ["gemini-2.5-pro-002"]         # resolved model = scorecard hook
    assert p["timestamp"] == "2026-05-26T10:00:00Z"
    assert "version" not in p                            # llm tool not in engines


def test_unstamped_when_no_manifest(tmp_path):
    s = CoverageStore(tmp_path / "coverage.json")
    run = _run(tmp_path, "scan-1", "semgrep", ["a.c"])   # no manifest
    backfill(s, [run], _CHECKLIST)
    assert s.who_checked("a.c", 5) == ["semgrep"]        # coverage still recorded
    assert s.tool_provenance("a.c", "semgrep") == {}     # just no provenance

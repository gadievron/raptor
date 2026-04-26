"""Tests for core.orchestration.understand_bridge — /understand → /validate pipeline handoff."""

import copy
import json
import os
import sys
import time
import unittest.mock
from pathlib import Path

import pytest

# core/orchestration/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.orchestration.understand_bridge import (
    find_understand_output,
    load_understand_context,
    enrich_checklist,
    normalize_context_map,
    TRACE_SOURCE_LABEL,
    _extract_hashes,
    _find_stale_files,
    _rank_candidates,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_CONTEXT_MAP = {
    "sources": [
        {"type": "http_route", "entry": "POST /api/query @ src/routes/query.py:34"},
    ],
    "sinks": [
        {"type": "db_query", "location": "src/db/query.py:89"},
    ],
    "trust_boundaries": [
        {"boundary": "JWT auth middleware", "check": "src/middleware/auth.py:12"},
    ],
    "meta": {
        "target": "/some/repo",
        "app_type": "web_app",
    },
    "entry_points": [
        {
            "id": "EP-001",
            "type": "http_route",
            "file": "src/routes/query.py",
            "line": 34,
            "accepts": "JSON body",
            "auth_required": True,
        },
    ],
    "sink_details": [
        {
            "id": "SINK-001",
            "type": "db_query",
            "file": "src/db/query.py",
            "line": 89,
            "reaches_from": ["EP-001"],
            "parameterized": False,
        },
    ],
    "boundary_details": [
        {
            "id": "TB-001",
            "type": "auth_check",
            "file": "src/middleware/auth.py",
            "line": 12,
            "covers": ["EP-001"],
            "gaps": "EP-002 bypasses this via direct import at src/admin/bulk.py:67",
        },
    ],
    "unchecked_flows": [
        {
            "entry_point": "EP-002",
            "sink": "SINK-001",
            "missing_boundary": "No auth check on admin bulk endpoint",
        },
    ],
}

MINIMAL_FLOW_TRACE = {
    "id": "TRACE-001",
    "name": "POST /api/query → db_query",
    "finding": "FIND-001",
    "steps": [
        {
            "step": 1,
            "type": "entry",
            "call_site": None,
            "definition": "src/routes/query.py:34",
            "description": "POST handler receives JSON body.",
            "tainted_var": "request.json['query']",
            "transform": "none",
            "confidence": "high",
        },
        {
            "step": 2,
            "type": "sink",
            "call_site": "src/services/query_service.py:31",
            "definition": "psycopg2.cursor.execute()",
            "description": "Raw SQL via f-string.",
            "tainted_var": "query_str",
            "confidence": "high",
            "sink_type": "db_query",
            "parameterized": False,
            "injectable": True,
        },
    ],
    "proximity": 9,
    "blockers": [],
    "attacker_control": {
        "level": "full",
        "what": "Full control over `query` field via POST body",
    },
    "summary": {
        "flow_confirmed": True,
        "verdict": "Direct SQLi — no parameterisation.",
    },
}

MINIMAL_CHECKLIST = {
    "generated_at": "2026-04-08T00:00:00",
    "target_path": "/some/repo",
    "total_files": 2,
    "total_functions": 4,
    "files": [
        {
            "path": "src/routes/query.py",
            "language": "python",
            "lines": 80,
            "sha256": "aaa",
            "functions": [
                {"name": "handle_query", "line_start": 34, "checked_by": []},
            ],
        },
        {
            "path": "src/db/query.py",
            "language": "python",
            "lines": 100,
            "sha256": "bbb",
            "functions": [
                {"name": "run_query", "line_start": 89, "checked_by": []},
            ],
        },
    ],
}


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2))


def _make_understand_dir(parent, name="understand-20260401-120000",
                         context_map=None, checklist=None):
    """Create a minimal understand run directory with metadata."""
    d = parent / name
    d.mkdir(parents=True, exist_ok=True)
    _write_json(d / "context-map.json", context_map or {"sources": []})
    # .raptor-run.json so infer_command_type works
    _write_json(d / ".raptor-run.json", {"version": 1, "command": "understand",
                                          "status": "completed"})
    if checklist:
        _write_json(d / "checklist.json", checklist)
    return d


# ---------------------------------------------------------------------------
# find_understand_output — 3-tier search
# ---------------------------------------------------------------------------

class TestFindUnderstandOutput:
    def test_tier1_local_context_map(self, tmp_path):
        """Tier 1: context-map.json co-located in validate dir (shared --out)."""
        validate_dir = tmp_path / "shared"
        validate_dir.mkdir()
        _write_json(validate_dir / "context-map.json", {"sources": []})

        result_dir, stale = find_understand_output(validate_dir)
        assert result_dir == validate_dir
        assert stale == set()

    def test_tier2_project_sibling(self, tmp_path):
        """Tier 2: understand run as sibling in same project dir."""
        project_dir = tmp_path / "project"
        validate_dir = project_dir / "validate-20260402-120000"
        validate_dir.mkdir(parents=True)

        _make_understand_dir(project_dir)

        result_dir, stale = find_understand_output(validate_dir)
        assert result_dir == project_dir / "understand-20260401-120000"

    def test_tier2_picks_newest_sibling(self, tmp_path):
        project_dir = tmp_path / "project"
        validate_dir = project_dir / "validate-20260403-120000"
        validate_dir.mkdir(parents=True)

        old = _make_understand_dir(project_dir, "understand-20260401-120000")
        time.sleep(0.01)
        new = _make_understand_dir(project_dir, "understand-20260402-120000")

        result_dir, stale = find_understand_output(validate_dir)
        assert result_dir == new

    def test_tier3_global_out_by_target_path(self, tmp_path, monkeypatch):
        """Tier 3: scan out/ matching by checklist target_path."""
        out_root = tmp_path / "out"
        out_root.mkdir()

        # Monkeypatch RaptorConfig to use our tmp out/
        monkeypatch.setattr("core.config.RaptorConfig.get_out_dir",
                            staticmethod(lambda: out_root))

        _make_understand_dir(
            out_root, "understand_20260401_120000",
            checklist={"target_path": "/tmp/vulns", "files": []},
        )

        # validate_dir outside out/ with no siblings
        validate_dir = tmp_path / "validate-run"
        validate_dir.mkdir()

        result_dir, stale = find_understand_output(validate_dir, target_path="/tmp/vulns")
        assert result_dir == out_root / "understand_20260401_120000"

    def test_tier3_no_match_for_wrong_target(self, tmp_path, monkeypatch):
        out_root = tmp_path / "out"
        out_root.mkdir()

        monkeypatch.setattr("core.config.RaptorConfig.get_out_dir",
                            staticmethod(lambda: out_root))

        _make_understand_dir(
            out_root, "understand_20260401_120000",
            checklist={"target_path": "/tmp/vulns", "files": []},
        )

        validate_dir = tmp_path / "validate-run"
        validate_dir.mkdir()

        result_dir, stale = find_understand_output(validate_dir, target_path="/tmp/other")
        assert result_dir is None

    def test_returns_none_when_no_candidates(self, tmp_path, monkeypatch):
        out_root = tmp_path / "empty-out"
        out_root.mkdir()
        monkeypatch.setattr("core.config.RaptorConfig.get_out_dir",
                            staticmethod(lambda: out_root))

        validate_dir = tmp_path / "validate-run"
        validate_dir.mkdir()

        result_dir, stale = find_understand_output(validate_dir, target_path="/tmp/vulns")
        assert result_dir is None

    def test_ignores_dirs_without_context_map(self, tmp_path):
        project_dir = tmp_path / "project"
        validate_dir = project_dir / "validate-20260402-120000"
        validate_dir.mkdir(parents=True)

        # understand dir exists but has no context-map.json
        empty = project_dir / "understand-20260401-120000"
        empty.mkdir()
        _write_json(empty / ".raptor-run.json", {"version": 1, "command": "understand"})

        result_dir, stale = find_understand_output(validate_dir)
        assert result_dir is None

    def test_ignores_non_understand_dirs(self, tmp_path):
        project_dir = tmp_path / "project"
        validate_dir = project_dir / "validate-20260402-120000"
        validate_dir.mkdir(parents=True)

        scan = project_dir / "scan-20260401-120000"
        scan.mkdir()
        _write_json(scan / "context-map.json", {"sources": []})
        _write_json(scan / ".raptor-run.json", {"version": 1, "command": "scan"})

        result_dir, stale = find_understand_output(validate_dir)
        assert result_dir is None


# ---------------------------------------------------------------------------
# Hash freshness ranking
# ---------------------------------------------------------------------------

class TestHashFreshness:
    def test_extract_hashes(self):
        hashes = _extract_hashes(MINIMAL_CHECKLIST)
        assert hashes == {"src/routes/query.py": "aaa", "src/db/query.py": "bbb"}

    def test_stale_empty_when_matching(self, tmp_path):
        """On-disk files matching understand hashes → no stale files."""
        import hashlib
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("aaa")
        (target / "b.py").write_text("bbb")
        h1 = {
            "a.py": hashlib.sha256(b"aaa").hexdigest(),
            "b.py": hashlib.sha256(b"bbb").hexdigest(),
        }
        assert _find_stale_files(h1, str(target)) == set()

    def test_stale_detects_changed_files(self, tmp_path):
        """On-disk file differs from understand hash → returned in stale set."""
        import hashlib
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("aaa")
        (target / "b.py").write_text("MODIFIED")
        h1 = {
            "a.py": hashlib.sha256(b"aaa").hexdigest(),
            "b.py": hashlib.sha256(b"bbb").hexdigest(),  # original content
        }
        assert _find_stale_files(h1, str(target)) == {"b.py"}

    def test_stale_deleted_file_is_stale(self, tmp_path):
        """File in understand checklist but deleted from disk → in stale set."""
        import hashlib
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("aaa")
        h1 = {
            "a.py": hashlib.sha256(b"aaa").hexdigest(),
            "gone.py": hashlib.sha256(b"xyz").hexdigest(),
        }
        assert _find_stale_files(h1, str(target)) == {"gone.py"}

    def test_rank_prefers_fresh_over_newest(self, tmp_path):
        """A fresh older candidate beats a stale newer one."""
        import hashlib
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("current")
        disk_hash = hashlib.sha256(b"current").hexdigest()

        old_dir = tmp_path / "old"
        new_dir = tmp_path / "new"
        old_dir.mkdir()
        time.sleep(0.01)
        new_dir.mkdir()

        # old has matching hash, new has stale hash
        _write_json(old_dir / "checklist.json", {
            "files": [{"path": "a.py", "sha256": disk_hash}],
        })
        _write_json(new_dir / "checklist.json", {
            "files": [{"path": "a.py", "sha256": "STALE"}],
        })

        best_dir, stale = _rank_candidates([new_dir, old_dir], str(target))
        assert best_dir == old_dir
        assert stale == set()

    def test_rank_returns_stale_set(self, tmp_path):
        """When best candidate has stale files, they are returned."""
        import hashlib
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("current")

        d1 = tmp_path / "d1"
        d1.mkdir()
        _write_json(d1 / "checklist.json", {
            "files": [{"path": "a.py", "sha256": "STALE"}],
        })

        best_dir, stale = _rank_candidates([d1], str(target))
        assert best_dir == d1
        assert stale == {"a.py"}

    def test_rank_falls_back_to_newest_when_all_fresh(self, tmp_path):
        import hashlib
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("current")
        disk_hash = hashlib.sha256(b"current").hexdigest()

        d1 = tmp_path / "d1"
        d2 = tmp_path / "d2"
        d1.mkdir()
        d2.mkdir()
        os.utime(d1, (1000, 1000))
        os.utime(d2, (2000, 2000))

        for d in (d1, d2):
            _write_json(d / "checklist.json", {
                "files": [{"path": "a.py", "sha256": disk_hash}],
            })

        best_dir, stale = _rank_candidates([d1, d2], str(target))
        assert best_dir == d2  # newer
        assert stale == set()

    def test_rank_without_target_picks_newest(self, tmp_path):
        d1 = tmp_path / "d1"
        d2 = tmp_path / "d2"
        d1.mkdir()
        d2.mkdir()
        os.utime(d1, (1000, 1000))
        os.utime(d2, (2000, 2000))

        best_dir, stale = _rank_candidates([d1, d2], target_path=None)
        assert best_dir == d2
        assert stale == set()

    def test_rank_empty_candidates(self):
        assert _rank_candidates([], None) is None


# ---------------------------------------------------------------------------
# load_understand_context — attack-surface.json
# ---------------------------------------------------------------------------

class TestLoadUnderstandContextAttackSurface:
    def test_creates_attack_surface_from_context_map(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)

        result = load_understand_context(understand_dir, validate_dir)

        assert result["context_map_loaded"] is True
        assert result["attack_surface"]["sources"] == 1
        assert result["attack_surface"]["sinks"] == 1
        assert result["attack_surface"]["trust_boundaries"] == 1
        assert result["attack_surface"]["unchecked_flows"] == 1

        surface = json.loads((validate_dir / "attack-surface.json").read_text())
        assert len(surface["sources"]) == 1
        assert len(surface["sinks"]) == 1
        assert len(surface["trust_boundaries"]) == 1

    def test_does_not_raise_on_non_string_file_during_stale_filter(self, tmp_path):
        # _references_file does `f in stale_files` — list-typed file would
        # raise TypeError. Pre-existing weakness, but newly exposed once
        # normalize_context_map stopped rejecting non-string file values.
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()
        ctx = {
            "sources": [], "sinks": [], "trust_boundaries": [],
            "entry_points": [{"id": "EP-1", "file": ["bad", "list"], "line": 1}],
        }
        _write_json(understand_dir / "context-map.json", ctx)
        # Must not raise.
        load_understand_context(
            understand_dir, validate_dir, stale_files={"foo.py"},
        )

    def test_normalises_paths_before_filtering_stale_files(self, tmp_path):
        # Regression for an ordering bug: _filter_context_map matches
        # entry["file"] against stale_files using strict equality. If we
        # filter first and normalise after, an entry with "./foo.py"
        # survives a stale_files set containing "foo.py" — leaking a
        # stale entry to downstream consumers.
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        # context-map has the file under "./foo.py" (with the dot-slash
        # claude sometimes emits) — should be filtered as stale.
        ctx = {
            "sources": [], "sinks": [], "trust_boundaries": [],
            "entry_points": [{"id": "EP-1", "file": "./foo.py", "line": 1}],
            "sink_details": [{"id": "SINK-1", "file": "./foo.py", "line": 5}],
        }
        _write_json(understand_dir / "context-map.json", ctx)

        # stale_files uses canonical relative paths.
        result = load_understand_context(
            understand_dir, validate_dir, stale_files={"foo.py"},
        )
        # After fix: normalise → "./foo.py" → "foo.py" → matches stale set
        # → entry filtered. Pre-fix: filter ran first, no match, entry leaked.
        loaded = result["context_map"]
        assert len(loaded["entry_points"]) == 0, \
            "entry should have been filtered as stale once paths were normalised"
        assert len(loaded["sink_details"]) == 0

    def test_merges_into_existing_attack_surface(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        _write_json(validate_dir / "attack-surface.json", {
            "sources": [
                {"type": "cli_arg", "entry": "main() arg parsing @ src/main.py:10"},
            ],
            "sinks": [],
            "trust_boundaries": [],
        })

        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)

        load_understand_context(understand_dir, validate_dir)

        surface = json.loads((validate_dir / "attack-surface.json").read_text())
        assert len(surface["sources"]) == 2

    def test_does_not_duplicate_existing_sources(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        _write_json(validate_dir / "attack-surface.json", {
            "sources": [
                {"type": "http_route", "entry": "POST /api/query @ src/routes/query.py:34"},
            ],
            "sinks": [],
            "trust_boundaries": [],
        })

        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)

        load_understand_context(understand_dir, validate_dir)

        surface = json.loads((validate_dir / "attack-surface.json").read_text())
        assert len(surface["sources"]) == 1

    def test_gap_annotations_added_to_trust_boundaries(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)

        load_understand_context(understand_dir, validate_dir)

        surface = json.loads((validate_dir / "attack-surface.json").read_text())
        jwt_boundary = surface["trust_boundaries"][0]
        assert "boundary" in jwt_boundary

    def test_missing_context_map_returns_empty_summary(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        result = load_understand_context(understand_dir, validate_dir)

        assert result["context_map_loaded"] is False
        assert not (validate_dir / "attack-surface.json").exists()


# ---------------------------------------------------------------------------
# load_understand_context — flow trace import
# ---------------------------------------------------------------------------

class TestLoadUnderstandContextFlowTraces:
    def test_imports_flow_trace_as_attack_path(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)
        _write_json(understand_dir / "flow-trace-EP-001.json", MINIMAL_FLOW_TRACE)

        result = load_understand_context(understand_dir, validate_dir)

        assert result["flow_traces"]["count"] == 1
        assert result["flow_traces"]["imported_as_paths"] == 1

        paths = json.loads((validate_dir / "attack-paths.json").read_text())
        assert len(paths) == 1
        assert paths[0]["id"] == "TRACE-001"
        assert paths[0]["status"] == "uncertain"
        assert paths[0]["source"] == TRACE_SOURCE_LABEL
        assert len(paths[0]["steps"]) == 2
        assert paths[0]["proximity"] == 9

    def test_carries_through_attacker_control_and_verdict(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)
        _write_json(understand_dir / "flow-trace-EP-001.json", MINIMAL_FLOW_TRACE)

        load_understand_context(understand_dir, validate_dir)

        paths = json.loads((validate_dir / "attack-paths.json").read_text())
        assert paths[0]["attacker_control"]["level"] == "full"
        assert "SQLi" in paths[0]["trace_verdict"]

    def test_does_not_re_import_existing_path(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        _write_json(validate_dir / "attack-paths.json", [
            {"id": "TRACE-001", "status": "confirmed", "steps": [], "proximity": 9},
        ])

        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)
        _write_json(understand_dir / "flow-trace-EP-001.json", MINIMAL_FLOW_TRACE)

        result = load_understand_context(understand_dir, validate_dir)

        assert result["flow_traces"]["imported_as_paths"] == 0
        paths = json.loads((validate_dir / "attack-paths.json").read_text())
        assert len(paths) == 1
        assert paths[0]["status"] == "confirmed"

    def test_merges_with_existing_paths(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        _write_json(validate_dir / "attack-paths.json", [
            {"id": "PATH-001", "status": "confirmed", "steps": [], "proximity": 7},
        ])

        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)
        _write_json(understand_dir / "flow-trace-EP-001.json", MINIMAL_FLOW_TRACE)

        load_understand_context(understand_dir, validate_dir)

        paths = json.loads((validate_dir / "attack-paths.json").read_text())
        assert len(paths) == 2

    def test_no_trace_files_returns_zero_count(self, tmp_path):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()

        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)

        result = load_understand_context(understand_dir, validate_dir)

        assert result["flow_traces"]["count"] == 0
        assert result["flow_traces"]["imported_as_paths"] == 0
        assert not (validate_dir / "attack-paths.json").exists()


# ---------------------------------------------------------------------------
# normalize_context_map
# ---------------------------------------------------------------------------

class TestNormalizeContextMap:
    def _checklist(self, files):
        return {"target_path": "/repo", "files": files}

    def test_backfills_missing_name_from_line_range(self):
        # claude omitted the `name` field — we look up the function whose
        # line range contains the entry's line and inject it.
        ctx = {"entry_points": [{"file": "app.py", "line": 12}]}
        checklist = self._checklist([{
            "path": "app.py", "lines": 50,
            "functions": [{"name": "handle", "line_start": 10, "line_end": 25}],
        }])
        normalize_context_map(ctx, checklist)
        assert ctx["entry_points"][0]["name"] == "handle"

    def test_backfill_falls_back_to_closest_preceding_when_no_line_end(self):
        # Inventories without line_end can still get best-effort matching:
        # the closest preceding line_start wins.
        ctx = {"sink_details": [{"file": "x.py", "line": 50}]}
        checklist = self._checklist([{
            "path": "x.py", "lines": 100,
            "functions": [
                {"name": "first", "line_start": 10},
                {"name": "second", "line_start": 40},
                {"name": "third", "line_start": 70},
            ],
        }])
        normalize_context_map(ctx, checklist)
        assert ctx["sink_details"][0]["name"] == "second"

    def test_does_not_raise_on_string_typed_line_numbers_in_checklist(self):
        # If a corrupt checklist has line_start / line_end as strings
        # (LLM-produced inventory or hand-edited), the comparison
        # `line_start <= line <= line_end` would raise TypeError
        # (str vs int). Must be defensive — skip those entries.
        ctx = {"entry_points": [{"file": "x.py", "line": 12}]}
        checklist = self._checklist([{
            "path": "x.py", "lines": 50,
            "functions": [
                # All three malformed in different ways.
                {"name": "stringly_typed", "line_start": "10", "line_end": "25"},
                {"name": "missing_end", "line_start": 5, "line_end": "fifty"},
                {"name": "valid", "line_start": 10, "line_end": 25},
            ],
        }])
        # Must not raise; valid entry should still be the backfill source.
        normalize_context_map(ctx, checklist)
        assert ctx["entry_points"][0].get("name") == "valid"

    def test_does_not_raise_on_string_typed_line_in_fallback(self):
        # Same but for the fallback path (no line_end on any function).
        ctx = {"entry_points": [{"file": "x.py", "line": 50}]}
        checklist = self._checklist([{
            "path": "x.py", "lines": 100,
            "functions": [
                {"name": "stringly", "line_start": "40"},  # corrupt
                {"name": "real",     "line_start": 30},     # valid, preceding
            ],
        }])
        normalize_context_map(ctx, checklist)
        assert ctx["entry_points"][0].get("name") == "real"

    def test_backfill_prefers_smallest_span_for_nested_functions(self):
        # When functions nest (outer 1-100, inner 30-50) and the entry
        # references a line inside the inner range, attribute to the
        # innermost — first-match-wins would falsely pick the outer.
        ctx = {"entry_points": [{"file": "x.py", "line": 35}]}
        checklist = self._checklist([{
            "path": "x.py", "lines": 100,
            "functions": [
                {"name": "outer", "line_start": 1,  "line_end": 100},
                {"name": "inner", "line_start": 30, "line_end": 50},
            ],
        }])
        normalize_context_map(ctx, checklist)
        assert ctx["entry_points"][0]["name"] == "inner"

    def test_does_not_overwrite_existing_name(self):
        ctx = {"entry_points": [{"file": "app.py", "line": 5, "name": "claude_said"}]}
        checklist = self._checklist([{
            "path": "app.py", "lines": 50,
            "functions": [{"name": "different", "line_start": 1, "line_end": 30}],
        }])
        normalize_context_map(ctx, checklist)
        assert ctx["entry_points"][0]["name"] == "claude_said"

    def test_strips_leading_dotslash_from_file_paths(self):
        ctx = {"entry_points": [{"file": "./src/app.py", "line": 5}]}
        normalize_context_map(ctx, {"files": []})
        assert ctx["entry_points"][0]["file"] == "src/app.py"

    def test_converts_absolute_path_under_target_to_relative(self, tmp_path):
        # claude sometimes emits absolute paths; bridge needs relative for
        # strict-equality match against checklist paths.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "app.py").write_text("x")
        ctx = {"entry_points": [{"file": str(target / "app.py"), "line": 1}]}
        normalize_context_map(ctx, {"files": []}, target_path=str(target))
        assert ctx["entry_points"][0]["file"] == "app.py"

    def test_warns_on_file_not_in_checklist(self, caplog):
        ctx = {"entry_points": [{"file": "nope.py", "line": 5}]}
        checklist = self._checklist([{"path": "real.py", "lines": 10}])
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            normalize_context_map(ctx, checklist)
        assert any("not present in checklist" in r.message for r in caplog.records)

    def test_warns_on_line_past_end_of_file(self, caplog):
        ctx = {"sink_details": [{"file": "app.py", "line": 9999}]}
        checklist = self._checklist([{"path": "app.py", "lines": 50}])
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            normalize_context_map(ctx, checklist)
        assert any("but file has only" in r.message for r in caplog.records)

    def test_warns_on_unchecked_flow_referencing_missing_entry_id(self, caplog):
        ctx = {
            "entry_points": [{"id": "EP-001", "file": "a.py", "line": 1}],
            "sink_details": [{"id": "SINK-001", "file": "a.py", "line": 5}],
            "unchecked_flows": [{"entry_point": "EP-999", "sink": "SINK-001"}],
        }
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            normalize_context_map(ctx, {"files": [{"path": "a.py", "lines": 10}]})
        assert any("EP-999" in r.message for r in caplog.records)

    def test_log_output_escapes_terminal_escapes_in_file_path(self, caplog):
        # Without escape_nonprintable, a malicious target repo whose file
        # paths contain CSI 2J (clear screen) or BEL would corrupt the
        # operator's terminal via raptor's own warning output. Defended
        # via core.security.log_sanitisation.escape_nonprintable.
        nasty = "evil\x1b[2J\x07.py"
        ctx = {"entry_points": [{"file": nasty, "line": 5}]}
        checklist = self._checklist([{"path": "real.py", "lines": 10}])
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            normalize_context_map(ctx, checklist)
        formatted = " ".join(r.getMessage() for r in caplog.records)
        assert "\x1b" not in formatted
        assert "\x07" not in formatted
        assert "\\x1b" in formatted
        assert "\\x07" in formatted

    def test_log_output_escapes_terminal_escapes_in_unchecked_flow_id(self, caplog):
        ctx = {
            "entry_points": [{"id": "EP-001", "file": "a.py", "line": 1}],
            "sink_details": [{"id": "SINK-001", "file": "a.py", "line": 5}],
            "unchecked_flows": [{"entry_point": "EP-\x1bevil", "sink": "SINK-001"}],
        }
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            normalize_context_map(ctx, {"files": [{"path": "a.py", "lines": 10}]})
        formatted = " ".join(r.getMessage() for r in caplog.records)
        assert "\x1b" not in formatted
        assert "\\x1b" in formatted

    def test_idempotent_safe_to_call_twice(self):
        ctx = {"entry_points": [{"file": "./app.py", "line": 12}]}
        checklist = self._checklist([{
            "path": "app.py", "lines": 50,
            "functions": [{"name": "handle", "line_start": 10, "line_end": 25}],
        }])
        normalize_context_map(ctx, checklist)
        snapshot = json.loads(json.dumps(ctx))
        normalize_context_map(ctx, checklist)
        assert ctx == snapshot

    def test_no_op_on_missing_inputs(self):
        # Must never raise on None / non-dict inputs — defensive.
        normalize_context_map(None, {})
        normalize_context_map({}, None)
        normalize_context_map("not-a-dict", {})

    def test_path_normalisation_runs_even_without_checklist(self):
        # Path normalisation doesn't depend on the checklist (it just
        # strips ./ and resolves absolute paths under target_path).
        # Callers that pass checklist=None should still get clean paths.
        ctx = {"entry_points": [{"file": "./src/app.py", "line": 5}]}
        normalize_context_map(ctx, None, target_path="/repo")
        assert ctx["entry_points"][0]["file"] == "src/app.py"

    def test_cross_ref_validation_handles_list_valued_refs(self):
        # An unchecked_flow may legitimately reference multiple entry points
        # or sinks via a list. Set membership on a raw list would raise
        # TypeError (lists unhashable) — must coerce safely.
        ctx = {
            "entry_points": [
                {"id": "EP-001", "file": "a.py", "line": 1},
                {"id": "EP-002", "file": "a.py", "line": 5},
            ],
            "sink_details": [{"id": "SINK-001", "file": "a.py", "line": 10}],
            "unchecked_flows": [
                {"entry_point": ["EP-001", "EP-002"], "sink": "SINK-001"},
            ],
        }
        # Must not raise; both EP IDs are valid so no warning either.
        normalize_context_map(ctx, {"files": [{"path": "a.py", "lines": 20}]})

    def test_does_not_raise_on_non_string_id_value(self):
        # Set construction `{e.get("id") for ...}` requires hashable values.
        # If claude emits id as a list / dict (schema violation), the
        # comprehension would crash before the validation could even run.
        ctx = {
            "entry_points": [
                {"id": ["EP-001"], "file": "a.py", "line": 1},  # list id
                {"id": "EP-002",   "file": "a.py", "line": 5},  # control
            ],
            "sink_details": [
                {"id": {"obj": "x"}, "file": "a.py", "line": 10},  # dict id
                {"id": "SINK-001",   "file": "a.py", "line": 15},  # control
            ],
            "unchecked_flows": [{"entry_point": "EP-002", "sink": "SINK-001"}],
        }
        # Must not raise.
        normalize_context_map(ctx, {"files": [{"path": "a.py", "lines": 50}]})

    def test_does_not_raise_on_non_string_file_value(self):
        # An LLM that emits a list / int / dict for `file:` would crash
        # str.strip() inside path normalisation. Must be defensive.
        ctx = {
            "entry_points": [
                {"file": ["src/a.py", "src/b.py"], "line": 5},  # list
                {"file": 42, "line": 10},                        # int
                {"file": {"path": "x"}, "line": 1},              # dict
                {"file": "valid.py", "line": 1},                 # control
            ],
        }
        # Must not raise.
        normalize_context_map(ctx, {"files": []})
        # Valid one stays unchanged; invalid ones get left alone (no
        # silent corruption).
        assert ctx["entry_points"][3]["file"] == "valid.py"

    def test_cross_ref_validation_warns_on_invalid_id_in_list(self, caplog):
        ctx = {
            "entry_points": [{"id": "EP-001", "file": "a.py", "line": 1}],
            "sink_details": [{"id": "SINK-001", "file": "a.py", "line": 10}],
            "unchecked_flows": [
                {"entry_point": ["EP-001", "EP-MISSING"], "sink": "SINK-001"},
            ],
        }
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            normalize_context_map(ctx, {"files": [{"path": "a.py", "lines": 20}]})
        assert any("EP-MISSING" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# enrich_checklist
# ---------------------------------------------------------------------------

class TestEnrichChecklist:
    def test_marks_entry_point_files_as_high_priority(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)

        enrich_checklist(checklist, copy.deepcopy(MINIMAL_CONTEXT_MAP))

        routes_file = next(
            f for f in checklist["files"] if f["path"] == "src/routes/query.py"
        )
        assert routes_file["functions"][0]["priority"] == "high"
        assert routes_file["functions"][0]["priority_reason"] == "entry_point"

    def test_marks_sink_files_as_high_priority(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)

        enrich_checklist(checklist, copy.deepcopy(MINIMAL_CONTEXT_MAP))

        db_file = next(
            f for f in checklist["files"] if f["path"] == "src/db/query.py"
        )
        assert db_file["functions"][0]["priority"] == "high"

    def test_priority_targets_carry_resolved_entry_and_sink_details(self):
        # Each priority_target should include resolved file/line/name from
        # the entry_points/sink_details lists, so consumers don't have to
        # do the ID → details join. Original ID fields are preserved
        # (additive enrichment).
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        # Same shape as MINIMAL_CONTEXT_MAP but with EP-001 used (the
        # one that DOES exist in entry_points) so we can verify resolution.
        ctx = copy.deepcopy(MINIMAL_CONTEXT_MAP)
        ctx["unchecked_flows"] = [
            {"entry_point": "EP-001", "sink": "SINK-001",
             "missing_boundary": "..."},
        ]
        enrich_checklist(checklist, ctx)

        targets = checklist["priority_targets"]
        assert len(targets) == 1
        target = targets[0]
        # Original fields preserved.
        assert target["entry_point"] == "EP-001"
        assert target["sink"] == "SINK-001"
        # Resolved details added — includes name backfilled by
        # normalize_context_map from line 34 → handle_query in the
        # checklist (and similarly for the sink).
        assert target["entry_points_resolved"] == [{
            "id": "EP-001",
            "file": "src/routes/query.py",
            "line": 34,
            "name": "handle_query",
        }]
        assert target["sinks_resolved"] == [{
            "id": "SINK-001",
            "file": "src/db/query.py",
            "line": 89,
            "name": "run_query",
        }]

    def test_priority_targets_handle_list_valued_refs(self):
        # An unchecked_flow may reference multiple entry_points (multiple
        # sources reaching one sink). Resolution should produce a list
        # entry per referenced ID.
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        ctx = {
            "entry_points": [
                {"id": "EP-A", "file": "a.py", "line": 1, "name": "f1"},
                {"id": "EP-B", "file": "b.py", "line": 2, "name": "f2"},
            ],
            "sink_details": [
                {"id": "S-1", "file": "x.py", "line": 10, "name": "g1"},
            ],
            "unchecked_flows": [
                {"entry_point": ["EP-A", "EP-B"], "sink": "S-1"},
            ],
        }
        enrich_checklist(checklist, ctx)
        target = checklist["priority_targets"][0]
        ids = [r["id"] for r in target["entry_points_resolved"]]
        assert ids == ["EP-A", "EP-B"]
        assert target["sinks_resolved"][0]["id"] == "S-1"

    def test_priority_targets_drop_malformed_field_types_in_resolved(self):
        # If an entry_point or sink_detail has corrupt typing on file /
        # line / name (LLM schema violation), the resolved output should
        # silently drop the bad field rather than copying it into the
        # downstream consumer's expected shape.
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        ctx = {
            "entry_points": [{
                "id": "EP-1",
                "file": ["bad", "list"],   # malformed
                "line": "thirty-four",     # malformed
                "name": "good_name",       # valid
            }],
            "sink_details": [{
                "id": "S-1",
                "file": "ok.py",
                "line": True,              # malformed (bool, not real int)
                "name": {"corrupt": True}, # malformed
            }],
            "unchecked_flows": [
                {"entry_point": "EP-1", "sink": "S-1"},
            ],
        }
        enrich_checklist(checklist, ctx)
        target = checklist["priority_targets"][0]

        # Resolved entry: only the valid `name` survives (id always
        # included as the lookup key).
        assert target["entry_points_resolved"] == [
            {"id": "EP-1", "name": "good_name"},
        ]
        # Resolved sink: only the valid `file` survives.
        assert target["sinks_resolved"] == [
            {"id": "S-1", "file": "ok.py"},
        ]

    def test_priority_targets_partial_resolution_when_some_ids_unknown(self):
        # List-valued entry_point with one known and one unknown ID —
        # known should resolve, unknown should drop, raw IDs preserved.
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        ctx = {
            "entry_points": [{"id": "EP-OK", "file": "a.py", "line": 1, "name": "f"}],
            "sink_details": [{"id": "S-1", "file": "x.py", "line": 10}],
            "unchecked_flows": [
                {"entry_point": ["EP-OK", "EP-MISSING"], "sink": "S-1"},
            ],
        }
        enrich_checklist(checklist, ctx)
        target = checklist["priority_targets"][0]
        # Raw IDs untouched (downstream can still see what was requested).
        assert target["entry_point"] == ["EP-OK", "EP-MISSING"]
        # Resolved list contains only the valid one.
        ids = [r["id"] for r in target["entry_points_resolved"]]
        assert ids == ["EP-OK"]

    def test_does_not_raise_when_entry_points_is_non_list(self):
        # Same TypeError class as the unchecked_flows case, in different
        # `for x in d.get("...") or []` sites. Probes the new _record
        # and _index_entries_by_id helpers plus the file-level walk.
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        for bad_value in ("a string", {"obj": True}, 42):
            ctx = {
                "entry_points": bad_value,   # malformed
                "sink_details": [],
                "unchecked_flows": [],
            }
            # Must not raise.
            enrich_checklist(checklist, ctx)

    def test_does_not_raise_when_sink_details_is_non_list(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        for bad_value in ("a string", {"obj": True}, 42):
            ctx = {
                "entry_points": [],
                "sink_details": bad_value,   # malformed
                "unchecked_flows": [],
            }
            enrich_checklist(checklist, ctx)

    def test_no_priority_targets_when_unchecked_flows_is_non_list(self):
        # Defensive: unchecked_flows="some string" or other weird shapes
        # should not produce an empty priority_targets list (which would
        # be more confusing than just leaving the key absent).
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        for bad_value in ("a string", {"obj": True}, 42, True):
            ctx = {
                "entry_points": [], "sink_details": [],
                "unchecked_flows": bad_value,
            }
            enrich_checklist(checklist, ctx)
            assert "priority_targets" not in checklist, \
                f"unchecked_flows={bad_value!r} should not produce priority_targets"

    def test_priority_targets_drop_unknown_ids_silently(self):
        # If unchecked_flow names a missing ID (already warned by
        # _validate_cross_refs), resolution drops it from *_resolved
        # rather than emitting a half-formed dict.
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        ctx = {
            "entry_points": [{"id": "EP-1", "file": "a.py", "line": 1}],
            "sink_details": [{"id": "S-1", "file": "x.py", "line": 10}],
            "unchecked_flows": [
                {"entry_point": "EP-MISSING", "sink": "S-1"},
            ],
        }
        enrich_checklist(checklist, ctx)
        target = checklist["priority_targets"][0]
        assert target["entry_point"] == "EP-MISSING"  # raw ID preserved
        assert target["entry_points_resolved"] == []   # but resolution empty
        assert len(target["sinks_resolved"]) == 1

    def test_adds_priority_targets_for_unchecked_flows(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)

        enrich_checklist(checklist, copy.deepcopy(MINIMAL_CONTEXT_MAP))

        assert "priority_targets" in checklist
        assert len(checklist["priority_targets"]) == 1
        assert checklist["priority_targets"][0]["entry_point"] == "EP-002"
        assert checklist["priority_targets"][0]["source"] == "understand:map"

    def test_no_unchecked_flows_omits_priority_targets(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        # deepcopy — enrich_checklist mutates context_map (via
        # normalize_context_map) and a shallow dict() would let mutation
        # of nested entry lists leak back into MINIMAL_CONTEXT_MAP.
        context_map = copy.deepcopy(MINIMAL_CONTEXT_MAP)
        context_map["unchecked_flows"] = []

        enrich_checklist(checklist, context_map)

        assert "priority_targets" not in checklist

    def test_enrich_is_idempotent_under_repeated_calls(self):
        # Re-running enrich_checklist with the same inputs should produce
        # identical output. The clear-step opens a small risk window where
        # a future bug could leave the checklist in a different shape on
        # the second call (e.g. by failing to re-write something it just
        # popped). Snapshot-equal-after-two-calls catches that class of bug.
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        ctx = copy.deepcopy(MINIMAL_CONTEXT_MAP)
        enrich_checklist(checklist, ctx)
        snapshot_after_run1 = json.loads(json.dumps(checklist))

        # Same inputs (deepcopy because enrich mutates context_map) — must
        # produce the same checklist state.
        ctx2 = copy.deepcopy(MINIMAL_CONTEXT_MAP)
        enrich_checklist(checklist, ctx2)
        snapshot_after_run2 = json.loads(json.dumps(checklist))

        assert snapshot_after_run1 == snapshot_after_run2

    def test_clears_stale_priority_markers_on_re_enrichment(self):
        # If a function was marked priority=high in a prior enrich run
        # but the current context-map no longer references it, the marker
        # should be cleared (not silently retained as stale data).
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)

        # Run #1: pretend a prior enrich marked handle_query and run_query
        for f in checklist["files"]:
            for fn in f["functions"]:
                fn["priority"] = "high"
                fn["priority_reason"] = "sink"  # stale reason
        checklist["priority_targets"] = [{"entry_point": "EP-OLD", "source": "understand:map"}]

        # Run #2: enrich with a context-map that has NO entry_points / sinks
        # at all — every prior marker should be cleared.
        empty_ctx = {
            "sources": [], "sinks": [], "trust_boundaries": [],
            "entry_points": [], "sink_details": [], "unchecked_flows": [],
        }
        enrich_checklist(checklist, empty_ctx)

        for f in checklist["files"]:
            for fn in f["functions"]:
                assert "priority" not in fn, \
                    f"stale priority on {fn['name']} should have been cleared"
                assert "priority_reason" not in fn
        assert "priority_targets" not in checklist, \
            "stale priority_targets at checklist level should have been cleared"

    def test_re_enrichment_with_changed_context_map_overwrites_correctly(self):
        # Stronger version: prior run marked X as 'sink', new run says X is
        # only 'entry_point' — verify the reason was OVERWRITTEN, not
        # accumulated as 'entry_point+sink'.
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        for f in checklist["files"]:
            for fn in f["functions"]:
                fn["priority"] = "high"
                fn["priority_reason"] = "sink"  # stale from prior run

        # New context-map: handle_query is ONLY an entry point now.
        ctx = {
            "sources": [], "sinks": [], "trust_boundaries": [],
            "entry_points": [{
                "id": "EP-001", "file": "src/routes/query.py", "line": 34,
                "name": "handle_query",
            }],
            "sink_details": [],
        }
        enrich_checklist(checklist, ctx)

        routes_func = next(
            f["functions"][0] for f in checklist["files"]
            if f["path"] == "src/routes/query.py"
        )
        assert routes_func["priority"] == "high"
        assert routes_func["priority_reason"] == "entry_point", \
            "reason should be the new run's value, not the stale 'sink'"

    def test_safe_on_empty_inputs(self):
        enrich_checklist({}, {})
        enrich_checklist(None, None)

    def test_does_not_raise_when_context_map_has_non_string_name(self):
        # If `name` is a list/dict (LLM schema violation), the tuple key
        # `(file_path, name)` is unhashable and would crash the
        # priority_functions setdefault. Drop those entries silently
        # rather than propagating the type bug.
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        ctx = {
            "entry_points": [
                {"id": "EP-1", "file": "src/routes/query.py", "line": 34,
                 "name": ["weird", "list", "name"]},  # malformed
            ],
            "sink_details": [
                {"id": "S-1", "file": "src/db/query.py", "line": 89,
                 "name": {"corrupt": True}},  # malformed
            ],
            "unchecked_flows": [],
        }
        # Must not raise.
        enrich_checklist(checklist, ctx)

    def test_does_not_raise_when_context_map_has_non_string_file(self):
        # _normalize_paths leaves non-string `file:` values alone, so they
        # survive into enrich_checklist's tuple keys. Defend.
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        ctx = {
            "entry_points": [
                {"id": "EP-1", "file": ["a", "b"], "line": 1},  # malformed
                {"id": "EP-2", "file": "src/routes/query.py", "line": 34},  # control
            ],
            "sink_details": [],
            "unchecked_flows": [],
        }
        # Must not raise; the valid control entry should still get marked.
        enrich_checklist(checklist, ctx)
        routes_file = next(
            f for f in checklist["files"] if f["path"] == "src/routes/query.py"
        )
        assert routes_file["functions"][0]["priority"] == "high"

    def test_does_not_raise_when_checklist_has_non_string_function_name(self):
        # If the checklist itself has a corrupt non-string function name,
        # backfill must not propagate that into context_map (which would
        # crash enrich_checklist downstream).
        checklist = {
            "target_path": "/repo",
            "files": [{
                "path": "app.py", "lines": 50,
                "functions": [
                    {"name": ["corrupt"], "line_start": 10, "line_end": 25},
                ],
            }],
        }
        ctx = {"entry_points": [{"file": "app.py", "line": 12}]}  # no name
        # Must not raise; entry's name should NOT be backfilled with the
        # corrupt list-typed name from the checklist.
        normalize_context_map(ctx, checklist)
        assert "name" not in ctx["entry_points"][0]

    def test_safe_on_non_dict_checklist(self):
        # A malformed caller passing a list as the checklist would crash
        # checklist.get("target_path"). Must be defensive — return early.
        result = enrich_checklist(["not", "a", "dict"], MINIMAL_CONTEXT_MAP)
        assert result == ["not", "a", "dict"]  # returned unchanged

    def test_function_level_matching_when_context_map_provides_name(self):
        # When the context map labels an entry point or sink with a
        # specific function name, only that function should get marked —
        # not every function in the file. Old behaviour was file-level
        # always, which falsely promoted unrelated helpers.
        checklist = {
            "files": [{
                "path": "src/handler.py",
                "language": "python",
                "lines": 50,
                "sha256": "h",
                "functions": [
                    {"name": "handle_request", "line_start": 10, "checked_by": []},
                    {"name": "internal_helper", "line_start": 30, "checked_by": []},
                ],
            }],
        }
        context_map = {
            "entry_points": [
                {"file": "src/handler.py", "name": "handle_request"},
            ],
            "sink_details": [],
        }
        enrich_checklist(checklist, context_map)

        funcs = checklist["files"][0]["functions"]
        by_name = {f["name"]: f for f in funcs}
        assert by_name["handle_request"].get("priority") == "high"
        assert by_name["handle_request"].get("priority_reason") == "entry_point"
        # The helper sits in the same file but is NOT an entry point —
        # under the old file-level logic it would be falsely marked.
        assert "priority" not in by_name["internal_helper"]

    def test_file_level_fallback_when_name_absent(self):
        # When the context map omits the name field (older /understand
        # outputs, simpler maps), every function in the file gets marked
        # — preserves backward compat with the existing fixtures.
        checklist = {
            "files": [{
                "path": "src/handler.py",
                "language": "python",
                "lines": 50,
                "sha256": "h",
                "functions": [
                    {"name": "handle_request", "line_start": 10, "checked_by": []},
                    {"name": "another", "line_start": 30, "checked_by": []},
                ],
            }],
        }
        context_map = {
            "entry_points": [{"file": "src/handler.py"}],  # no "name"
            "sink_details": [],
        }
        enrich_checklist(checklist, context_map)

        for func in checklist["files"][0]["functions"]:
            assert func.get("priority") == "high"
            assert func.get("priority_reason") == "entry_point"

    def test_function_in_both_entry_and_sink_gets_combined_reason(self):
        # A function that is both an entry point AND a sink (e.g. a Flask
        # route that does its own SQL execute) should be tagged with both
        # — the old code silently overwrote entry_point with "sink".
        checklist = {
            "files": [{
                "path": "src/api.py",
                "language": "python",
                "lines": 30,
                "sha256": "a",
                "functions": [
                    {"name": "search", "line_start": 10, "checked_by": []},
                ],
            }],
        }
        context_map = {
            "entry_points": [{"file": "src/api.py", "name": "search"}],
            "sink_details": [{"file": "src/api.py", "name": "search"}],
        }
        enrich_checklist(checklist, context_map)

        func = checklist["files"][0]["functions"][0]
        assert func.get("priority") == "high"
        # Sorted alphabetically for determinism: entry_point + sink.
        assert func.get("priority_reason") == "entry_point+sink"

    def test_file_level_entry_plus_function_level_sink_combine(self):
        # A function that inherits a file-level entry_point marker AND
        # also matches a function-level sink should get both reasons.
        # Verifies the union of file-level + function-level lookups.
        checklist = {
            "files": [{
                "path": "src/api.py",
                "language": "python",
                "lines": 30,
                "sha256": "a",
                "functions": [
                    {"name": "search", "line_start": 10, "checked_by": []},
                ],
            }],
        }
        context_map = {
            "entry_points": [{"file": "src/api.py"}],         # file-level
            "sink_details": [{"file": "src/api.py", "name": "search"}],  # func-level
        }
        enrich_checklist(checklist, context_map)

        func = checklist["files"][0]["functions"][0]
        assert func.get("priority_reason") == "entry_point+sink"

    def test_does_not_touch_unrelated_files(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        checklist["files"].append({
            "path": "src/utils/helpers.py",
            "language": "python",
            "lines": 20,
            "sha256": "ccc",
            "functions": [{"name": "format_string", "line_start": 5, "checked_by": []}],
        })

        enrich_checklist(checklist, copy.deepcopy(MINIMAL_CONTEXT_MAP))

        helpers_file = next(
            f for f in checklist["files"] if f["path"] == "src/utils/helpers.py"
        )
        assert "priority" not in helpers_file["functions"][0]


# ---------------------------------------------------------------------------
# Deduplication and staleness edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_tier2_and_tier3_same_dir_not_duplicated(self, tmp_path, monkeypatch):
        """Dir found via both project sibling and global scan appears only once."""
        project_dir = tmp_path / "out" / "projects" / "myapp"
        validate_dir = project_dir / "validate-20260402-120000"
        validate_dir.mkdir(parents=True)

        # Create a target dir so on-disk hashing works
        target_dir = tmp_path / "vulns"
        target_dir.mkdir()

        understand = _make_understand_dir(
            project_dir, "understand-20260401-120000",
            checklist={"target_path": str(target_dir), "files": []},
        )

        # Point global out/ at the same parent so tier 3 finds same dir
        monkeypatch.setattr("core.config.RaptorConfig.get_out_dir",
                            staticmethod(lambda: project_dir))

        result_dir, stale = find_understand_output(
            validate_dir, target_path=str(target_dir),
        )
        assert result_dir == understand

    def test_staleness_warning_logged(self, tmp_path):
        """When best candidate has stale files, _rank_candidates logs a warning."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("MODIFIED")

        stale_dir = tmp_path / "stale"
        stale_dir.mkdir()
        _write_json(stale_dir / "checklist.json", {
            "files": [{"path": "a.py", "sha256": "OLD_HASH_WONT_MATCH"}],
        })

        with unittest.mock.patch("core.orchestration.understand_bridge.logger") as mock_logger:
            best_dir, stale = _rank_candidates([stale_dir], str(target))

        assert best_dir == stale_dir
        assert stale == {"a.py"}
        mock_logger.warning.assert_called_once()
        assert "stale" in mock_logger.warning.call_args[0][0].lower()

    def test_tier1_takes_priority_over_fresher_sibling(self, tmp_path):
        """Co-located context-map (tier 1) wins even if a sibling exists."""
        project_dir = tmp_path / "project"
        validate_dir = project_dir / "validate-20260402-120000"
        validate_dir.mkdir(parents=True)

        # Tier 1: context-map in validate dir itself
        _write_json(validate_dir / "context-map.json", {"sources": []})

        # Tier 2: sibling that's newer
        _make_understand_dir(project_dir, "understand-20260403-120000")

        result_dir, stale = find_understand_output(validate_dir)
        assert result_dir == validate_dir  # tier 1 wins
        assert stale == set()

    def test_candidate_without_checklist_ranked_lowest(self, tmp_path):
        """Candidate missing checklist.json treated as stale."""
        import hashlib
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("content")
        disk_hash = hashlib.sha256(b"content").hexdigest()

        d_no_checklist = tmp_path / "no-checklist"
        d_with_checklist = tmp_path / "with-checklist"
        d_no_checklist.mkdir()
        time.sleep(0.01)
        d_with_checklist.mkdir()

        # Newer dir has no checklist
        # Older dir has fresh checklist matching disk
        _write_json(d_with_checklist / "checklist.json", {
            "files": [{"path": "a.py", "sha256": disk_hash}],
        })

        # d_no_checklist is newer by mtime but has no checklist → stale_count=1
        best_dir, stale = _rank_candidates(
            [d_no_checklist, d_with_checklist], str(target),
        )
        assert best_dir == d_with_checklist


# ---------------------------------------------------------------------------
# raptor-build-checklist script
# ---------------------------------------------------------------------------

class TestBuildChecklistScript:
    def test_creates_checklist(self, tmp_path):
        """raptor-build-checklist creates checklist.json."""
        import subprocess
        target = tmp_path / "src"
        target.mkdir()
        (target / "hello.c").write_text("int main() { return 0; }\n")
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        repo_root = Path(__file__).parents[3]  # core/orchestration/tests -> repo root
        result = subprocess.run(
            ["libexec/raptor-build-checklist", str(target), str(out_dir)],
            capture_output=True, text=True, cwd=repo_root,
        )
        assert result.returncode == 0, result.stderr
        assert "Checklist:" in result.stdout
        assert (out_dir / "checklist.json").exists()

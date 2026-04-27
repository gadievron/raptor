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


class TestPathConditionsForwarding:
    """Optional ``path_conditions`` and ``path_profile`` fields produced by
    ``/understand --trace`` should round-trip into ``attack-paths.json``
    exactly as written, so Stage E can feed them straight to the SMT
    helper without re-extracting from source.  Malformed values are
    dropped with a logged warning rather than passed through."""

    def _trace_with(self, **overrides):
        trace = copy.deepcopy(MINIMAL_FLOW_TRACE)
        trace.update(overrides)
        return trace

    def _import_and_get_path(self, tmp_path, trace):
        understand_dir = tmp_path / "understand"
        validate_dir = tmp_path / "validate"
        understand_dir.mkdir()
        validate_dir.mkdir()
        _write_json(understand_dir / "context-map.json", MINIMAL_CONTEXT_MAP)
        _write_json(understand_dir / "flow-trace-001.json", trace)
        load_understand_context(understand_dir, validate_dir)
        paths = json.loads((validate_dir / "attack-paths.json").read_text())
        assert len(paths) == 1
        return paths[0]

    def test_path_conditions_round_trip(self, tmp_path):
        trace = self._trace_with(path_conditions=[
            {"text": "size > 0", "step_index": 1, "negated": False},
            {"text": "ptr != NULL", "step_index": 2, "negated": False},
        ])
        path = self._import_and_get_path(tmp_path, trace)
        assert path["path_conditions"] == [
            {"text": "size > 0", "step_index": 1, "negated": False},
            {"text": "ptr != NULL", "step_index": 2, "negated": False},
        ]

    def test_path_conditions_bare_strings_round_trip(self, tmp_path):
        trace = self._trace_with(path_conditions=["size > 0", "count < 1024"])
        path = self._import_and_get_path(tmp_path, trace)
        assert path["path_conditions"] == ["size > 0", "count < 1024"]

    def test_path_profile_round_trip(self, tmp_path):
        trace = self._trace_with(path_profile="uint32")
        path = self._import_and_get_path(tmp_path, trace)
        assert path["path_profile"] == "uint32"

    def test_absent_fields_omitted_from_attack_path(self, tmp_path):
        path = self._import_and_get_path(tmp_path, self._trace_with())
        assert "path_conditions" not in path
        assert "path_profile" not in path

    def test_malformed_path_conditions_dropped(self, tmp_path, caplog):
        # Not a list — entire field dropped
        trace = self._trace_with(path_conditions="not a list")
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            path = self._import_and_get_path(tmp_path, trace)
        assert "path_conditions" not in path
        assert any("path_conditions must be a list" in r.message for r in caplog.records)

    def test_path_conditions_with_int_element_dropped(self, tmp_path, caplog):
        trace = self._trace_with(path_conditions=["size > 0", 42])
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            path = self._import_and_get_path(tmp_path, trace)
        assert "path_conditions" not in path

    def test_path_conditions_dict_missing_text_dropped(self, tmp_path, caplog):
        trace = self._trace_with(path_conditions=[{"step_index": 1, "negated": False}])
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            path = self._import_and_get_path(tmp_path, trace)
        assert "path_conditions" not in path

    def test_unknown_path_profile_dropped(self, tmp_path, caplog):
        trace = self._trace_with(path_profile="size_t")
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            path = self._import_and_get_path(tmp_path, trace)
        assert "path_profile" not in path
        assert any("path_profile must be one of" in r.message for r in caplog.records)

    def test_non_string_path_profile_dropped(self, tmp_path, caplog):
        trace = self._trace_with(path_profile=32)
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            path = self._import_and_get_path(tmp_path, trace)
        assert "path_profile" not in path

    def test_malformed_field_does_not_break_other_data(self, tmp_path, caplog):
        """Even when SMT-related fields are malformed, the rest of the
        attack-path import (steps, proximity, blockers) must still land."""
        trace = self._trace_with(path_conditions=42, path_profile="bogus")
        with caplog.at_level("WARNING", logger="core.orchestration.understand_bridge"):
            path = self._import_and_get_path(tmp_path, trace)
        assert "path_conditions" not in path
        assert "path_profile" not in path
        assert path["steps"] == MINIMAL_FLOW_TRACE["steps"]
        assert path["proximity"] == MINIMAL_FLOW_TRACE["proximity"]


# ---------------------------------------------------------------------------
# enrich_checklist
# ---------------------------------------------------------------------------

class TestEnrichChecklist:
    def test_marks_entry_point_files_as_high_priority(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)

        enrich_checklist(checklist, MINIMAL_CONTEXT_MAP)

        routes_file = next(
            f for f in checklist["files"] if f["path"] == "src/routes/query.py"
        )
        assert routes_file["functions"][0]["priority"] == "high"
        assert routes_file["functions"][0]["priority_reason"] == "entry_point"

    def test_marks_sink_files_as_high_priority(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)

        enrich_checklist(checklist, MINIMAL_CONTEXT_MAP)

        db_file = next(
            f for f in checklist["files"] if f["path"] == "src/db/query.py"
        )
        assert db_file["functions"][0]["priority"] == "high"

    def test_adds_priority_targets_for_unchecked_flows(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)

        enrich_checklist(checklist, MINIMAL_CONTEXT_MAP)

        assert "priority_targets" in checklist
        assert len(checklist["priority_targets"]) == 1
        assert checklist["priority_targets"][0]["entry_point"] == "EP-002"
        assert checklist["priority_targets"][0]["source"] == "understand:map"

    def test_no_unchecked_flows_omits_priority_targets(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        context_map = dict(MINIMAL_CONTEXT_MAP)
        context_map["unchecked_flows"] = []

        enrich_checklist(checklist, context_map)

        assert "priority_targets" not in checklist

    def test_safe_on_empty_inputs(self):
        enrich_checklist({}, {})
        enrich_checklist(None, None)

    def test_does_not_touch_unrelated_files(self):
        checklist = copy.deepcopy(MINIMAL_CHECKLIST)
        checklist["files"].append({
            "path": "src/utils/helpers.py",
            "language": "python",
            "lines": 20,
            "sha256": "ccc",
            "functions": [{"name": "format_string", "line_start": 5, "checked_by": []}],
        })

        enrich_checklist(checklist, MINIMAL_CONTEXT_MAP)

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

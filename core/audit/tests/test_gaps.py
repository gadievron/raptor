"""Tests for core.audit.gaps — gap computation."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.gaps import (
    PRIORITY_DEAD_CODE,
    PRIORITY_ENTRY_POINT,
    PRIORITY_FULLY_COVERED,
    PRIORITY_NO_TOOL_COVERAGE,
    PRIORITY_PARTIAL_TOOL_COVERAGE,
    compute_gaps,
    load_checklist,
    load_context_map,
    write_gaps,
)


def _sample_checklist():
    return {
        "target_path": "/tmp/target",
        "files": [
            {
                "path": "src/handler.c",
                "items": [
                    {"name": "parse_request", "line_start": 10, "line_end": 50},
                    {"name": "handle_error", "line_start": 55, "line_end": 70},
                    {"name": "tiny_helper", "line_start": 72, "line_end": 75},
                ],
            },
            {
                "path": "src/auth.c",
                "items": [
                    {"name": "check_password", "line_start": 5, "line_end": 30},
                ],
            },
        ],
    }


def _sample_coverage_records():
    return [
        {
            "tool": "semgrep",
            "files": {
                "src/handler.c": {
                    "functions": {
                        "parse_request": {"status": "clean"},
                    },
                },
            },
            "files_examined": ["src/handler.c"],
        },
    ]


class TestComputeGaps:
    def test_basic_gaps(self):
        gaps = compute_gaps(_sample_checklist(), [])
        assert len(gaps) == 4

    def test_covered_functions_excluded(self):
        gaps = compute_gaps(_sample_checklist(), _sample_coverage_records())
        names = {g["name"] for g in gaps}
        assert "parse_request" not in names
        assert "handle_error" in names
        assert "check_password" in names

    def test_sorted_by_priority(self):
        gaps = compute_gaps(_sample_checklist(), _sample_coverage_records())
        priorities = [g["priority"] for g in gaps]
        assert priorities == sorted(priorities)

    def test_no_tool_coverage_highest_priority(self):
        gaps = compute_gaps(_sample_checklist(), _sample_coverage_records())
        auth_gap = next(g for g in gaps if g["name"] == "check_password")
        assert auth_gap["priority"] == PRIORITY_NO_TOOL_COVERAGE

    def test_partial_coverage_medium_priority(self):
        gaps = compute_gaps(_sample_checklist(), _sample_coverage_records())
        handler_gap = next(g for g in gaps if g["name"] == "handle_error")
        assert handler_gap["priority"] == PRIORITY_PARTIAL_TOOL_COVERAGE

    def test_trivial_function_deprioritized(self):
        gaps = compute_gaps(_sample_checklist(), [])
        tiny_gap = next(g for g in gaps if g["name"] == "tiny_helper")
        assert tiny_gap["priority"] == PRIORITY_FULLY_COVERED

    def test_trivial_entry_point_demoted(self):
        checklist = {
            "files": [
                {
                    "path": "a.c",
                    "items": [
                        {"name": "big_handler", "line_start": 1, "line_end": 100},
                        {"name": "tiny_wrapper", "line_start": 101, "line_end": 104},
                    ],
                },
            ],
        }
        context_map = {
            "entry_points": [
                {"file": "a.c", "name": "big_handler"},
                {"file": "a.c", "name": "tiny_wrapper"},
            ],
        }
        gaps = compute_gaps(checklist, [], context_map=context_map)
        big = next(g for g in gaps if g["name"] == "big_handler")
        tiny = next(g for g in gaps if g["name"] == "tiny_wrapper")
        assert big["priority"] == PRIORITY_ENTRY_POINT
        assert tiny["priority"] == PRIORITY_NO_TOOL_COVERAGE

    def test_strategy_filter(self):
        gaps = compute_gaps(
            _sample_checklist(), [],
            strategy_filter="auth",
        )
        names = {g["name"] for g in gaps}
        assert "check_password" in names
        for g in gaps:
            assert "auth" in g["strategies"]

    def test_budget_limits_results(self):
        gaps = compute_gaps(_sample_checklist(), [], budget=2)
        assert len(gaps) == 2

    def test_strategies_assigned(self):
        gaps = compute_gaps(_sample_checklist(), [])
        for g in gaps:
            assert "general" in g["strategies"]

    def test_context_map_sinks_boost_priority(self):
        context_map = {
            "entry_points": [
                {
                    "file": "src/auth.c",
                    "name": "check_password",
                    "reachable_sinks": ["os.system"],
                },
            ],
        }
        gaps = compute_gaps(
            _sample_checklist(), _sample_coverage_records(),
            context_map=context_map,
        )
        auth_gap = next(g for g in gaps if g["name"] == "check_password")
        assert auth_gap["priority"] <= PRIORITY_NO_TOOL_COVERAGE
        assert "reachable_sinks" in auth_gap

    def test_empty_checklist(self):
        gaps = compute_gaps({}, [])
        assert gaps == []

    def test_all_covered(self):
        records = [
            {
                "tool": "audit",
                "files": {
                    "src/handler.c": {
                        "functions": {
                            "parse_request": {},
                            "handle_error": {},
                            "tiny_helper": {},
                        },
                    },
                    "src/auth.c": {
                        "functions": {
                            "check_password": {},
                        },
                    },
                },
            },
        ]
        gaps = compute_gaps(_sample_checklist(), records)
        assert len(gaps) == 0

    def test_checked_by_no_longer_excludes(self):
        """Post-migration: ``checked_by`` on checklist items is no
        longer consulted by ``compute_gaps``. LLM-review existence
        flows via the coverage store (imported from the review
        journal at run completion), not via checklist mutation.
        A stale ``checked_by`` on a checklist item should NOT
        suppress a gap — otherwise pre-migration state would ghost-
        skip functions after the migration."""
        checklist = {
            "files": [
                {
                    "path": "src/handler.c",
                    "items": [
                        {"name": "f1", "line_start": 1, "line_end": 20},
                        {"name": "f2", "line_start": 25, "line_end": 40,
                         "checked_by": ["audit"]},
                    ],
                },
            ],
        }
        gaps = compute_gaps(checklist, [])
        names = {g["name"] for g in gaps}
        assert "f1" in names
        assert "f2" in names  # not excluded by legacy checked_by

    def test_scope_filters_to_prefix(self):
        gaps = compute_gaps(_sample_checklist(), [], scope="src/auth")
        names = {g["name"] for g in gaps}
        assert "check_password" in names
        assert "parse_request" not in names
        assert "handle_error" not in names

    def test_scope_none_includes_all(self):
        gaps = compute_gaps(_sample_checklist(), [])
        assert len(gaps) == 4

    def test_scope_no_match_returns_empty(self):
        gaps = compute_gaps(_sample_checklist(), [], scope="nonexistent/")
        assert gaps == []

    def test_binary_absent_deprioritized(self):
        checklist = {
            "files": [
                {
                    "path": "src/handler.c",
                    "items": [
                        {
                            "name": "live_fn",
                            "line_start": 10,
                            "line_end": 50,
                            "metadata": {
                                "binary_oracle": {
                                    "classification": "symbol_present",
                                },
                            },
                        },
                        {
                            "name": "dead_fn",
                            "line_start": 55,
                            "line_end": 100,
                            "metadata": {
                                "binary_oracle": {
                                    "classification": "absent",
                                },
                            },
                        },
                    ],
                },
            ],
        }
        gaps = compute_gaps(checklist, [])
        live = next(g for g in gaps if g["name"] == "live_fn")
        dead = next(g for g in gaps if g["name"] == "dead_fn")
        assert dead["priority"] == PRIORITY_DEAD_CODE
        assert live["priority"] < dead["priority"]

    def test_binary_absent_sorted_last(self):
        checklist = {
            "files": [
                {
                    "path": "src/handler.c",
                    "items": [
                        {
                            "name": "dead_fn",
                            "line_start": 10,
                            "line_end": 100,
                            "metadata": {
                                "binary_oracle": {
                                    "classification": "absent",
                                },
                            },
                        },
                        {
                            "name": "normal_fn",
                            "line_start": 110,
                            "line_end": 200,
                        },
                    ],
                },
            ],
        }
        gaps = compute_gaps(checklist, [])
        assert gaps[-1]["name"] == "dead_fn"


class TestLoadChecklist:
    def test_load_existing(self, tmp_path: Path):
        checklist_path = tmp_path / "checklist.json"
        data = {"target_path": "/tmp/t", "files": []}
        checklist_path.write_text(json.dumps(data))

        result = load_checklist(tmp_path)
        assert result["target_path"] == "/tmp/t"

    def test_load_missing(self, tmp_path: Path):
        result = load_checklist(tmp_path)
        assert result == {}

    def test_load_malformed_returns_empty(self, tmp_path: Path):
        (tmp_path / "checklist.json").write_text("{not json")
        assert load_checklist(tmp_path) == {}

    def test_load_non_dict_returns_empty(self, tmp_path: Path):
        # A JSON array is corrupt for every consumer that calls .get()
        # on the checklist — the shared accessor normalises it to {}.
        (tmp_path / "checklist.json").write_text("[1, 2, 3]")
        assert load_checklist(tmp_path) == {}

    def test_load_routes_through_shared_accessor(self, tmp_path: Path,
                                                 monkeypatch):
        # The audit read side must share the inventory writers' flock +
        # project-symlink resolution (torn-read protection).
        import core.inventory as inv
        calls = []

        def _spy(output_dir):
            calls.append(Path(output_dir))
            return {"spied": True}

        monkeypatch.setattr(inv, "read_checklist", _spy)
        assert load_checklist(tmp_path) == {"spied": True}
        assert calls == [tmp_path]

    def test_load_reads_project_checklist_through_symlink(
            self, tmp_path: Path):
        project = tmp_path / "project"
        run_dir = project / "run-001"
        run_dir.mkdir(parents=True)
        (project / "checklist.json").write_text(
            json.dumps({"version": "project-level"}))
        (run_dir / "checklist.json").symlink_to("../checklist.json")

        assert load_checklist(run_dir)["version"] == "project-level"


class TestLoadContextMap:
    def test_load_existing(self, tmp_path: Path):
        cm_path = tmp_path / "context-map.json"
        data = {"entry_points": [], "sink_details": []}
        cm_path.write_text(json.dumps(data))

        result = load_context_map(tmp_path)
        assert result is not None
        assert "entry_points" in result

    def test_load_missing(self, tmp_path: Path):
        result = load_context_map(tmp_path)
        assert result is None


class TestFuzzPriority:
    def test_heavy_fuzz_no_crashes_deprioritized(self):
        fuzz = {
            "files": {
                "src/handler.c": {
                    "functions": {
                        "parse_request": {
                            "iterations": 50_000,
                            "crashes": 0,
                        },
                    },
                },
            },
        }
        gaps = compute_gaps(_sample_checklist(), [], fuzz_coverage=fuzz)
        fuzzed = next(g for g in gaps if g["name"] == "parse_request")
        unfuzzed = next(g for g in gaps if g["name"] == "handle_error")
        assert fuzzed["priority"] >= unfuzzed["priority"]

    def test_fuzz_with_crashes_not_deprioritized(self):
        fuzz = {
            "files": {
                "src/handler.c": {
                    "functions": {
                        "parse_request": {
                            "iterations": 50_000,
                            "crashes": 3,
                        },
                    },
                },
            },
        }
        gaps = compute_gaps(_sample_checklist(), [], fuzz_coverage=fuzz)
        fuzzed = next(g for g in gaps if g["name"] == "parse_request")
        unfuzzed = next(g for g in gaps if g["name"] == "handle_error")
        assert fuzzed["priority"] == unfuzzed["priority"]

    def test_no_fuzz_data_no_change(self):
        gaps_no_fuzz = compute_gaps(_sample_checklist(), [])
        gaps_with_fuzz = compute_gaps(_sample_checklist(), [], fuzz_coverage={})
        assert len(gaps_no_fuzz) == len(gaps_with_fuzz)
        for a, b in zip(gaps_no_fuzz, gaps_with_fuzz):
            assert a["priority"] == b["priority"]


class TestWriteGaps:
    def test_writes_json(self, tmp_path: Path):
        gaps = [{"file": "a.c", "name": "foo", "priority": 0}]
        path = write_gaps(gaps, tmp_path)
        assert path.exists()

        with open(path) as f:
            data = json.load(f)
        assert data["count"] == 1
        assert len(data["gaps"]) == 1


# ``TestMarkChecked`` removed — ``mark_checked`` was deleted at
# Phase-3 completion (annotation → journal migration). Checklist is
# a pure inventory snapshot post-migration; LLM review state lives
# exclusively in the review journal. See amendment §2.


# ---------------------------------------------------------------------------
# Dead-code flag propagation
# ---------------------------------------------------------------------------


def test_lexical_dead_propagated():
    checklist = {
        "files": [{
            "path": "a.py",
            "items": [
                {"name": "dead_fn", "line_start": 5, "line_end": 10,
                 "lexical_dead": True},
                {"name": "live_fn", "line_start": 15, "line_end": 20},
            ],
        }],
    }
    gaps = compute_gaps(checklist, [])
    by_name = {g["name"]: g for g in gaps}
    assert by_name["dead_fn"].get("lexical_dead") is True
    assert "lexical_dead" not in by_name["live_fn"]


def test_module_aborts_on_load_propagated():
    checklist = {
        "files": [{
            "path": "b.py",
            "module_aborts_on_load": {"line": 3, "summary": "raise ImportError"},
            "items": [
                {"name": "before_abort", "line_start": 1, "line_end": 2},
                {"name": "after_abort", "line_start": 5, "line_end": 10},
            ],
        }],
    }
    gaps = compute_gaps(checklist, [])
    by_name = {g["name"]: g for g in gaps}
    assert "module_aborts_on_load" not in by_name["before_abort"]
    assert by_name["after_abort"].get("module_aborts_on_load") is True


def test_build_excluded_propagated():
    checklist = {
        "files": [{
            "path": "c.go",
            "build_excluded": {"line": 1, "summary": "//go:build ignore"},
            "items": [
                {"name": "excluded_fn", "line_start": 5, "line_end": 15},
            ],
        }],
    }
    gaps = compute_gaps(checklist, [])
    assert gaps[0].get("build_excluded") is True


def test_dead_flag_set_for_all_dead_code_signals():
    checklist = {
        "files": [
            {
                "path": "a.py",
                "items": [
                    {"name": "lexical", "line_start": 5, "line_end": 10,
                     "lexical_dead": True},
                    {"name": "live", "line_start": 15, "line_end": 20},
                ],
            },
            {
                "path": "b.py",
                "module_aborts_on_load": {"line": 3, "summary": "raise"},
                "items": [
                    {"name": "after_abort", "line_start": 5, "line_end": 10},
                ],
            },
            {
                "path": "c.go",
                "build_excluded": {"line": 1, "summary": "//go:build ignore"},
                "items": [
                    {"name": "excluded", "line_start": 5, "line_end": 15},
                ],
            },
        ],
    }
    gaps = compute_gaps(checklist, [])
    by_name = {g["name"]: g for g in gaps}
    assert by_name["lexical"].get("dead") is True
    assert by_name["after_abort"].get("dead") is True
    assert by_name["excluded"].get("dead") is True
    assert "dead" not in by_name["live"]


class TestCoveredKeyInjectivity:
    """Colon-bearing filenames must not alias another function's
    coverage — the covered-set keys use the injective encoding."""

    def _checklist(self):
        return {
            "target_path": "/tmp/target",
            "files": [
                {
                    "path": "src/a.c:evil",
                    "items": [
                        {"name": "f", "line_start": 1, "line_end": 20},
                    ],
                },
                {
                    "path": "src/a.c",
                    "items": [
                        {"name": "evil:f", "line_start": 1, "line_end": 20},
                    ],
                },
            ],
        }

    def test_coverage_record_does_not_alias(self):
        records = [{
            "tool": "semgrep",
            "files": {
                "src/a.c:evil": {"functions": {"f": {"status": "clean"}}},
            },
            "files_examined": ["src/a.c:evil"],
        }]
        gaps = compute_gaps(self._checklist(), records)
        remaining = {(g["file"], g["name"]) for g in gaps}
        assert ("src/a.c", "evil:f") in remaining
        assert ("src/a.c:evil", "f") not in remaining

    def test_journal_fold_does_not_alias(self, tmp_path):
        from core.coverage.journal import ReviewJournalEntry, append_entry, now_iso
        append_entry(tmp_path, ReviewJournalEntry(
            ts=now_iso(),
            run_id="test",
            file="src/a.c:evil",
            function="f",
            verdict="clean",
            source_hash="",
        ))
        gaps = compute_gaps(self._checklist(), [], out_dir=tmp_path)
        remaining = {(g["file"], g["name"]) for g in gaps}
        assert ("src/a.c", "evil:f") in remaining
        assert ("src/a.c:evil", "f") not in remaining

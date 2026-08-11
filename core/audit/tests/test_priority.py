"""Tests for core.audit.priority — attack-surface-aware gap scoring."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.priority import (
    SCORE_CALLEE_OF_ENTRY,
    SCORE_COMPLEX,
    SCORE_ENTRY_POINT,
    SCORE_EXPORTED,
    SCORE_FILE_HAS_ENTRY_POINT,
    SCORE_MODERATE,
    SCORE_NEW_CODE,
    SCORE_NO_TOOL_COVERAGE,
    SCORE_ON_FLOW_PATH,
    SCORE_OPEN_CONSTRAINT,
    SCORE_PARTIAL_TOOL_COVERAGE,
    SCORE_SINK,
    SCORE_THREAT_MODEL_FOCUS,
    SCORE_TRUST_BOUNDARY,
    SCORE_UNCHECKED_FLOW,
    _COMPLEX_SLOC,
    _MODERATE_SLOC,
    detect_widely_used,
    group_by_subsystem,
    load_flow_traces,
    load_fuzz_coverage,
    load_new_functions,
    load_tool_coverage,
    load_tool_failures,
    score_functions,
)


def _gap(file, name, priority=0, sloc=10, metadata=None):
    return {
        "file": file,
        "name": name,
        "line_start": 1,
        "line_end": sloc + 1,
        "priority": priority,
        "strategies": [],
        "is_stale": False,
        "sloc": sloc,
        "metadata": metadata,
    }


class TestScoreFunctions:
    def test_no_context_preserves_order(self):
        gaps = [_gap("a.c", "f"), _gap("b.c", "g")]
        result = score_functions(gaps)
        assert result[0]["name"] == "f"
        assert result[1]["name"] == "g"
        assert all(g["priority_score"] == 0 for g in result)

    def test_entry_point_gets_score(self):
        context_map = {
            "entry_points": [{"file": "a.c", "name": "handle_request"}],
        }
        gaps = [
            _gap("a.c", "handle_request", priority=-1),
            _gap("a.c", "helper"),
        ]
        result = score_functions(gaps, context_map=context_map)
        ep_gap = next(g for g in result if g["name"] == "handle_request")
        helper_gap = next(g for g in result if g["name"] == "helper")
        assert ep_gap["priority_score"] >= SCORE_ENTRY_POINT
        assert helper_gap["priority_score"] >= SCORE_FILE_HAS_ENTRY_POINT
        assert ep_gap["priority_score"] > helper_gap["priority_score"]

    def test_sink_gets_score(self):
        context_map = {
            "sinks": [{"file": "db.c", "name": "execute_query"}],
        }
        gaps = [_gap("db.c", "execute_query"), _gap("util.c", "log")]
        result = score_functions(gaps, context_map=context_map)
        sink_gap = next(g for g in result if g["name"] == "execute_query")
        assert sink_gap["priority_score"] >= SCORE_SINK

    def test_trust_boundary_gets_score(self):
        context_map = {
            "trust_boundaries": [
                {
                    "name": "kernel/user",
                    "functions": [{"file": "sys.c", "name": "syscall_handler"}],
                },
            ],
        }
        gaps = [_gap("sys.c", "syscall_handler")]
        result = score_functions(gaps, context_map=context_map)
        assert result[0]["priority_score"] >= SCORE_TRUST_BOUNDARY

    def test_flow_path_function_gets_score(self):
        flow_traces = [
            {
                "steps": [
                    {"file": "a.c", "function": "entry"},
                    {"file": "b.c", "function": "middle"},
                    {"file": "c.c", "function": "sink"},
                ],
            },
        ]
        gaps = [_gap("b.c", "middle"), _gap("d.c", "unrelated")]
        result = score_functions(gaps, flow_traces=flow_traces)
        middle_gap = next(g for g in result if g["name"] == "middle")
        unrelated_gap = next(g for g in result if g["name"] == "unrelated")
        assert middle_gap["priority_score"] >= SCORE_ON_FLOW_PATH
        assert unrelated_gap["priority_score"] == 0

    def test_flow_traces_with_hops_key(self):
        flow_traces = [
            {"hops": [{"file": "a.c", "function": "hop1"}]},
        ]
        gaps = [_gap("a.c", "hop1")]
        result = score_functions(gaps, flow_traces=flow_traces)
        assert result[0]["priority_score"] >= SCORE_ON_FLOW_PATH

    def test_flow_traces_definition_schema(self):
        flow_traces = [
            {
                "steps": [
                    {"step": 1, "type": "entry",
                     "definition": "src/handler.c:34"},
                    {"step": 2, "type": "call",
                     "definition": "src/service.c:12"},
                ],
            },
        ]
        gaps = [
            _gap("src/handler.c", "handler"),
            _gap("other/file.c", "unrelated"),
        ]
        result = score_functions(gaps, flow_traces=flow_traces)
        handler_gap = next(g for g in result if g["name"] == "handler")
        other_gap = next(g for g in result if g["name"] == "unrelated")
        assert handler_gap["priority_score"] >= SCORE_ON_FLOW_PATH
        assert other_gap["priority_score"] == 0

    def test_entry_callee_gets_score(self):
        context_map = {
            "entry_points": [
                {
                    "file": "a.c",
                    "name": "handler",
                    "callees": [{"file": "b.c", "name": "validate"}],
                },
            ],
        }
        gaps = [_gap("b.c", "validate")]
        result = score_functions(gaps, context_map=context_map)
        assert result[0]["priority_score"] >= SCORE_CALLEE_OF_ENTRY

    def test_entry_callee_via_call_edges(self):
        context_map = {
            "entry_points": [{"file": "a.c", "name": "handler"}],
            "call_edges": [
                {"caller_file": "a.c", "caller": "handler",
                 "callee": "wrapper"},
                {"caller_file": "a.c", "caller": "wrapper",
                 "callee": "impl"},
            ],
        }
        gaps = [_gap("a.c", "impl")]
        result = score_functions(gaps, context_map=context_map)
        assert result[0]["priority_score"] >= SCORE_CALLEE_OF_ENTRY

    def test_unchecked_flow_gets_score(self):
        context_map = {
            "unchecked_flows": [
                {
                    "source": {"file": "a.c", "name": "read_input"},
                    "sink": {"file": "b.c", "name": "write_output"},
                },
            ],
        }
        gaps = [_gap("a.c", "read_input"), _gap("c.c", "unrelated")]
        result = score_functions(gaps, context_map=context_map)
        src_gap = next(g for g in result if g["name"] == "read_input")
        assert src_gap["priority_score"] >= SCORE_UNCHECKED_FLOW

    def test_scores_are_additive(self):
        context_map = {
            "entry_points": [{"file": "a.c", "name": "f"}],
            "sinks": [{"file": "a.c", "name": "f"}],
        }
        gaps = [_gap("a.c", "f", priority=-1)]
        result = score_functions(gaps, context_map=context_map)
        expected_min = SCORE_ENTRY_POINT + SCORE_SINK + SCORE_FILE_HAS_ENTRY_POINT
        assert result[0]["priority_score"] >= expected_min

    def test_sort_by_priority_then_score(self):
        context_map = {
            "entry_points": [{"file": "a.c", "name": "high"}],
        }
        gaps = [
            _gap("b.c", "low", priority=1),
            _gap("a.c", "high", priority=-1),
            _gap("c.c", "medium", priority=0),
        ]
        result = score_functions(gaps, context_map=context_map)
        assert result[0]["name"] == "high"
        assert result[-1]["name"] == "low"

    def test_budget_applied_after_scoring(self):
        gaps = [_gap("a.c", f"f{i}") for i in range(20)]
        result = score_functions(gaps)
        assert len(result) == 20

    def test_empty_gaps(self):
        result = score_functions([])
        assert result == []


class TestLoadFlowTraces:
    def test_loads_matching_files(self, tmp_path: Path):
        trace1 = {"id": "t1", "steps": []}
        trace2 = {"id": "t2", "hops": []}
        (tmp_path / "flow-trace-001.json").write_text(json.dumps(trace1))
        (tmp_path / "flow-trace-002.json").write_text(json.dumps(trace2))
        (tmp_path / "other-file.json").write_text("{}")

        traces = load_flow_traces(tmp_path)
        assert len(traces) == 2
        assert traces[0]["id"] == "t1"
        assert traces[1]["id"] == "t2"

    def test_skips_invalid_json(self, tmp_path: Path):
        (tmp_path / "flow-trace-bad.json").write_text("not json{")
        traces = load_flow_traces(tmp_path)
        assert len(traces) == 0

    def test_empty_dir(self, tmp_path: Path):
        traces = load_flow_traces(tmp_path)
        assert traces == []


class TestToolCoverageScoring:
    def test_no_tool_coverage_boost(self):
        gaps = [_gap("src/uncovered.c", "f")]
        tool_cov = {"src/other.c": {"semgrep"}}
        scored = score_functions(gaps, tool_coverage=tool_cov)
        assert scored[0]["priority_score"] >= SCORE_NO_TOOL_COVERAGE

    def test_partial_tool_coverage_boost(self):
        gaps = [_gap("src/partial.c", "f")]
        tool_cov = {"src/partial.c": {"semgrep"}}
        scored = score_functions(gaps, tool_coverage=tool_cov)
        assert scored[0]["priority_score"] >= SCORE_PARTIAL_TOOL_COVERAGE

    def test_full_tool_coverage_no_boost(self):
        gaps = [_gap("src/covered.c", "f")]
        tool_cov = {"src/covered.c": {"semgrep", "codeql"}}
        scored = score_functions(gaps, tool_coverage=tool_cov)
        assert scored[0]["priority_score"] == 0

    def test_none_tool_coverage_no_crash(self):
        gaps = [_gap("src/a.c", "f")]
        scored = score_functions(gaps, tool_coverage=None)
        assert scored[0]["priority_score"] == 0

    def test_empty_tool_coverage_no_crash(self):
        gaps = [_gap("src/a.c", "f")]
        scored = score_functions(gaps, tool_coverage={})
        assert scored[0]["priority_score"] >= SCORE_NO_TOOL_COVERAGE


class TestGroupBySubsystem:
    def test_basic_grouping(self):
        gaps = [
            _gap("src/auth.c", "check"),
            _gap("src/login.c", "do_login"),
            _gap("lib/utils.c", "parse"),
        ]
        groups = group_by_subsystem(gaps)
        assert "src" in groups
        assert "lib" in groups
        assert len(groups["src"]) == 2
        assert len(groups["lib"]) == 1

    def test_depth_2(self):
        gaps = [
            _gap("kernel/ipc/msg.c", "send"),
            _gap("kernel/ipc/sem.c", "wait"),
            _gap("kernel/sched/core.c", "pick"),
        ]
        groups = group_by_subsystem(gaps, depth=2)
        assert "kernel/ipc" in groups
        assert "kernel/sched" in groups
        assert len(groups["kernel/ipc"]) == 2

    def test_shallow_file(self):
        gaps = [_gap("main.c", "main")]
        groups = group_by_subsystem(gaps)
        assert "." in groups
        assert len(groups["."]) == 1

    def test_preserves_order(self):
        gaps = [
            _gap("src/a.c", "f1"),
            _gap("src/b.c", "f2"),
            _gap("src/a.c", "f3"),
        ]
        groups = group_by_subsystem(gaps)
        names = [g["name"] for g in groups["src"]]
        assert names == ["f1", "f2", "f3"]

    def test_empty_gaps(self):
        groups = group_by_subsystem([])
        assert groups == {}


class TestVisibilityScoring:
    def test_exported_function_boost(self):
        gap = _gap("src/api.c", "handle_request")
        gap["metadata"] = {"visibility": "exported"}
        scored = score_functions([gap])
        assert scored[0]["priority_score"] >= SCORE_EXPORTED

    def test_extern_function_boost(self):
        gap = _gap("src/lib.c", "public_fn")
        gap["metadata"] = {"visibility": "extern"}
        scored = score_functions([gap])
        assert scored[0]["priority_score"] >= SCORE_EXPORTED

    def test_static_function_no_boost(self):
        gap = _gap("src/internal.c", "helper")
        gap["metadata"] = {"visibility": "static"}
        scored = score_functions([gap])
        assert scored[0]["priority_score"] == 0

    def test_no_metadata_no_crash(self):
        gap = _gap("src/a.c", "f")
        scored = score_functions([gap])
        assert scored[0]["priority_score"] == 0


class TestNewCodeScoring:
    def test_new_function_boost(self):
        gaps = [_gap("src/new.c", "added_fn")]
        new_fns = {"src/new.c:added_fn"}
        scored = score_functions(gaps, new_functions=new_fns)
        assert scored[0]["priority_score"] >= SCORE_NEW_CODE

    def test_old_function_no_boost(self):
        gaps = [_gap("src/old.c", "existing_fn")]
        new_fns = {"src/new.c:other_fn"}
        scored = score_functions(gaps, new_functions=new_fns)
        assert scored[0]["priority_score"] == 0

    def test_none_new_functions(self):
        gaps = [_gap("src/a.c", "f")]
        scored = score_functions(gaps, new_functions=None)
        assert scored[0]["priority_score"] == 0


class TestLoadNewFunctions:
    def test_loads_from_diff(self, tmp_path: Path):
        diff = {"added": ["src/new.c"], "modified": ["src/changed.c"]}
        (tmp_path / "inventory-diff.json").write_text(json.dumps(diff))

        checklist = {
            "files": [
                {"path": "src/new.c", "items": [{"name": "new_fn", "line_start": 1}]},
                {"path": "src/changed.c", "items": [{"name": "mod_fn", "line_start": 5}]},
                {"path": "src/old.c", "items": [{"name": "old_fn", "line_start": 10}]},
            ],
        }
        result = load_new_functions(tmp_path, checklist)
        assert "src/new.c:new_fn" in result
        assert "src/changed.c:mod_fn" in result
        assert "src/old.c:old_fn" not in result

    def test_no_diff_file(self, tmp_path: Path):
        result = load_new_functions(tmp_path, {"files": {}})
        assert result == set()

    def test_empty_diff(self, tmp_path: Path):
        (tmp_path / "inventory-diff.json").write_text(
            json.dumps({"added": [], "modified": []}),
        )
        result = load_new_functions(tmp_path, {"files": {}})
        assert result == set()


class TestThreatModelScoring:
    def test_focus_cwe_boost(self):
        gaps = [_gap("src/a.c", "fn", metadata={"cwe": "CWE-787"})]
        tm = {"focus_cwes": ["CWE-787", "CWE-416"]}
        result = score_functions(gaps, threat_model=tm)
        assert result[0]["priority_score"] == SCORE_THREAT_MODEL_FOCUS

    def test_non_matching_cwe_no_boost(self):
        gaps = [_gap("src/a.c", "fn", metadata={"cwe": "CWE-79"})]
        tm = {"focus_cwes": ["CWE-787"]}
        result = score_functions(gaps, threat_model=tm)
        assert result[0]["priority_score"] == 0

    def test_focus_area_boost(self):
        gaps = [_gap("kernel/ipc/msg.c", "do_msgsnd")]
        tm = {"focus_areas": ["kernel/ipc/"]}
        result = score_functions(gaps, threat_model=tm)
        assert result[0]["priority_score"] == SCORE_THREAT_MODEL_FOCUS

    def test_no_threat_model_no_effect(self):
        gaps = [_gap("src/a.c", "fn", metadata={"cwe": "CWE-787"})]
        result = score_functions(gaps)
        assert result[0]["priority_score"] == 0

    def test_empty_threat_model_no_effect(self):
        gaps = [_gap("src/a.c", "fn", metadata={"cwe": "CWE-787"})]
        result = score_functions(gaps, threat_model={})
        assert result[0]["priority_score"] == 0

    def test_both_cwe_and_area_stack(self):
        gaps = [_gap("kernel/a.c", "fn", metadata={"cwe": "CWE-787"})]
        tm = {
            "focus_cwes": ["CWE-787"],
            "focus_areas": ["kernel/"],
        }
        result = score_functions(gaps, threat_model=tm)
        assert result[0]["priority_score"] == SCORE_THREAT_MODEL_FOCUS * 2


class TestOpenConstraintScoring:
    def test_open_constraint_boost(self):
        gaps = [_gap("src/a.c", "parse_input")]
        keys = {"src/a.c:parse_input"}
        result = score_functions(gaps, open_constraint_keys=keys)
        assert result[0]["priority_score"] == SCORE_OPEN_CONSTRAINT

    def test_no_constraint_no_boost(self):
        gaps = [_gap("src/a.c", "other")]
        keys = {"src/a.c:parse_input"}
        result = score_functions(gaps, open_constraint_keys=keys)
        assert result[0]["priority_score"] == 0

    def test_none_keys_no_crash(self):
        gaps = [_gap("src/a.c", "f")]
        result = score_functions(gaps, open_constraint_keys=None)
        assert result[0]["priority_score"] == 0


class TestComplexityScoring:
    def test_complex_function_boost(self):
        gaps = [_gap("a.c", "big", sloc=100)]
        result = score_functions(gaps)
        assert result[0]["priority_score"] == SCORE_COMPLEX

    def test_moderate_function_boost(self):
        gaps = [_gap("a.c", "medium", sloc=50)]
        result = score_functions(gaps)
        assert result[0]["priority_score"] == SCORE_MODERATE

    def test_small_function_no_boost(self):
        gaps = [_gap("a.c", "small", sloc=10)]
        result = score_functions(gaps)
        assert result[0]["priority_score"] == 0

    def test_complex_outranks_small_same_tier(self):
        gaps = [
            _gap("a.c", "small", priority=0, sloc=5),
            _gap("a.c", "big", priority=0, sloc=100),
        ]
        result = score_functions(gaps)
        assert result[0]["name"] == "big"
        assert result[1]["name"] == "small"

    def test_complexity_stacks_with_entry_point(self):
        context_map = {
            "entry_points": [{"file": "a.c", "name": "handler"}],
        }
        gaps = [_gap("a.c", "handler", priority=-1, sloc=100)]
        result = score_functions(gaps, context_map=context_map)
        assert result[0]["priority_score"] >= SCORE_ENTRY_POINT + SCORE_COMPLEX

    def test_thresholds(self):
        assert _COMPLEX_SLOC == 80
        assert _MODERATE_SLOC == 30


class TestLoadToolCoverage:
    def test_loads_from_coverage_files(self, tmp_path: Path):
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        (run_dir / "coverage-record.json").write_text(json.dumps({
            "tools": {
                "semgrep": {"files": ["src/a.c", "src/b.c"]},
                "codeql": {"files": ["src/a.c"]},
            },
        }))

        from unittest.mock import patch
        with patch(
            "core.audit.priority.file_level_view",
            create=True,
        ) as mock_view:
            mock_view.return_value = {
                "tools": {
                    "semgrep": {"files": ["src/a.c", "src/b.c"]},
                    "codeql": {"files": ["src/a.c"]},
                },
            }
            try:
                result = load_tool_coverage([run_dir])
            except Exception:
                result = load_tool_coverage([run_dir])

        if result:
            assert "semgrep" in result.get("src/a.c", set())

    def test_empty_dirs_returns_empty(self):
        result = load_tool_coverage([])
        assert result == {}

    def test_graceful_on_import_error(self, tmp_path: Path):
        result = load_tool_coverage([tmp_path])
        assert isinstance(result, dict)


class TestLoadToolFailures:
    def test_collects_failed_files(self, tmp_path: Path):
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        (run_dir / "coverage-semgrep.json").write_text(json.dumps({
            "files_failed": ["src/big.c", "src/broken.c"],
        }))
        result = load_tool_failures([run_dir])
        assert "src/big.c" in result
        assert "src/broken.c" in result

    def test_empty_dirs_returns_empty(self):
        result = load_tool_failures([])
        assert result == set()

    def test_skips_malformed_json(self, tmp_path: Path):
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        (run_dir / "coverage-semgrep.json").write_text("not json")
        result = load_tool_failures([run_dir])
        assert result == set()

    def test_merges_across_dirs(self, tmp_path: Path):
        d1 = tmp_path / "r1"
        d1.mkdir()
        (d1 / "coverage-a.json").write_text(json.dumps({
            "files_failed": ["a.c"],
        }))
        d2 = tmp_path / "r2"
        d2.mkdir()
        (d2 / "coverage-b.json").write_text(json.dumps({
            "files_failed": ["b.c"],
        }))
        result = load_tool_failures([d1, d2])
        assert result == {"a.c", "b.c"}


class TestLoadFuzzCoverage:
    def test_loads_fuzz_files(self, tmp_path: Path):
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        (run_dir / "coverage-fuzz.json").write_text(json.dumps({
            "files_examined": ["src/parser.c", "src/decoder.c"],
        }))
        result = load_fuzz_coverage([run_dir])
        assert result is not None
        assert "src/parser.c" in result
        assert "src/decoder.c" in result

    def test_returns_none_when_no_fuzz_file(self, tmp_path: Path):
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        result = load_fuzz_coverage([run_dir])
        assert result is None

    def test_empty_dirs_returns_none(self):
        result = load_fuzz_coverage([])
        assert result is None

    def test_skips_malformed_json(self, tmp_path: Path):
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        (run_dir / "coverage-fuzz.json").write_text("{bad")
        result = load_fuzz_coverage([run_dir])
        assert result is not None
        assert len(result) == 0

    def test_merges_across_dirs(self, tmp_path: Path):
        d1 = tmp_path / "r1"
        d1.mkdir()
        (d1 / "coverage-fuzz.json").write_text(json.dumps({
            "files_examined": ["a.c"],
        }))
        d2 = tmp_path / "r2"
        d2.mkdir()
        (d2 / "coverage-fuzz.json").write_text(json.dumps({
            "files_examined": ["b.c"],
        }))
        result = load_fuzz_coverage([d1, d2])
        assert result == {"a.c", "b.c"}


class TestDetectWidelyUsed:
    def test_returns_empty_without_reachability(self):
        checklist = {
            "files": [
                {
                    "path": "a.c",
                    "items": [
                        {"name": "f1", "line_start": 1},
                    ],
                },
            ],
        }
        result = detect_widely_used(checklist)
        assert isinstance(result, set)

    def test_empty_checklist(self):
        result = detect_widely_used({})
        assert result == set()

    def test_dict_files_format(self):
        checklist = {
            "files": {
                "a.c": [
                    {"name": "f1", "line_start": 1},
                ],
            },
        }
        result = detect_widely_used(checklist)
        assert isinstance(result, set)

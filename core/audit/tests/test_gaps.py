"""Tests for core.audit.gaps — gap computation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.gaps import (
    PRIORITY_DEAD_CODE,
    PRIORITY_ENTRY_POINT,
    PRIORITY_FULLY_COVERED,
    PRIORITY_NO_TOOL_COVERAGE,
    PRIORITY_PARTIAL_TOOL_COVERAGE,
    compute_gaps,
    load_checklist,
    load_context_map,
    mark_checked,
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

    def test_checked_by_excluded(self):
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
        assert "f2" not in names

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


class TestMarkChecked:
    def _write_checklist(self, tmp_path, checklist):
        path = tmp_path / "checklist.json"
        path.write_text(json.dumps(checklist))

    def _read_checklist(self, tmp_path):
        path = tmp_path / "checklist.json"
        return json.loads(path.read_text())

    def test_marks_function_checked(self, tmp_path: Path):
        checklist = {
            "files": [
                {
                    "path": "src/handler.c",
                    "items": [
                        {"name": "parse_request", "line_start": 10},
                    ],
                },
            ],
        }
        self._write_checklist(tmp_path, checklist)
        mark_checked(tmp_path, "src/handler.c", "parse_request", ["audit"])
        result = self._read_checklist(tmp_path)
        item = result["files"][0]["items"][0]
        assert "audit" in item["checked_by"]

    def test_merges_checked_by(self, tmp_path: Path):
        checklist = {
            "files": [
                {
                    "path": "a.c",
                    "items": [
                        {
                            "name": "f1",
                            "line_start": 1,
                            "checked_by": ["semgrep"],
                        },
                    ],
                },
            ],
        }
        self._write_checklist(tmp_path, checklist)
        mark_checked(tmp_path, "a.c", "f1", ["audit", "codeql"])
        result = self._read_checklist(tmp_path)
        checked = result["files"][0]["items"][0]["checked_by"]
        assert set(checked) == {"semgrep", "audit", "codeql"}

    def test_noop_when_missing_checklist(self, tmp_path: Path):
        mark_checked(tmp_path, "a.c", "f1", ["audit"])

    def test_noop_when_function_not_found(self, tmp_path: Path):
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
        self._write_checklist(tmp_path, checklist)
        mark_checked(tmp_path, "a.c", "nonexistent", ["audit"])
        result = self._read_checklist(tmp_path)
        assert "checked_by" not in result["files"][0]["items"][0]

    def test_atomic_write_survives(self, tmp_path: Path):
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
        self._write_checklist(tmp_path, checklist)
        mark_checked(tmp_path, "a.c", "f1", ["tool1"])
        mark_checked(tmp_path, "a.c", "f1", ["tool2"])
        result = self._read_checklist(tmp_path)
        checked = result["files"][0]["items"][0]["checked_by"]
        assert set(checked) == {"tool1", "tool2"}


class TestGapSourceHydration:
    """Gaps carry their function body so the mechanical detectors work.

    negative_space.discover_conventions and sibling_analysis both read
    ``gap["source"]`` and skip any gap without it, so an unhydrated gap
    list makes those passes silently no-op.
    """

    def _target(self, tmp_path: Path) -> Path:
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "handler.c").write_text(
            "\n".join(
                ["// line 1", "// line 2"]
                + [f"    body_{i}();" for i in range(3, 21)]
            )
            + "\n"
        )
        return target

    def _checklist(self):
        return {
            "files": [
                {
                    "path": "src/handler.c",
                    "items": [
                        {"name": "parse", "kind": "function",
                         "line_start": 3, "line_end": 8},
                    ],
                },
            ],
        }

    def test_source_absent_without_target_path(self):
        gaps = compute_gaps(self._checklist(), [])
        assert gaps
        assert "source" not in gaps[0]

    def test_source_present_with_target_path(self, tmp_path: Path):
        target = self._target(tmp_path)
        gaps = compute_gaps(self._checklist(), [], target_path=target)
        assert gaps
        assert "body_3();" in gaps[0]["source"]
        assert "body_8();" in gaps[0]["source"]

    def test_hydration_respects_the_line_span(self, tmp_path: Path):
        target = self._target(tmp_path)
        gaps = compute_gaps(self._checklist(), [], target_path=target)
        assert gaps[0]["source"].count("\n") == 6
        assert "body_9();" not in gaps[0]["source"]

    def test_missing_file_is_not_fatal(self, tmp_path: Path):
        target = tmp_path / "empty"
        target.mkdir()
        gaps = compute_gaps(self._checklist(), [], target_path=target)
        assert gaps
        assert "source" not in gaps[0]

    def test_path_traversal_is_refused(self, tmp_path: Path):
        target = self._target(tmp_path)
        (tmp_path / "secret.c").write_text("TOP SECRET\n" * 10)
        checklist = {
            "files": [
                {
                    "path": "../secret.c",
                    "items": [
                        {"name": "leak", "kind": "function",
                         "line_start": 1, "line_end": 5},
                    ],
                },
            ],
        }
        gaps = compute_gaps(checklist, [], target_path=target)
        assert gaps
        assert "source" not in gaps[0]

    def test_oversized_function_is_skipped(self, tmp_path: Path):
        target = self._target(tmp_path)
        checklist = {
            "files": [
                {
                    "path": "src/handler.c",
                    "items": [
                        {"name": "huge", "kind": "function",
                         "line_start": 1, "line_end": 100_000},
                    ],
                },
            ],
        }
        gaps = compute_gaps(checklist, [], target_path=target)
        assert "source" not in gaps[0]

    def test_hydrated_source_is_not_serialized_to_gaps_json(
        self, tmp_path: Path,
    ):
        """gaps.json must not become a copy of the scanned tree."""
        target = self._target(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        gaps = compute_gaps(self._checklist(), [], target_path=target)
        assert "source" in gaps[0]

        path = write_gaps(gaps, out_dir)
        written = json.loads(path.read_text())
        assert written["gaps"]
        assert "source" not in written["gaps"][0]
        # The in-memory list is untouched for the caller still using it.
        assert "source" in gaps[0]

    def test_negative_space_sees_hydrated_gaps(self, tmp_path: Path):
        """The end the hydration serves: conventions become discoverable."""
        from core.audit.negative_space import discover_conventions

        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        body = []
        for i in range(6):
            body.append(f"int handler_{i}(struct req *r) {{")
            body.append("    if (!check_permission(r)) return -EPERM;")
            body.append("    return do_work(r);")
            body.append("}")
        (target / "src" / "ops.c").write_text("\n".join(body) + "\n")

        items = [
            {"name": f"handler_{i}", "kind": "function",
             "line_start": 1 + i * 4, "line_end": 4 + i * 4}
            for i in range(6)
        ]
        checklist = {"files": [{"path": "src/ops.c", "items": items}]}

        dry = compute_gaps(checklist, [])
        assert discover_conventions(dry) == []

        hydrated = compute_gaps(checklist, [], target_path=target)
        assert all("source" in g for g in hydrated)
        assert discover_conventions(hydrated) != []


class TestGapSourceHydrationBounds:
    """The advertised ceiling has to be a real one."""

    def _target_with(self, tmp_path: Path, name: str, content: str) -> Path:
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True, exist_ok=True)
        (target / "src" / name).write_text(content)
        return target

    def _checklist(self, name: str, line_end: int):
        return {
            "files": [
                {
                    "path": f"src/{name}",
                    "items": [
                        {"name": "f", "kind": "function",
                         "line_start": 1, "line_end": line_end},
                    ],
                },
            ],
        }

    def test_repeated_calls_do_not_stack_budgets(self, tmp_path: Path):
        """Idempotence: already-hydrated bodies count against the total."""
        from core.audit.gaps import (
            _MAX_HYDRATED_TOTAL_BYTES,
            hydrate_gap_source,
        )

        target = self._target_with(tmp_path, "a.c", "x\n" * 100)
        gaps = [
            {"file": "src/a.c", "name": "f", "line_start": 1, "line_end": 10},
            {"file": "src/a.c", "name": "g", "line_start": 11, "line_end": 20},
        ]
        assert hydrate_gap_source(gaps, target) == 2
        # Second call is a no-op: everything already has source.
        assert hydrate_gap_source(gaps, target) == 0
        total = sum(len(g["source"].encode()) for g in gaps)
        assert total <= _MAX_HYDRATED_TOTAL_BYTES

    def test_binary_looking_file_is_refused(self, tmp_path: Path):
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "blob.c").write_bytes(b"int x;\n\x00\x00\x00binary\n" * 10)
        gaps = compute_gaps(
            self._checklist("blob.c", 5), [], target_path=target,
        )
        assert "source" not in gaps[0]

    def test_oversized_file_is_refused(self, tmp_path: Path):
        from core.audit.gaps import _MAX_HYDRATED_FILE_BYTES

        target = self._target_with(
            tmp_path, "big.c", "x" * (_MAX_HYDRATED_FILE_BYTES + 1) + "\n",
        )
        gaps = compute_gaps(
            self._checklist("big.c", 1), [], target_path=target,
        )
        assert "source" not in gaps[0]

    def test_single_huge_line_is_refused_by_the_byte_cap(self, tmp_path: Path):
        """A one-line minified body satisfies the SLOC bound but not bytes."""
        from core.audit.gaps import _MAX_HYDRATED_FUNCTION_BYTES

        target = self._target_with(
            tmp_path, "min.js", "y" * (_MAX_HYDRATED_FUNCTION_BYTES + 10) + "\n",
        )
        gaps = compute_gaps(
            self._checklist("min.js", 1), [], target_path=target,
        )
        assert "source" not in gaps[0]

    def test_symlink_escape_is_refused(self, tmp_path: Path):
        import os

        secret = tmp_path / "secret.c"
        secret.write_text("TOP SECRET\n" * 5)
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        try:
            os.symlink(secret, target / "src" / "link.c")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")

        gaps = compute_gaps(
            self._checklist("link.c", 3), [], target_path=target,
        )
        assert "source" not in gaps[0]

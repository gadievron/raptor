"""Tests for core.audit.sink_heuristics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from core.audit.sink_heuristics import (
    DiscoveredSink,
    SinkHeuristicsResult,
    discover_project_sinks,
    merge_discovered_sinks,
)


@dataclass
class FakeCall:
    caller: str
    chain: List[str]
    line: int = 0


@dataclass
class FakeCallGraph:
    calls: List[FakeCall] = field(default_factory=list)


@dataclass
class FakeSinkInfo:
    file: str
    function: str
    line: int
    target: str
    direct: bool = True


@dataclass
class FakeSinkResult:
    direct_sinks: List[FakeSinkInfo] = field(default_factory=list)
    transitive_reach: list = field(default_factory=list)
    framework_apis: list = field(default_factory=list)
    dangerous_target_counts: dict = field(default_factory=dict)


class TestDiscoverProjectSinks:
    def test_empty_inputs(self):
        result = discover_project_sinks(None)
        assert len(result.discovered) == 0

    def test_no_call_graphs(self):
        sr = FakeSinkResult(direct_sinks=[
            FakeSinkInfo("a.c", "dangerous_fn", 10, "system"),
        ])
        result = discover_project_sinks(sr)
        assert len(result.discovered) == 0

    def test_wrapper_discovery(self):
        sr = FakeSinkResult(direct_sinks=[
            FakeSinkInfo("db.py", "raw_query", 10, "cursor.execute"),
        ])
        cg = {
            "db.py": FakeCallGraph(calls=[
                FakeCall("raw_query", ["cursor", "execute"]),
                FakeCall("safe_query", ["raw_query"]),
                FakeCall("admin_query", ["raw_query"]),
            ]),
            "handler.py": FakeCallGraph(calls=[
                FakeCall("handle_search", ["safe_query"]),
                FakeCall("handle_list", ["safe_query"]),
            ]),
        }
        result = discover_project_sinks(sr, cg, min_callers_for_wrapper=2)
        wrappers = [s for s in result.discovered if s.reason == "wrapper"]
        assert len(wrappers) >= 1
        assert wrappers[0].function in ("safe_query",)

    def test_wrapper_not_promoted_with_one_caller(self):
        sr = FakeSinkResult(direct_sinks=[
            FakeSinkInfo("a.c", "do_exec", 5, "system"),
        ])
        cg = {
            "a.c": FakeCallGraph(calls=[
                FakeCall("do_exec", ["system"]),
                FakeCall("main", ["do_exec"]),
            ]),
        }
        result = discover_project_sinks(sr, cg, min_callers_for_wrapper=2)
        wrappers = [s for s in result.discovered if s.reason == "wrapper"]
        assert len(wrappers) == 0

    def test_naming_heuristic_with_dangerous_callee(self):
        sr = FakeSinkResult()
        cg = {
            "server.py": FakeCallGraph(calls=[
                FakeCall("execute_command", ["system"]),
            ]),
        }
        result = discover_project_sinks(sr, cg)
        naming = [s for s in result.discovered if s.reason == "naming"]
        assert len(naming) >= 1
        assert naming[0].confidence == "medium"

    def test_naming_heuristic_without_dangerous_callee(self):
        sr = FakeSinkResult()
        cg = {
            "utils.py": FakeCallGraph(calls=[
                FakeCall("run_command", ["log_message"]),
            ]),
        }
        result = discover_project_sinks(sr, cg)
        naming = [s for s in result.discovered if s.reason == "naming"]
        assert len(naming) >= 1
        assert naming[0].confidence == "low"

    def test_side_effect_wrapper(self):
        sr = FakeSinkResult()
        cg = {
            "io.c": FakeCallGraph(calls=[
                FakeCall("save_data", ["fopen"]),
                FakeCall("save_data", ["fwrite"]),
                FakeCall("save_data", ["fclose"]),
            ]),
        }
        result = discover_project_sinks(sr, cg)
        se = [s for s in result.discovered if s.reason == "side_effect"]
        assert len(se) == 1
        assert se[0].function == "save_data"
        assert "fopen" in se[0].wraps

    def test_taxonomy_sinks_excluded(self):
        sr = FakeSinkResult(direct_sinks=[
            FakeSinkInfo("a.c", "do_exec", 5, "system"),
        ])
        cg = {
            "a.c": FakeCallGraph(calls=[
                FakeCall("do_exec", ["system"]),
            ]),
        }
        result = discover_project_sinks(sr, cg)
        found = [s for s in result.discovered if s.function == "do_exec"]
        assert len(found) == 0

    def test_deduplication_across_strategies(self):
        sr = FakeSinkResult()
        cg = {
            "handler.py": FakeCallGraph(calls=[
                FakeCall("execute_query", ["fopen"]),
            ]),
        }
        result = discover_project_sinks(sr, cg)
        matches = [s for s in result.discovered
                   if s.function == "execute_query"]
        assert len(matches) == 1

    def test_sorted_by_confidence(self):
        sr = FakeSinkResult()
        cg = {
            "a.py": FakeCallGraph(calls=[
                FakeCall("run_command", ["log"]),
                FakeCall("save_file", ["fwrite"]),
            ]),
        }
        result = discover_project_sinks(sr, cg)
        if len(result.discovered) >= 2:
            confs = [s.confidence for s in result.discovered]
            priority = [
                {"high": 0, "medium": 1, "low": 2}[c]
                for c in confs
            ]
            assert priority == sorted(priority)

    def test_taint_upgrades_wrapper_confidence(self):
        sr = FakeSinkResult(direct_sinks=[
            FakeSinkInfo("db.py", "raw_query", 10, "cursor.execute"),
        ])

        @dataclass
        class FakeTaint:
            direct_flows: list = field(default_factory=lambda: [("param0", "return")])

        cg = {
            "db.py": FakeCallGraph(calls=[
                FakeCall("raw_query", ["cursor", "execute"]),
                FakeCall("safe_query", ["raw_query"]),
                FakeCall("admin_query", ["safe_query"]),
                FakeCall("handler", ["safe_query"]),
            ]),
        }
        taint = {"db.py:safe_query": FakeTaint()}
        result = discover_project_sinks(
            sr, cg, taint, min_callers_for_wrapper=2,
        )
        wrappers = [s for s in result.discovered if s.reason == "wrapper"]
        high_conf = [w for w in wrappers if w.confidence == "high"]
        assert len(high_conf) >= 1


_SIDE_EFFECT_CALLS = [
    "fopen", "fwrite", "fread", "unlink", "rename", "mkdir", "chmod",
]


class TestSideEffectWrapsUncapped:
    """The `wraps` list on side-effect sinks carries every wrapped call."""

    @staticmethod
    def _call_graphs():
        return {
            "src/io.c": FakeCallGraph(calls=[
                FakeCall("handle_io", [c]) for c in _SIDE_EFFECT_CALLS
            ]),
        }

    def test_wraps_lists_all_side_effect_targets(self):
        result = discover_project_sinks(None, call_graphs=self._call_graphs())
        side = [s for s in result.discovered if s.reason == "side_effect"]
        assert len(side) == 1
        sink = side[0]
        assert sink.function == "handle_io"
        # Not truncated to the first few items; must carry all of them,
        # deterministically ordered.
        assert sink.wraps == sorted(_SIDE_EFFECT_CALLS)

    def test_wraps_survives_to_dict(self):
        result = discover_project_sinks(None, call_graphs=self._call_graphs())
        d = result.to_dict()
        sinks = [
            s for s in d["discovered_sinks"] if s["reason"] == "side_effect"
        ]
        assert sinks and len(sinks[0]["wraps"]) == len(_SIDE_EFFECT_CALLS)


class TestDiscoveredSink:
    def test_to_dict(self):
        s = DiscoveredSink(
            file="a.c", function="my_exec",
            reason="wrapper", confidence="high",
            wraps=["system"], caller_count=5,
        )
        d = s.to_dict()
        assert d["file"] == "a.c"
        assert d["wraps"] == ["system"]
        assert d["caller_count"] == 5

    def test_to_dict_minimal(self):
        s = DiscoveredSink(
            file="b.py", function="run",
            reason="naming", confidence="low",
        )
        d = s.to_dict()
        assert "wraps" not in d
        assert "caller_count" not in d


class TestSinkHeuristicsResult:
    def test_to_dict(self):
        r = SinkHeuristicsResult(
            discovered=[
                DiscoveredSink("a.c", "fn", "wrapper", "high"),
            ],
            wrapper_count=1,
        )
        d = r.to_dict()
        assert d["counts"]["total"] == 1
        assert d["counts"]["wrapper"] == 1

    def test_empty_result(self):
        r = SinkHeuristicsResult()
        d = r.to_dict()
        assert d["counts"]["total"] == 0


class TestMergeDiscoveredSinks:
    def test_merge_into_sink_results(self):
        sr = FakeSinkResult(direct_sinks=[
            FakeSinkInfo("a.c", "existing", 1, "system"),
        ])
        hr = SinkHeuristicsResult(discovered=[
            DiscoveredSink("b.c", "wrapper_fn", "wrapper", "high",
                           wraps=["exec"]),
        ])
        merge_discovered_sinks(sr, hr)
        assert len(sr.direct_sinks) == 2
        added = sr.direct_sinks[-1]
        assert added.function == "wrapper_fn"
        assert "[project]" in added.target
        assert added.direct is False

    def test_no_duplicate_merge(self):
        sr = FakeSinkResult(direct_sinks=[
            FakeSinkInfo("a.c", "fn", 1, "system"),
        ])
        hr = SinkHeuristicsResult(discovered=[
            DiscoveredSink("a.c", "fn", "wrapper", "high"),
        ])
        merge_discovered_sinks(sr, hr)
        assert len(sr.direct_sinks) == 1

    def test_merge_with_none_sink_results(self):
        hr = SinkHeuristicsResult(discovered=[
            DiscoveredSink("a.c", "fn", "naming", "low"),
        ])
        merge_discovered_sinks(None, hr)

    def test_merge_empty_heuristics(self):
        sr = FakeSinkResult()
        merge_discovered_sinks(sr, SinkHeuristicsResult())
        assert len(sr.direct_sinks) == 0

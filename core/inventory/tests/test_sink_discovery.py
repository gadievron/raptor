"""Tests for core.inventory.sink_discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.inventory.call_graph import CallSite, FileCallGraph
from core.inventory.sink_discovery import (
    DANGEROUS_TARGETS,
    _is_dangerous,
    _is_language_builtin,
    discover_sinks,
)


# ── _is_dangerous ───────────────────────────────────────────────────

class TestIsDangerous:
    def test_full_chain_match(self):
        assert _is_dangerous(["subprocess", "Popen"]) == "subprocess.Popen"

    def test_qualified_pair_match(self):
        assert _is_dangerous(["os", "system"]) == "os.system"

    def test_bare_name_match(self):
        assert _is_dangerous(["popen"]) == "popen"

    def test_c_exec_family(self):
        assert _is_dangerous(["execve"]) == "execve"

    def test_lua_sinks(self):
        assert _is_dangerous(["os", "execute"]) == "os.execute"
        assert _is_dangerous(["io", "popen"]) == "io.popen"
        assert _is_dangerous(["loadstring"]) == "loadstring"
        assert _is_dangerous(["dofile"]) == "dofile"

    def test_detection_surface_family(self):
        # Incident regression: audit/security-event writers were not
        # sinks, so a function selecting BSM audit masks looked
        # "sink-unreachable" and a confirmed audit-evasion defect in
        # it was triage-skipped without any LLM review.
        assert _is_dangerous(["au_user_mask"]) == "au_user_mask"
        assert _is_dangerous(["getacna"]) == "getacna"
        assert _is_dangerous(["syslog"]) == "syslog"
        assert _is_dangerous(["updwtmp"]) == "updwtmp"
        assert _is_dangerous(["audit_log_user_message"]) == (
            "audit_log_user_message"
        )

    def test_not_dangerous(self):
        assert _is_dangerous(["print"]) is None
        assert _is_dangerous(["os", "path", "join"]) is None
        assert _is_dangerous(["json", "loads"]) is None

    def test_deep_chain_method_not_bare_match(self):
        """Multi-element chains don't bare-match — self.helper.system() is not C's system()."""
        assert _is_dangerous(["self", "helper", "system"]) is None

    def test_nixio_exec(self):
        assert _is_dangerous(["nixio", "exec"]) == "nixio.exec"


# ── _is_language_builtin ────────────────────────────────────────────

class TestIsLanguageBuiltin:
    def test_js_builtins(self):
        assert _is_language_builtin("Promise.all")
        assert _is_language_builtin("Array.isArray")
        assert _is_language_builtin("JSON.parse")

    def test_python_builtins(self):
        assert _is_language_builtin("os.path.join")
        assert _is_language_builtin("json.loads")

    def test_lua_builtins(self):
        assert _is_language_builtin("table.insert")
        assert _is_language_builtin("string.format")

    def test_not_builtin(self):
        assert not _is_language_builtin("uci.get")
        assert not _is_language_builtin("rpc.declare")
        assert not _is_language_builtin("custom.framework.call")


# ── DANGEROUS_TARGETS ───────────────────────────────────────────────

class TestDangerousTargets:
    def test_includes_source_level_sinks(self):
        assert "subprocess.Popen" in DANGEROUS_TARGETS
        assert "os.execute" in DANGEROUS_TARGETS
        assert "loadstring" in DANGEROUS_TARGETS

    def test_includes_c_exec_funcs(self):
        # These come from core.function_taxonomy.EXEC_FUNCS
        assert "execve" in DANGEROUS_TARGETS
        assert "popen" in DANGEROUS_TARGETS


# ── discover_sinks ──────────────────────────────────────────────────

def _make_graph(calls: list[tuple]) -> FileCallGraph:
    """Build a FileCallGraph from (caller, chain, line) tuples."""
    return FileCallGraph(
        imports={},
        calls=[
            CallSite(
                line=line,
                chain=chain,
                caller=caller,
            )
            for caller, chain, line in calls
        ],
        indirection=set(),
    )


class TestDiscoverSinks:
    def test_direct_sinks_found(self):
        graphs = {
            "app.lua": _make_graph([
                ("handler", ["os", "execute"], 10),
                ("helper", ["print"], 20),
            ]),
        }
        result = discover_sinks(graphs)
        assert len(result.direct_sinks) == 1
        s = result.direct_sinks[0]
        assert s.file == "app.lua"
        assert s.function == "handler"
        assert s.target == "os.execute"
        assert s.line == 10

    def test_transitive_reachability(self):
        graphs = {
            "util.lua": _make_graph([
                ("exec_cmd", ["os", "execute"], 10),
                ("run_task", ["exec_cmd"], 20),
                ("main", ["run_task"], 30),
            ]),
        }
        result = discover_sinks(graphs)
        assert len(result.direct_sinks) == 1
        assert len(result.transitive_reach) == 2

        by_func = {t.function: t for t in result.transitive_reach}
        assert "run_task" in by_func
        assert by_func["run_task"].distance == 1
        assert "os.execute" in by_func["run_task"].sinks

        assert "main" in by_func
        assert by_func["main"].distance == 2
        assert "os.execute" in by_func["main"].sinks

    def test_max_depth_limits_traversal(self):
        graphs = {
            "deep.lua": _make_graph([
                ("sink", ["os", "execute"], 1),
                ("d1", ["sink"], 2),
                ("d2", ["d1"], 3),
                ("d3", ["d2"], 4),
            ]),
        }
        result = discover_sinks(graphs, max_depth=1)
        assert len(result.transitive_reach) == 1
        assert result.transitive_reach[0].function == "d1"

    def test_framework_api_discovery(self):
        calls = []
        for i in range(10):
            calls.append((f"fn_{i}", ["uci", "get"], i * 10))
        graphs = {
            f"file_{i}.lua": _make_graph([
                (f"fn_{i}", ["uci", "get"], i * 10),
            ])
            for i in range(10)
        }
        result = discover_sinks(graphs, framework_threshold=5, framework_min_files=3)
        api_names = [f.name for f in result.framework_apis]
        assert "uci.get" in api_names

    def test_framework_builtin_excluded(self):
        graphs = {
            f"file_{i}.py": _make_graph([
                (f"fn_{i}", ["json", "loads"], i * 10),
            ])
            for i in range(10)
        }
        result = discover_sinks(graphs, framework_threshold=5, framework_min_files=3)
        api_names = [f.name for f in result.framework_apis]
        assert "json.loads" not in api_names

    def test_framework_min_files_filter(self):
        # All calls in one file — should be filtered out
        graphs = {
            "single.lua": _make_graph([
                (f"fn_{i}", ["custom", "api"], i * 10)
                for i in range(20)
            ]),
        }
        result = discover_sinks(graphs, framework_threshold=5, framework_min_files=3)
        api_names = [f.name for f in result.framework_apis]
        assert "custom.api" not in api_names

    def test_no_dangerous_calls(self):
        graphs = {
            "safe.lua": _make_graph([
                ("fn1", ["print"], 1),
                ("fn2", ["table", "insert"], 2),
            ]),
        }
        result = discover_sinks(graphs)
        assert len(result.direct_sinks) == 0
        assert len(result.transitive_reach) == 0

    def test_multiple_sinks_same_function(self):
        graphs = {
            "multi.lua": _make_graph([
                ("handler", ["os", "execute"], 10),
                ("handler", ["io", "popen"], 15),
            ]),
        }
        result = discover_sinks(graphs)
        assert len(result.direct_sinks) == 2
        targets = {s.target for s in result.direct_sinks}
        assert "os.execute" in targets
        assert "io.popen" in targets

    def test_as_dict_shape(self):
        graphs = {
            "a.lua": _make_graph([
                ("sink_caller", ["os", "execute"], 1),
            ]),
        }
        result = discover_sinks(graphs)
        d = result.as_dict()
        assert "direct_sinks" in d
        assert "transitive_reach" in d
        assert "framework_apis" in d
        assert "dangerous_target_usage" in d
        assert d["direct_sinks"][0]["target"] == "os.execute"

    def test_cross_file_edge_resolved(self):
        """Cross-file calls are linked via function name index."""
        graphs = {
            "a.lua": _make_graph([
                ("caller_a", ["remote_fn"], 1),
            ]),
            "b.lua": _make_graph([
                ("remote_fn", ["os", "execute"], 10),
            ]),
        }
        result = discover_sinks(graphs)
        assert len(result.direct_sinks) == 1
        assert len(result.transitive_reach) == 1
        assert result.transitive_reach[0].function == "caller_a"


    def test_diamond_graph_merges_sinks(self):
        """main -> A -> sink1, main -> B -> sink2: main sees both."""
        graphs = {
            "d.lua": _make_graph([
                ("sink1", ["os", "execute"], 1),
                ("sink2", ["io", "popen"], 2),
                ("A", ["sink1"], 3),
                ("B", ["sink2"], 4),
                ("main", ["A"], 5),
                ("main", ["B"], 6),
            ]),
        }
        result = discover_sinks(graphs)
        by_func = {t.function: t for t in result.transitive_reach}
        assert "main" in by_func
        assert set(by_func["main"].sinks) == {"os.execute", "io.popen"}

    def test_cycle_does_not_infinite_loop(self):
        """A -> B -> A with B calling os.execute: terminates, both reachable."""
        graphs = {
            "cyc.lua": _make_graph([
                ("B", ["os", "execute"], 1),
                ("A", ["B"], 2),
                ("B", ["A"], 3),
            ]),
        }
        result = discover_sinks(graphs)
        by_func = {t.function: t for t in result.transitive_reach}
        assert "A" in by_func
        assert "os.execute" in by_func["A"].sinks

    def test_empty_chain_no_crash(self):
        """CallSite with empty chain should not crash discover_sinks."""
        graphs = {
            "e.lua": _make_graph([
                ("fn", [], 1),
                ("fn", ["os", "execute"], 2),
            ]),
        }
        result = discover_sinks(graphs)
        assert len(result.direct_sinks) == 1

    def test_self_eval_not_dangerous(self):
        """self.eval() should not match — it's a method call, not builtin eval."""
        assert _is_dangerous(["self", "eval"]) is None
        assert _is_dangerous(["model", "eval"]) is None
        assert _is_dangerous(["this", "system"]) is None

    def test_bare_eval_is_dangerous(self):
        """Bare eval() (single-element chain) should match."""
        assert _is_dangerous(["eval"]) == "eval"
        assert _is_dangerous(["popen"]) == "popen"

    def test_non_dir_target_returns_empty(self):
        """discover_sinks_for_target with non-dir path returns empty result."""
        from core.inventory.sink_discovery import discover_sinks_for_target
        result = discover_sinks_for_target(Path("/nonexistent/path"))
        assert len(result.direct_sinks) == 0
        assert len(result.transitive_reach) == 0


class TestDiscoverSinksForTarget:
    def test_real_target_lua(self):
        """Integration test on openwrt-luci (skip if not available)."""
        target = Path("/data/openwrt-luci")
        if not target.exists():
            pytest.skip("openwrt-luci not available")

        from core.inventory.sink_discovery import discover_sinks_for_target

        result = discover_sinks_for_target(target, languages={"lua"})
        assert len(result.direct_sinks) > 0
        targets = {s.target for s in result.direct_sinks}
        assert targets & {"os.execute", "io.popen", "loadstring", "loadfile"}


class TestChainReconstruction:
    def test_linear_chain(self):
        """main → run_task → exec_cmd → os.execute produces a 2-hop chain."""
        graphs = {
            "util.lua": _make_graph([
                ("exec_cmd", ["os", "execute"], 10),
                ("run_task", ["exec_cmd"], 20),
                ("main", ["run_task"], 30),
            ]),
        }
        result = discover_sinks(graphs)
        by_func = {t.function: t for t in result.transitive_reach}

        main_chain = by_func["main"].chain
        assert main_chain is not None
        assert len(main_chain) == 2
        assert main_chain[0].function == "run_task"
        assert main_chain[1].function == "exec_cmd"

        run_chain = by_func["run_task"].chain
        assert run_chain is not None
        assert len(run_chain) == 1
        assert run_chain[0].function == "exec_cmd"

    def test_chain_serialization(self):
        """Chains appear in as_dict() output."""
        graphs = {
            "a.lua": _make_graph([
                ("sink_fn", ["os", "execute"], 1),
                ("caller", ["sink_fn"], 2),
            ]),
        }
        result = discover_sinks(graphs)
        d = result.as_dict()
        tr = d["transitive_reach"]
        assert len(tr) == 1
        assert "chain" in tr[0]
        assert tr[0]["chain"][0]["function"] == "sink_fn"

    def test_cross_file_chain(self):
        """Chain works across files."""
        graphs = {
            "a.lua": _make_graph([
                ("caller_a", ["remote_fn"], 1),
            ]),
            "b.lua": _make_graph([
                ("remote_fn", ["os", "execute"], 10),
            ]),
        }
        result = discover_sinks(graphs)
        assert len(result.transitive_reach) == 1
        chain = result.transitive_reach[0].chain
        assert chain is not None
        assert len(chain) == 1
        assert chain[0].function == "remote_fn"
        assert chain[0].file == "b.lua"

    def test_no_chain_for_direct_sinks(self):
        """Direct sink callers don't appear in transitive_reach."""
        graphs = {
            "a.lua": _make_graph([
                ("handler", ["os", "execute"], 10),
            ]),
        }
        result = discover_sinks(graphs)
        assert len(result.transitive_reach) == 0
        assert len(result.direct_sinks) == 1


class TestDiscoveryWalkBounds:
    """Symlink refusal + per-file/aggregate byte budgets on the walk."""

    TAINTED = "import os\n\ndef handler(x):\n    os.system(x)\n"

    def test_symlinked_file_not_read(self, tmp_path):
        from core.inventory.sink_discovery import discover_sinks_for_target
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "evil.py").write_text(self.TAINTED)
        target = tmp_path / "target"
        target.mkdir()
        (target / "m.py").symlink_to(outside / "evil.py")
        result = discover_sinks_for_target(target)
        assert len(result.direct_sinks) == 0

    def test_oversize_file_skipped_small_still_processed(
        self, tmp_path, monkeypatch,
    ):
        import core.inventory.sink_discovery as sd
        monkeypatch.setattr(sd, "_PER_FILE_CAP", 256)
        target = tmp_path / "target"
        target.mkdir()
        (target / "small.py").write_text(self.TAINTED)
        (target / "big.py").write_text(
            self.TAINTED + "# " + "x" * 512 + "\n")
        result = sd.discover_sinks_for_target(target)
        files = {s.file for s in result.direct_sinks}
        assert files == {"small.py"}

    def test_aggregate_budget_stops_walk(self, tmp_path, monkeypatch):
        import core.inventory.sink_discovery as sd
        monkeypatch.setattr(sd, "_AGGREGATE_CAP", 4)
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text(self.TAINTED)
        (target / "b.py").write_text(self.TAINTED)
        result = sd.discover_sinks_for_target(target)
        assert len(result.direct_sinks) == 0

    def test_within_budget_unchanged(self, tmp_path):
        from core.inventory.sink_discovery import discover_sinks_for_target
        target = tmp_path / "target"
        target.mkdir()
        (target / "m.py").write_text(self.TAINTED)
        result = discover_sinks_for_target(target)
        assert {s.target for s in result.direct_sinks} == {"os.system"}

    def test_iter_source_files_skips_symlinked_files(self, tmp_path):
        from core.inventory.sink_discovery import _iter_source_files
        (tmp_path / "real.py").write_text("x = 1\n")
        (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
        names = {p.name for p in _iter_source_files(tmp_path)}
        assert names == {"real.py"}


class TestFullDictRoundTrip:
    """to_full_dict/from_full_dict must be lossless — the audit prep
    cache reloads the discovery result from it on resumed segments."""

    def _result(self):
        from core.inventory.sink_discovery import (
            ChainHop,
            FrameworkAPI,
            SinkDiscoveryResult,
            SinkInfo,
            TransitiveReach,
            UnreachableVerdict,
        )
        return SinkDiscoveryResult(
            direct_sinks=[
                SinkInfo(file="a.py", function="run", line=3,
                         target="os.system"),
                SinkInfo(file="b.py", function="wrap", line=9,
                         target="wrapper of: os.system", direct=False),
            ],
            transitive_reach=[
                TransitiveReach(
                    file="a.py", function="entry", distance=2,
                    sinks=["os.system"],
                    chain=[
                        ChainHop(file="a.py", function="mid"),
                        ChainHop(file="a.py", function="run"),
                    ],
                ),
                TransitiveReach(
                    file="c.py", function="lone", distance=1,
                    sinks=["eval"], chain=[],
                ),
            ],
            framework_apis=[
                FrameworkAPI(name="app.route", caller_count=7,
                             files=["a.py", "b.py"]),
            ],
            dangerous_target_counts={"os.system": 1},
            unreachable_eligible={
                ("d.py", "idle"): UnreachableVerdict(
                    file="d.py", function="idle", eligible=True,
                    reason="no transitive reach, no indirection",
                ),
                ("e.py", "cb"): UnreachableVerdict(
                    file="e.py", function="cb", eligible=False,
                    reason="indirection flags: ['fn_pointer']",
                ),
            },
        )

    def test_round_trip_is_lossless(self):
        import json as _json

        from core.inventory.sink_discovery import SinkDiscoveryResult
        orig = self._result()
        # Through JSON, as the prep cache stores it.
        blob = _json.loads(_json.dumps(orig.to_full_dict()))
        back = SinkDiscoveryResult.from_full_dict(blob)
        assert back.to_full_dict() == orig.to_full_dict()
        # The lossy fields as_dict drops survive the full round trip.
        assert [s.direct for s in back.direct_sinks] == [True, False]
        assert back.unreachable_eligible is not None
        assert back.unreachable_eligible[("d.py", "idle")].eligible
        assert not back.unreachable_eligible[("e.py", "cb")].eligible
        # The operator/context-map shape is identical too.
        assert back.as_dict() == orig.as_dict()

    def test_round_trip_none_unreachable(self):
        from core.inventory.sink_discovery import SinkDiscoveryResult
        orig = SinkDiscoveryResult([], [], [], {})
        back = SinkDiscoveryResult.from_full_dict(orig.to_full_dict())
        assert back.unreachable_eligible is None
        assert back.to_full_dict() == orig.to_full_dict()


class TestIterDiscoverySourceFiles:
    def test_yields_the_walk_input_set(self, tmp_path):
        from core.inventory.sink_discovery import (
            iter_discovery_source_files,
        )
        (tmp_path / "a.py").write_text("import os\nos.system('x')\n")
        (tmp_path / "notes.txt").write_text("not source\n")
        rels = [rel for _p, rel, _l in
                iter_discovery_source_files(tmp_path)]
        assert rels == ["a.py"]

    def test_respects_scope_dirs(self, tmp_path):
        from core.inventory.sink_discovery import (
            iter_discovery_source_files,
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "in.py").write_text("x = 1\n")
        (tmp_path / "out.py").write_text("y = 2\n")
        rels = [rel for _p, rel, _l in iter_discovery_source_files(
            tmp_path, scope_dirs=[str(tmp_path / "src")],
        )]
        assert rels == [str(Path("src") / "in.py")]

    def test_respects_aggregate_budget(self, tmp_path, monkeypatch):
        import core.inventory.sink_discovery as sd
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        monkeypatch.setattr(sd, "_AGGREGATE_CAP", 7)
        rels = [rel for _p, rel, _l in
                sd.iter_discovery_source_files(tmp_path)]
        assert len(rels) == 1

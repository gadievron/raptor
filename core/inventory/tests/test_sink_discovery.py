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

    def test_cross_file_no_edge(self):
        """Call graph edges are file-local; cross-file calls aren't linked."""
        graphs = {
            "a.lua": _make_graph([
                ("caller_a", ["remote_fn"], 1),
            ]),
            "b.lua": _make_graph([
                ("remote_fn", ["os", "execute"], 10),
            ]),
        }
        result = discover_sinks(graphs)
        # remote_fn in b.lua is a direct sink
        assert len(result.direct_sinks) == 1
        # caller_a in a.lua does NOT have transitive reach because
        # cross-file edges aren't linked (same-file only)
        assert len(result.transitive_reach) == 0


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

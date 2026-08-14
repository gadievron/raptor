"""Integration tests: guard-bypass query against real PythonCFG."""

from __future__ import annotations

import textwrap

import pytest

from core.analysis.guard_bypass import check_guard_coverage, query
from core.analysis.cfg_conditions import extract_conditions_from_cfg
from core.analysis.cfg_builder import build_python_cfg

_ts_available = build_python_cfg("def f(): pass", "__probe__.py") is not None
pytestmark = pytest.mark.skipif(not _ts_available, reason="tree-sitter-python not installed")


def _build(source: str, func_name: str = "f"):
    """Build a PythonCFG from inline source."""
    source = textwrap.dedent(source).strip()
    cfgs = build_python_cfg(source, "test.py")
    for cfg in cfgs:
        if cfg.function_name == func_name:
            return cfg
    raise ValueError(f"function {func_name!r} not found in {[c.function_name for c in cfgs]}")


class TestExtractConditionsFromRealCFG:
    def test_simple_if(self):
        cfg = _build("""
            def f(x):
                if x > 0:
                    return x
                return -x
        """)
        edges = extract_conditions_from_cfg(cfg)
        cond_edges = [e for e in edges if e.condition is not None]
        assert len(cond_edges) >= 2
        texts = {e.condition.text for e in cond_edges}
        assert "x > 0" in texts

    def test_nested_if(self):
        cfg = _build("""
            def f(x, y):
                if x > 0:
                    if y > 0:
                        return x + y
                    return x
                return 0
        """)
        edges = extract_conditions_from_cfg(cfg)
        cond_edges = [e for e in edges if e.condition is not None]
        texts = {e.condition.text for e in cond_edges}
        assert "x > 0" in texts
        assert "y > 0" in texts


class TestGuardBypassWithRealCFG:
    def test_guarded_path_no_bypass(self):
        cfg = _build("""
            def f(user_input):
                if user_input.isalnum():
                    eval(user_input)
        """)
        result = query(
            cfg,
            source_var="user_input",
            source_line=1,
            sink_line=3,
        )
        assert not result.is_bypassed()
        assert len(result.constraining_guards) >= 1

    def test_unguarded_path_is_bypass(self):
        cfg = _build("""
            def f(user_input):
                eval(user_input)
        """)
        result = query(
            cfg,
            source_var="user_input",
            source_line=1,
            sink_line=2,
        )
        assert len(result.constraining_guards) == 0
        assert result.is_bypassed()

    def test_partial_guard_one_branch_bypasses(self):
        cfg = _build("""
            def f(user_input, flag):
                if flag:
                    validated = sanitize(user_input)
                else:
                    validated = user_input
                eval(validated)
        """)
        result = query(
            cfg,
            source_var="user_input",
            source_line=1,
            sink_line=6,
        )
        assert len(result.constraining_guards) == 0


class TestCheckGuardCoverageWithRealCFG:
    def test_guard_dominates_read(self):
        cfg = _build("""
            def f(task):
                if task.mm is not None:
                    dumpable = task.get_dumpable()
                    return dumpable
                return 0
        """)
        assert check_guard_coverage(cfg, 3, "task.mm is not None")

    def test_guard_not_on_all_paths(self):
        cfg = _build("""
            def f(task, skip):
                if skip:
                    return task.get_dumpable()
                if task.mm is not None:
                    return task.get_dumpable()
                return 0
        """)
        assert not check_guard_coverage(cfg, 3, "task.mm is not None")

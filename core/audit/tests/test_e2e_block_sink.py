"""End-to-end tests for block-level review + sink prefilter pipeline.

Exercises the full orchestrator path against eval/audit-synthetic/target:

    call graph → checklist → sink discovery → taint approx → evidence index
    → _build_context → _try_block_level_context → format_context_for_prompt

No LLM calls.  Verifies that the pipeline produces the right mechanical
signals for complex functions (block review), simple functions (no block
review), and sink-unreachable functions (scope narrowing).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

pytestmark = pytest.mark.slow

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_TARGET_DIR = _RAPTOR_DIR / "eval" / "audit-synthetic" / "target"


@pytest.fixture(scope="module")
def target_path():
    if not _TARGET_DIR.exists():
        pytest.skip("eval/audit-synthetic/target not available")
    return _TARGET_DIR


@pytest.fixture(scope="module")
def checklist(target_path):
    """Build a checklist from call-graph extraction (same as the pipeline)."""
    from core.inventory.call_graph import extract_call_graph_c, extract_call_graph_python
    from core.inventory.sink_discovery import _iter_source_files
    from core.inventory.languages import detect_language

    extractors = {"c": extract_call_graph_c, "python": extract_call_graph_python}

    files = []
    for source_file in _iter_source_files(target_path):
        rel = str(source_file.relative_to(target_path))
        lang = detect_language(rel)
        ext_fn = extractors.get(lang)
        if not ext_fn:
            continue
        content = source_file.read_text(errors="replace")
        graph = ext_fn(content)

        seen = set()
        items = []
        for call in graph.calls:
            c = call.caller or "<module>"
            if c not in seen:
                seen.add(c)
                items.append({
                    "name": c,
                    "kind": "function",
                    "line_start": call.line,
                })
        if items:
            files.append({"path": rel, "items": items})

    return {"files": files}


@pytest.fixture(scope="module")
def sink_results(target_path):
    from core.inventory.sink_discovery import discover_sinks_for_target

    return discover_sinks_for_target(target_path)


@pytest.fixture(scope="module")
def taint_approx_results(target_path, checklist):
    from core.analysis.taint_approx import extract_taint_approx_c

    results = {}
    for fobj in checklist.get("files", []):
        fpath = fobj["path"]
        full = target_path / fpath
        if not full.exists():
            continue
        if not (fpath.endswith(".c") or fpath.endswith(".h")):
            continue
        content = full.read_text(errors="replace")
        approx_map = extract_taint_approx_c(content)
        for item in fobj.get("items", []):
            name = item["name"]
            if name in approx_map:
                results[f"{fpath}:{name}"] = approx_map[name]
    return results


@pytest.fixture(scope="module")
def evidence_index(checklist, sink_results, taint_approx_results):
    from core.evidence import build_evidence_index

    return build_evidence_index(
        checklist=checklist,
        sink_results=sink_results,
        taint_approx_results=taint_approx_results,
    )


@dataclass
class _FakeConfig:
    target_path: Path
    out_dir: Path
    prefilter: bool = True
    annotations_dir: Optional[Path] = None
    inventory: Optional[Dict[str, Any]] = None
    models: List[str] = field(default_factory=lambda: ["test"])
    blind_first_pass: bool = False
    enable_session_context: bool = False


def _find_gap(checklist, file_path, function_name):
    """Locate a gap dict matching a function in the checklist."""
    for fobj in checklist.get("files", []):
        if fobj["path"] != file_path:
            continue
        for item in fobj.get("items", []):
            if item["name"] == function_name:
                return {
                    "file": file_path,
                    "name": function_name,
                    "line_start": item.get("line_start", 1),
                    "line_end": item.get("line_end"),
                }
    pytest.fail(f"{file_path}:{function_name} not in checklist")


# =====================================================================
# 1. Block-level review through the orchestrator helper
# =====================================================================


class TestBlockLevelE2E:

    def test_complex_c_function_gets_block_context(
        self, target_path, checklist, evidence_index, tmp_path,
    ):
        """parse_headers (CC=11) should produce block-level context
        when called through _try_block_level_context (the orchestrator
        helper), not just through the block_review module directly.
        """
        from core.audit.orchestrator import _try_block_level_context

        gap = _find_gap(checklist, "reqparse.c", "parse_headers")
        config = _FakeConfig(target_path=target_path, out_dir=tmp_path)
        ctx = {"source": "placeholder"}

        result = _try_block_level_context(gap, ctx, config, evidence_index)

        assert result is not None, "parse_headers should trigger block review"
        assert "Block-level analysis" in result
        assert "taint-relevant branches" in result
        assert "DANGEROUS CALLS" in result

    def test_block_context_has_taint_state(
        self, target_path, checklist, evidence_index, tmp_path,
    ):
        """Block review should show tainted vars propagated from params."""
        from core.audit.orchestrator import _try_block_level_context

        gap = _find_gap(checklist, "reqparse.c", "parse_headers")
        config = _FakeConfig(target_path=target_path, out_dir=tmp_path)
        ctx = {"source": "placeholder"}

        result = _try_block_level_context(gap, ctx, config, evidence_index)
        assert result is not None

        assert "Tainted at entry:" in result
        lower = result.lower()
        assert "buf" in lower, "buf (param) should appear as tainted"

    def test_simple_c_function_no_block_review(
        self, target_path, checklist, evidence_index, tmp_path,
    ):
        """to_lowercase (CC < threshold) should NOT get block review."""
        from core.audit.orchestrator import _try_block_level_context

        gap = _find_gap(checklist, "reqparse.c", "to_lowercase")
        config = _FakeConfig(target_path=target_path, out_dir=tmp_path)
        ctx = {"source": "placeholder"}

        result = _try_block_level_context(gap, ctx, config, evidence_index)
        assert result is None

    def test_python_cfg_builds_successfully(
        self, target_path,
    ):
        """Python functions should build a CFG (not silently fail).

        Regression test for Bug 1: invalid kwarg to build_python_cfg.
        """
        from core.audit.block_review import try_build_cfg

        cfg = try_build_cfg(
            "bindings.py", "resolve_user_file", target_path,
        )
        assert cfg is not None, (
            "Python CFG should build; Bug 1 (invalid kwarg) would cause None"
        )

    def test_block_context_includes_source_snippet(
        self, target_path, checklist, evidence_index, tmp_path,
    ):
        """Block context should include source code snippets."""
        from core.audit.orchestrator import _try_block_level_context

        gap = _find_gap(checklist, "reqparse.c", "parse_headers")
        config = _FakeConfig(target_path=target_path, out_dir=tmp_path)
        ctx = {"source": "placeholder"}

        result = _try_block_level_context(gap, ctx, config, evidence_index)
        assert result is not None
        assert "```" in result


# =====================================================================
# 2. Sink prefilter through the evidence pipeline
# =====================================================================


class TestSinkPrefilterE2E:

    def test_unreachable_fn_gets_narrowed_cwes(
        self, checklist, evidence_index,
    ):
        """Functions with no sink path should have narrowed CWE classes."""
        key = "reqparse.c:is_valid_method"
        rec = evidence_index.get(key)
        if rec is None:
            pytest.skip("is_valid_method not in evidence index")

        assert rec.sink_unreachable is True, (
            "is_valid_method has no dangerous calls, should be unreachable"
        )
        assert len(rec.sink_narrowed_classes) > 0
        assert "CWE-78" in rec.sink_narrowed_classes
        assert "CWE-89" in rec.sink_narrowed_classes

    def test_reachable_fn_has_no_narrowing(self, evidence_index):
        """Functions with a sink path should NOT be narrowed."""
        key = "reqparse.c:parse_headers"
        rec = evidence_index.get(key)
        if rec is None:
            pytest.skip("parse_headers not in evidence index")

        assert rec.sink_unreachable is False
        assert rec.sink_narrowed_classes == []

    def test_memory_cwes_not_narrowed(self, evidence_index):
        """CWE-416/787/190 should NOT appear in narrowed classes.

        Regression test for Bug 7: over-narrowing memory corruption CWEs.
        """
        for key, rec in evidence_index.items():
            if rec.sink_unreachable and rec.sink_narrowed_classes:
                assert "CWE-416" not in rec.sink_narrowed_classes, (
                    f"{key}: CWE-416 (UAF) should not be sink-dependent"
                )
                assert "CWE-787" not in rec.sink_narrowed_classes, (
                    f"{key}: CWE-787 (OOB write) should not be sink-dependent"
                )
                assert "CWE-190" not in rec.sink_narrowed_classes, (
                    f"{key}: CWE-190 (int overflow) should not be sink-dependent"
                )

    def test_lookup_user_has_sink_path(self, evidence_index):
        """lookup_user calls snprintf → should be sink-reachable."""
        key = "database.c:lookup_user"
        rec = evidence_index.get(key)
        if rec is None:
            pytest.skip("lookup_user not in evidence index")
        assert rec.sink_unreachable is False

    def test_at_least_some_functions_are_unreachable(self, evidence_index):
        """Sanity: the target should have at least one sink-unreachable fn."""
        unreachable = [
            k for k, r in evidence_index.items() if r.sink_unreachable
        ]
        assert len(unreachable) > 0, (
            "No sink-unreachable functions found — sink discovery may be broken"
        )


# =====================================================================
# 3. Full prompt rendering (evidence → context → block → prompt)
# =====================================================================


class TestFullPromptRenderE2E:

    def test_complex_fn_prompt_has_all_signals(
        self, target_path, checklist, evidence_index, tmp_path,
    ):
        """parse_headers prompt: source + evidence + block analysis."""
        from core.audit.context import format_context_for_prompt
        from core.audit.orchestrator import (
            _build_context,
            _try_block_level_context,
        )

        gap = _find_gap(checklist, "reqparse.c", "parse_headers")
        config = _FakeConfig(target_path=target_path, out_dir=tmp_path)

        ctx = _build_context(
            config, gap, checklist,
            context_map=None,
            evidence_index=evidence_index,
        )

        block_ctx = _try_block_level_context(
            gap, ctx, config, evidence_index,
        )
        if block_ctx:
            ctx["block_analysis"] = block_ctx

        prompt = format_context_for_prompt(ctx)

        assert "reqparse.c:parse_headers" in prompt
        assert "```" in prompt

        if block_ctx:
            assert "Block-level analysis" in prompt
            assert "DANGEROUS CALLS" in prompt

        key = "reqparse.c:parse_headers"
        rec = evidence_index.get(key)
        if rec and rec.has_any_evidence():
            assert "mechanical" in prompt.lower() or "Mechanical" in prompt

    def test_unreachable_fn_prompt_has_scope_narrowing(
        self, target_path, checklist, evidence_index, tmp_path,
    ):
        """Sink-unreachable function → scope narrowing in prompt."""
        from core.audit.context import format_context_for_prompt
        from core.audit.orchestrator import _build_context

        gap = _find_gap(
            checklist, "reqparse.c", "is_valid_method",
        )
        config = _FakeConfig(target_path=target_path, out_dir=tmp_path)

        ctx = _build_context(
            config, gap, checklist,
            context_map=None,
            evidence_index=evidence_index,
        )

        prompt = format_context_for_prompt(ctx)

        assert ctx.get("sink_unreachable"), "is_valid_method should be sink-unreachable"
        assert "Scope narrowing" in prompt
        assert ctx.get("sink_narrowed_classes"), "should have narrowed CWE classes"
        assert "CWE-78" in prompt
        assert "logic bugs" in prompt

    def test_reachable_fn_prompt_no_scope_narrowing(
        self, target_path, checklist, evidence_index, tmp_path,
    ):
        """Sink-reachable function should NOT have scope narrowing."""
        from core.audit.context import format_context_for_prompt
        from core.audit.orchestrator import _build_context

        gap = _find_gap(checklist, "reqparse.c", "parse_headers")
        config = _FakeConfig(target_path=target_path, out_dir=tmp_path)

        ctx = _build_context(
            config, gap, checklist,
            context_map=None,
            evidence_index=evidence_index,
        )

        prompt = format_context_for_prompt(ctx)
        assert "Scope narrowing" not in prompt

    def test_no_line_number_prefix_in_block_source(
        self, target_path, checklist, evidence_index, tmp_path,
    ):
        """Block context source must not have double line numbers.

        Regression test for Bug 2: ctx["source"] had line-number
        prefixes from _read_source; block_review would produce
        double-numbered snippet lines like "  100  100  void foo(...)".
        """
        from core.audit.orchestrator import _try_block_level_context

        gap = _find_gap(checklist, "reqparse.c", "parse_headers")
        config = _FakeConfig(target_path=target_path, out_dir=tmp_path)
        ctx = {"source": "placeholder"}

        result = _try_block_level_context(gap, ctx, config, evidence_index)
        if result is None:
            pytest.skip("block review not triggered")

        in_code_block = False
        for line in result.splitlines():
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code_block = not in_code_block
                continue
            if not in_code_block:
                continue
            double_num = re.match(r"^\s*\d+\s+\d+\s+\S", stripped)
            assert not double_num, (
                f"Double line-number prefix in code block: {stripped!r}"
            )

    def test_full_round_trip_context_keys(
        self, target_path, checklist, evidence_index, tmp_path,
    ):
        """_build_context → ctx should have all required keys."""
        from core.audit.orchestrator import _build_context

        gap = _find_gap(checklist, "reqparse.c", "parse_headers")
        config = _FakeConfig(target_path=target_path, out_dir=tmp_path)

        ctx = _build_context(
            config, gap, checklist,
            context_map=None,
            evidence_index=evidence_index,
        )

        assert ctx["file"] == "reqparse.c"
        assert ctx["function"] == "parse_headers"
        assert "source" in ctx
        assert isinstance(ctx["callers"], list)
        assert isinstance(ctx["callees"], list)


# =====================================================================
# 4. Taint propagation correctness on real code
# =====================================================================


class TestTaintPropagationE2E:

    def test_parse_headers_paths_to_sink(
        self, target_path, evidence_index,
    ):
        """parse_headers has memcpy calls reachable from tainted buf."""
        from core.audit.block_review import (
            analyze_complexity,
            try_build_cfg,
        )

        cfg = try_build_cfg("reqparse.c", "parse_headers", target_path)
        if cfg is None:
            pytest.skip("C CFG builder not available")

        key = "reqparse.c:parse_headers"
        taint = None
        if key in evidence_index and evidence_index[key].taint_approx:
            taint = evidence_index[key].taint_approx

        profile = analyze_complexity(cfg, taint_approx=taint)
        assert profile.path_to_sink_count > 0, (
            "parse_headers has memcpy calls reachable from tainted buf"
        )

    def test_lookup_user_paths_to_sink(
        self, target_path, evidence_index,
    ):
        """lookup_user has snprintf calls reachable from tainted username."""
        from core.audit.block_review import (
            analyze_complexity,
            try_build_cfg,
        )

        cfg = try_build_cfg("database.c", "lookup_user", target_path)
        if cfg is None:
            pytest.skip("C CFG builder not available")

        key = "database.c:lookup_user"
        taint = None
        if key in evidence_index and evidence_index[key].taint_approx:
            taint = evidence_index[key].taint_approx

        profile = analyze_complexity(cfg, taint_approx=taint)
        assert profile.path_to_sink_count > 0, (
            "lookup_user has snprintf calls reachable from tainted username"
        )

    def test_callee_names_not_taint_sources(
        self, target_path, evidence_index,
    ):
        """Callee names (memcpy, snprintf) must NOT inflate taint counts.

        Regression test for Bug 4: callee names from dangerous_flows
        were added to the taint set, inflating taint_relevant_branches.
        """
        from core.audit.block_review import (
            analyze_complexity,
            try_build_cfg,
        )

        cfg = try_build_cfg("reqparse.c", "parse_headers", target_path)
        if cfg is None:
            pytest.skip("C CFG builder not available")

        key = "reqparse.c:parse_headers"
        taint = None
        if key in evidence_index and evidence_index[key].taint_approx:
            taint = evidence_index[key].taint_approx

        profile = analyze_complexity(cfg, taint_approx=taint)

        params = getattr(taint, "params", []) if taint else []
        assert profile.taint_relevant_branches <= len(params) * 10, (
            "taint_relevant_branches appears inflated by callee names"
        )

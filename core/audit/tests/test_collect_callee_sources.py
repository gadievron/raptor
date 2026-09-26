"""``collect_callee_sources`` — the public callee-direction seam.

``core.audit.context`` already exported the caller direction
(``collect_caller_call_sites``); the callee lookup + source
enrichment pair (``_find_callees`` / ``_enrich_callees_with_source``)
was reachable only through ``assemble_context``. The public seam
combines the same two helpers with the same named window constants so
other pipelines consume the audit-side extractor instead of forking
it. These tests pin the wrapper contract: constant-derived defaults,
row cap before enrichment, cap pass-through, context-map fallback,
and empty-input degradation.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

from core.audit.context import (
    CALLEE_SNIPPET_SPAN_LINES,
    CALLEE_SNIPPET_TOTAL_LINES,
    MAX_PROMPT_CALLEES,
    collect_callee_sources,
)


def test_defaults_are_the_named_constants() -> None:
    sig = inspect.signature(collect_callee_sources)
    assert sig.parameters["max_callees"].default == MAX_PROMPT_CALLEES
    assert sig.parameters["max_lines"].default == CALLEE_SNIPPET_SPAN_LINES
    assert (sig.parameters["max_total_lines"].default
            == CALLEE_SNIPPET_TOTAL_LINES)


def _context_map(n_callees: int, callee_file: str) -> dict[str, Any]:
    """Context map whose ``call_edges`` name *n_callees* distinct
    callees of ``target_fn`` defined in ``caller.c``."""
    return {
        "call_edges": [
            {
                "caller": "target_fn",
                "caller_file": "caller.c",
                "callee": f"helper_{i}",
                "callee_file": callee_file,
            }
            for i in range(n_callees)
        ],
    }


def _write_callee_file(tmp_path: Path, n_lines: int = 40) -> str:
    lines = [f"callee-marker-{i:04d}" for i in range(1, n_lines + 1)]
    (tmp_path / "callee.c").write_bytes(("\n".join(lines) + "\n").encode())
    return "callee.c"


class TestDiscovery:
    def test_context_map_fallback_finds_callees(self, tmp_path: Path):
        fp = _write_callee_file(tmp_path)
        out = collect_callee_sources(
            None, "caller.c", "target_fn", tmp_path,
            context_map=_context_map(3, fp),
        )
        assert [c["name"] for c in out] == ["helper_0", "helper_1", "helper_2"]

    def test_no_inventory_no_context_map_is_empty(self, tmp_path: Path):
        assert collect_callee_sources(
            None, "caller.c", "target_fn", tmp_path,
        ) == []

    def test_unrelated_caller_edges_ignored(self, tmp_path: Path):
        cm = {
            "call_edges": [
                {
                    "caller": "other_fn",
                    "caller_file": "caller.c",
                    "callee": "helper_x",
                    "callee_file": "callee.c",
                },
            ],
        }
        assert collect_callee_sources(
            None, "caller.c", "target_fn", tmp_path, context_map=cm,
        ) == []


class TestRowCap:
    def test_rows_capped_at_max_callees(self, tmp_path: Path):
        fp = _write_callee_file(tmp_path)
        out = collect_callee_sources(
            None, "caller.c", "target_fn", tmp_path,
            max_callees=2, context_map=_context_map(4, fp),
        )
        assert len(out) == 2

    def test_default_cap_is_max_prompt_callees(self, tmp_path: Path):
        fp = _write_callee_file(tmp_path)
        out = collect_callee_sources(
            None, "caller.c", "target_fn", tmp_path,
            context_map=_context_map(MAX_PROMPT_CALLEES + 2, fp),
        )
        assert len(out) == MAX_PROMPT_CALLEES


class TestEnrichment:
    def test_internal_callee_gains_source_snippet(self, tmp_path: Path):
        fp = _write_callee_file(tmp_path)
        out = collect_callee_sources(
            None, "caller.c", "target_fn", tmp_path,
            context_map=_context_map(1, fp),
        )
        assert "callee-marker-0001" in out[0]["source_snippet"]

    def test_max_lines_cap_passes_through(self, tmp_path: Path):
        fp = _write_callee_file(tmp_path)
        out = collect_callee_sources(
            None, "caller.c", "target_fn", tmp_path,
            max_lines=2, context_map=_context_map(1, fp),
        )
        snippet = out[0]["source_snippet"]
        assert "callee-marker-0002" in snippet
        assert "callee-marker-0003" not in snippet

    def test_total_budget_cap_passes_through(self, tmp_path: Path):
        fp = _write_callee_file(tmp_path)
        out = collect_callee_sources(
            None, "caller.c", "target_fn", tmp_path,
            max_lines=5, max_total_lines=5,
            context_map=_context_map(3, fp),
        )
        enriched = [c for c in out if "source_snippet" in c]
        # First callee consumes the whole shared budget; the rest
        # render as bare rows — same behaviour assemble_context gets.
        assert len(enriched) == 1

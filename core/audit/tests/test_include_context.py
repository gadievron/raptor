"""Audit include_context block: hint-tier PHP include topology in
the review prompt, always census-qualified, never a verdict input."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.context import (
    MAX_INCLUDERS_RENDERED,
    _build_include_context,
    format_context_for_prompt,
)


def _write_graph(out_dir: Path, *, includers=1, unresolved=3,
                 unwalked=2) -> None:
    graph = {
        "tier": "hint",
        "census": {"unresolved_edge_count": unresolved,
                   "unwalked_target_count": unwalked},
        "files": {
            "lib/shared.php": {
                "role": "library",
                "includer_count": includers,
                "included_by": [
                    {"includer": f"entry_{i}.php", "line": 3 + i,
                     "keyword": "require_once", "conditional": False,
                     "position": "file_scope", "basis": "tail_unique"}
                    for i in range(includers)
                ],
                "direct_access_guard": True,
            },
            "entry_0.php": {
                "role": "designed_entry", "includer_count": 0,
                "included_by": [], "direct_access_guard": False,
            },
        },
        "unresolved_edges": [], "unwalked_targets": [],
    }
    (out_dir / "include-graph.json").write_text(json.dumps(graph))


def _ctx(include_context):
    return {
        "file": "lib/shared.php",
        "function": "interstitial:1-40",
        "line_start": 1,
        "source": "<?php $x = 1;",
        "metadata": {},
        "callers": [],
        "callees": [],
        "sinks": [],
        "existing_annotation": None,
        "threat_model": None,
        "include_context": include_context,
    }


class TestBuildIncludeContext:
    def test_facts_for_graph_file(self, tmp_path):
        _write_graph(tmp_path)
        facts = _build_include_context(tmp_path, "lib/shared.php")
        assert facts["tier"] == "hint"
        assert facts["role"] == "library"
        assert facts["direct_access_guard"] is True
        assert facts["census"]["unresolved_edges"] == 3
        assert "3 unresolved include site(s)" in facts["qualifier"]

    def test_absent_for_non_graph_file(self, tmp_path):
        _write_graph(tmp_path)
        assert _build_include_context(tmp_path, "src/main.c") is None

    def test_absent_without_graph(self, tmp_path):
        assert _build_include_context(tmp_path, "lib/shared.php") is None
        assert _build_include_context(None, "lib/shared.php") is None

    def test_forged_enums_sanitised(self, tmp_path):
        graph = {
            "census": {"unresolved_edge_count": 0,
                       "unwalked_target_count": 0},
            "files": {"a.php": {
                "role": "library", "includer_count": 1,
                "included_by": [{"includer": "b.php", "line": 1,
                                 "keyword": "system('x')",
                                 "position": "## injected"}],
            }},
        }
        (tmp_path / "include-graph.json").write_text(json.dumps(graph))
        facts = _build_include_context(tmp_path, "a.php")
        [inc] = facts["includers"]
        assert inc["keyword"] == "include"
        assert inc["position"] == "file_scope"


class TestRenderer:
    def test_census_qualifier_always_rendered(self, tmp_path):
        _write_graph(tmp_path)
        facts = _build_include_context(tmp_path, "lib/shared.php")
        out = format_context_for_prompt(_ctx(facts))
        assert "### Include topology (hint-tier)" in out
        assert "included by 1 file(s)" in out
        assert "direct-access guard: yes" in out
        assert "entry_0.php:3" in out
        # the mandatory census line
        assert "3 unresolved include site(s)" in out
        assert "2 unwalked include target(s)" in out
        assert "never treat as a verdict input" in out.lower()

    def test_includer_list_capped(self, tmp_path):
        _write_graph(tmp_path, includers=MAX_INCLUDERS_RENDERED + 5)
        facts = _build_include_context(tmp_path, "lib/shared.php")
        out = format_context_for_prompt(_ctx(facts))
        assert f"entry_{MAX_INCLUDERS_RENDERED - 1}.php" in out
        assert "(+5 more includers" in out

    def test_designed_entry_rendering(self, tmp_path):
        _write_graph(tmp_path)
        facts = _build_include_context(tmp_path, "entry_0.php")
        out = format_context_for_prompt(_ctx(facts))
        assert "designed entry — no includers found" in out

    def test_no_block_without_facts(self):
        out = format_context_for_prompt(_ctx(None))
        assert "Include topology" not in out

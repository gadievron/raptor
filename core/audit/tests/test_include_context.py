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

    def test_every_producer_basis_survives_to_block(self, tmp_path):
        # The block carries the includer refs verbatim from the one
        # consumer query; every basis the graph build can write must
        # arrive intact — the grounded/guessed distinction is what
        # the field exists to carry.
        from core.inventory.include_graph import REF_BASIS_VALUES
        graph = {
            "census": {"unresolved_edge_count": 0,
                       "unwalked_target_count": 0},
            "files": {"a.php": {
                "role": "library",
                "includer_count": len(REF_BASIS_VALUES),
                "included_by": [
                    {"includer": f"e{i}.php", "line": 1 + i,
                     "keyword": "require_once", "conditional": False,
                     "position": "file_scope", "basis": basis}
                    for i, basis in enumerate(REF_BASIS_VALUES)],
            }},
            "unresolved_edges": [], "unwalked_targets": [],
        }
        (tmp_path / "include-graph.json").write_text(json.dumps(graph))
        facts = _build_include_context(tmp_path, "a.php")
        assert [inc["basis"] for inc in facts["includers"]] == list(
            REF_BASIS_VALUES)


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


class TestBootstrapRendering:
    def _graph_with_walk(self, out_dir: Path) -> None:
        graph = {
            "tier": "hint",
            "census": {"unresolved_edge_count": 1,
                       "unwalked_target_count": 0},
            "files": {"lib/shared.php": {
                "role": "library", "includer_count": 1,
                "included_by": [{
                    "includer": "src/e1.php", "line": 3,
                    "keyword": "require_once", "conditional": False,
                    "position": "file_scope", "basis": "env_resolved",
                }],
                "direct_access_guard": False,
            }},
            "unresolved_edges": [], "unwalked_targets": [],
            "walk": {
                "entries_walked": 2, "entries_truncated": False,
                "outcomes": {},
                "entry_classes": [{
                    "class": "ecdeadbeef", "entry_count": 2,
                    "entries": ["src/e1.php", "src/e2.php"],
                    "guaranteed_prefix": ["inc/gate.php",
                                          "lib/shared.php"],
                }],
                "prefixes": {},
                "file_facts": {
                    "lib/shared.php": {"classes": [{
                        "class": "ecdeadbeef", "guaranteed": True,
                        "entries_reaching": 2,
                        "receipt": "src/e1.php -> "
                                   "src/e1.php:3->lib/shared.php",
                        "preceding": ["inc/gate.php"],
                    }]},
                    "inc/gate.php": {"classes": [{
                        "class": "ecdeadbeef", "guaranteed": True,
                        "entries_reaching": 2,
                        "receipt": "src/e1.php -> "
                                   "src/e1.php:2->inc/gate.php",
                    }]},
                },
            },
        }
        (out_dir / "include-graph.json").write_text(json.dumps(graph))

    def test_bootstrap_facts_rendered(self, tmp_path):
        self._graph_with_walk(tmp_path)
        facts = _build_include_context(tmp_path, "lib/shared.php")
        assert facts["bootstrap"]["entry_classes"][0]["guaranteed"]
        out = format_context_for_prompt(_ctx(facts))
        assert "Entry class `ecdeadbeef` reaches this file" in out
        assert "2 entries, guaranteed" in out
        assert "Guaranteed to have executed BEFORE this file" in out
        assert "inc/gate.php" in out
        assert "verify" in out  # hint-toned, never a verdict
        # the census line still renders once
        assert "1 unresolved include site(s)" in out

    def test_no_walk_no_bootstrap_lines(self, tmp_path):
        _write_graph(tmp_path)  # 1a-shaped graph without walk
        facts = _build_include_context(tmp_path, "lib/shared.php")
        assert "bootstrap" not in facts
        out = format_context_for_prompt(_ctx(facts))
        assert "Entry class" not in out

    def test_prefix_elision_renders_true_total(self, tmp_path):
        # The producer caps the carried prefix list; the rendered
        # "+N more" must count against the TRUE shared total, and
        # the earliest names must still render.
        preceding = [f"p{i:02d}.php" for i in range(1, 19)]
        g = {
            "tier": "hint",
            "census": {"unresolved_edge_count": 0,
                       "unwalked_target_count": 0},
            "files": {"lib/shared.php": {
                "role": "library", "includer_count": 1,
                "included_by": [{
                    "includer": "src/e1.php", "line": 3,
                    "keyword": "require_once", "conditional": False,
                    "position": "file_scope", "basis": "env_resolved",
                }],
                "direct_access_guard": False,
            }},
            "unresolved_edges": [], "unwalked_targets": [],
            "walk": {
                "entries_walked": 1, "entries_truncated": False,
                "outcomes": {},
                "entry_classes": [{
                    "class": "ecdeadbeef", "entry_count": 1,
                    "entries": ["src/e1.php"],
                    "guaranteed_prefix": preceding + ["lib/shared.php"],
                }],
                "prefixes": {},
                "file_facts": {"lib/shared.php": {"classes": [{
                    "class": "ecdeadbeef", "guaranteed": True,
                    "entries_reaching": 1,
                    "receipt": "src/e1.php -> x",
                    "preceding": preceding,
                }]}},
            },
        }
        (tmp_path / "include-graph.json").write_text(json.dumps(g))
        facts = _build_include_context(tmp_path, "lib/shared.php")
        bc = facts["bootstrap"]
        assert len(bc["guaranteed_prefix"]) == 15  # producer cap
        assert bc["guaranteed_prefix_total"] == 18
        assert bc["guaranteed_prefix_truncated"] is True
        out = format_context_for_prompt(_ctx(facts))
        assert "p10.php" in out
        assert "(+8 more)" in out  # 18 total - 10 rendered


class TestWalkTruncationCensusLine:
    """A budget-starved walk silently drops entry classes — the
    prompt's census line must say so whenever gate lines render."""

    def _write_built_graph(self, out_dir: Path) -> None:
        # A REAL graph from the real builder: many entries sharing
        # one library, each entry a define + one include.
        from core.inventory.include_graph import build_include_graph

        def entry(path):
            return {
                "path": path, "language": "php", "sha256": "x",
                "items": [], "call_graph": {
                    "imports": {}, "calls": [], "indirection": [],
                    "includes": [{
                        "line": 3, "keyword": "require_once",
                        "shape": "const_prefix", "conditional": False,
                        "position": "file_scope", "span_hash": "0" * 12,
                        "raw": "", "const_name": "APP",
                        "literal_tail": "lib/shared.php"}],
                    "defines": [{"line": 2, "name": "APP",
                                 "value": "./", "conditional": False,
                                 "fallback": False,
                                 "position": "file_scope"}]}}
        files = [entry(f"e{i}.php") for i in range(1, 7)]
        files.append({"path": "lib/shared.php", "language": "php",
                      "sha256": "x", "items": [],
                      "call_graph": {"imports": {}, "calls": [],
                                     "indirection": [], "includes": [],
                                     "defines": []}})
        g = build_include_graph({
            "target_path": "/t", "parse_fingerprint": "fp-test",
            "files": files, "excluded_files": [],
        })
        (out_dir / "include-graph.json").write_text(json.dumps(g))

    def test_starved_walk_truncation_reaches_census_line(
            self, tmp_path, monkeypatch):
        import core.inventory.include_walk as iw
        monkeypatch.setattr(iw, "MAX_WALK_STMT_VISITS", 3)
        self._write_built_graph(tmp_path)
        facts = _build_include_context(tmp_path, "lib/shared.php")
        bc = facts["bootstrap"]
        assert bc["unresolved_census"]["walk_truncated_entries"] == 5
        out = format_context_for_prompt(_ctx(facts))
        # gate lines render — and the census line carries the walk's
        # own truncation sentence, not just the graph-level counts
        assert "Entry class" in out
        assert "environment walk was TRUNCATED for 5 entries" in out
        assert "(global walk budget exhausted)" in out

    def test_unstarved_walk_has_no_truncation_sentence(self, tmp_path):
        self._write_built_graph(tmp_path)
        facts = _build_include_context(tmp_path, "lib/shared.php")
        assert "walk_truncated_entries" not in \
            facts["bootstrap"]["unresolved_census"]
        out = format_context_for_prompt(_ctx(facts))
        assert "Entry class" in out
        assert "TRUNCATED" not in out

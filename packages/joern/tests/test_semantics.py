"""Tests for packages.joern.semantics — learned flow-semantics rows.

Semantics rows are rendered into a Scala REPL, so name validation is a
security boundary, not a convenience: every rejection case here is an
injection defence. The render tests pin the byte-identical-default
contract — a server with no semantics installed must submit exactly
the script it submitted before the slots existed.
"""

from __future__ import annotations

from pathlib import Path

from packages.joern.semantics import (
    SemanticRow,
    filter_valid_rows,
    render_context_arg,
    render_semantics_decl,
    rows_from_vocab,
    validate_row,
)

_QUERIES = Path(__file__).resolve().parents[1] / "queries"


class TestValidateRow:
    def test_bare_identifier_kill_row_valid(self):
        assert validate_row(SemanticRow(method="sanitize")) is None

    def test_qualified_identifier_valid(self):
        assert validate_row(SemanticRow(method="mod.sub.sanitize")) is None

    def test_propagate_row_valid(self):
        row = SemanticRow(
            method="wrap", kind="propagate", mappings=((1, 1), (1, -1)),
        )
        assert validate_row(row) is None

    def test_scala_injection_refused(self):
        for evil in (
            'x"); System.exit(0); ("',
            "x; import sys",
            "x)",
            "x`y`",
            "x y",
            ".*sanitize",
            "sanitize$",
            "",
        ):
            row = SemanticRow(method=evil)
            assert validate_row(row) is not None, evil

    def test_llm_prior_provenance_refused(self):
        row = SemanticRow(method="sanitize", provenance="llm_prior")
        err = validate_row(row)
        assert err is not None and "provenance" in err

    def test_other_provenance_tiers_pass(self):
        for tier in ("", "verbatim", "mechanical", "llm_summarized"):
            assert validate_row(
                SemanticRow(method="sanitize", provenance=tier)
            ) is None

    def test_kill_with_mappings_refused(self):
        row = SemanticRow(method="x", kind="kill", mappings=((1, 1),))
        assert validate_row(row) is not None

    def test_propagate_without_mappings_refused(self):
        row = SemanticRow(method="x", kind="propagate")
        assert validate_row(row) is not None

    def test_unknown_kind_refused(self):
        row = SemanticRow(method="x", kind="taint")
        assert validate_row(row) is not None

    def test_mapping_index_bounds(self):
        bad = [((-2, 1),), ((1, 65),), ((True, 1),)]
        for mappings in bad:
            row = SemanticRow(method="x", kind="propagate", mappings=mappings)
            assert validate_row(row) is not None, mappings

    def test_too_many_mappings_refused(self):
        row = SemanticRow(
            method="x", kind="propagate",
            mappings=tuple((1, i) for i in range(9)),
        )
        assert validate_row(row) is not None


class TestFilterAndVocab:
    def test_filter_splits_and_reports(self):
        rows = [SemanticRow(method="ok"), SemanticRow(method="not ok")]
        valid, rejected = filter_valid_rows(rows)
        assert [r.method for r in valid] == ["ok"]
        assert len(rejected) == 1

    def test_strings_become_kill_rows(self):
        rows = rows_from_vocab(["check_len", "mod.validate_path"])
        assert [(r.method, r.kind) for r in rows] == [
            ("check_len", "kill"), ("mod.validate_path", "kill"),
        ]

    def test_dict_entries_carry_kind_and_mappings(self):
        rows = rows_from_vocab([
            {"name": "wrap", "kind": "propagate", "mappings": [[1, -1]]},
        ])
        assert rows == [SemanticRow(
            method="wrap", kind="propagate", mappings=((1, -1),),
        )]

    def test_llm_prior_entries_dropped(self):
        rows = rows_from_vocab([
            {"name": "sanitize", "provenance": "llm_prior"},
            {"name": "keep_me", "provenance": "mechanical"},
        ])
        assert [r.method for r in rows] == ["keep_me"]

    def test_garbage_entries_dropped(self):
        rows = rows_from_vocab([
            {"name": ""},
            {"no_name": "x"},
            {"name": "bad", "kind": "propagate", "mappings": "not-a-list"},
            42,
        ])
        assert rows == []


class TestRender:
    def test_empty_rows_render_empty(self):
        assert render_semantics_decl([]) == ""
        assert render_context_arg([]) == ""

    def test_decl_resolves_in_cpg_with_exact_rows(self):
        decl = render_semantics_decl([
            SemanticRow(method="sanitize"),
            SemanticRow(method="m.wrap", kind="propagate",
                        mappings=((1, -1),)),
        ])
        # In-CPG resolution to exact fullNames — FullNameSemantics'
        # forMethod is an exact-map lookup, regex rows are not
        # consulted on that path.
        assert "cpg.method.nameExact(n)" in decl
        assert "FullNameSemantics.fromList" in decl
        assert "DefaultSemantics()" in decl
        assert '("sanitize", "sanitize", false, List[(Int, Int)]())' in decl
        assert '("wrap", "m.wrap", true, List[(Int, Int)]((1, -1)))' in decl
        assert "JOERN_SEMANTICS:installed=" in decl

    def test_context_arg_names_the_val(self):
        arg = render_context_arg([SemanticRow(method="s")])
        assert arg == "semantics = raptorSemantics, "


class TestTieredTemplateRendering:
    """The tiered sweep renders byte-identically when no semantics set."""

    def _render(self, server) -> str:
        captured = {}
        server._submit_query = (  # noqa: SLF001 — test seam
            lambda content, **kw: captured.update(script=content) or None
        )
        server.run_tiered_sweep()
        return captured["script"]

    def _bare_server(self):
        from packages.joern.server import JoernServer
        srv = JoernServer.__new__(JoernServer)
        srv._flow_semantics = []
        srv._query_timeout_s = 1
        return srv

    def test_default_render_has_no_slot_residue_and_no_semantics(self):
        srv = self._bare_server()
        script = self._render(srv)
        assert "__SEMANTICS_DECL__" not in script
        assert "__CTX_SEMANTICS__" not in script
        assert "raptorSemantics" not in script
        # The exact pre-slot EngineContext lines.
        assert "val tier1Ctx = EngineContext(config = tier1Config)" in script
        assert "val tier2Ctx = EngineContext(config = tier2Config)" in script
        # Slot removal eats the whole line: no blank line is left
        # between the sinks val and the next statement.
        assert "__DANGEROUS_SINKS__" not in script

    def test_default_render_byte_identical_to_slot_stripped_template(self):
        srv = self._bare_server()
        script = self._render(srv)
        template = (_QUERIES / "tiered_taint.sc").read_text(encoding="utf-8")
        from packages.joern.lang_config import DEFAULT
        expected = (
            template
            .replace("__DANGEROUS_SINKS__",
                     "List(" + ", ".join(f'"{s}"' for s in DEFAULT.sinks) + ")")
            .replace("__EFFECTIVE_DEPTH__", str(DEFAULT.max_call_depth))
            .replace("__MAX_ARGS__", str(DEFAULT.max_args_to_allow))
            .replace("__MAX_OUTPUT_ARGS__",
                     str(DEFAULT.max_output_args_expansion))
            .replace("__SEMANTICS_DECL__\n", "")
            .replace("__CTX_SEMANTICS__", "")
        )
        assert script == expected

    def test_semantics_render_reaches_both_tiers(self):
        srv = self._bare_server()
        srv.set_flow_semantics([SemanticRow(method="sanitize")])
        script = self._render(srv)
        assert "val raptorSemantics" in script
        assert (
            "val tier1Ctx = EngineContext("
            "semantics = raptorSemantics, config = tier1Config)"
        ) in script
        assert (
            "val tier2Ctx = EngineContext("
            "semantics = raptorSemantics, config = tier2Config)"
        ) in script


class TestServerSetFlowSemantics:
    def _bare_server(self):
        from packages.joern.server import JoernServer
        srv = JoernServer.__new__(JoernServer)
        srv._flow_semantics = []
        return srv

    def test_accepts_rows_and_vocab_shapes(self):
        srv = self._bare_server()
        assert srv.set_flow_semantics([SemanticRow(method="a")]) == 1
        assert srv.set_flow_semantics(["b", {"name": "c"}]) == 2

    def test_invalid_and_llm_prior_dropped(self):
        srv = self._bare_server()
        kept = srv.set_flow_semantics([
            {"name": "ok"},
            {"name": "bad name"},
            {"name": "prior", "provenance": "llm_prior"},
        ])
        assert kept == 1
        assert [r.method for r in srv._flow_semantics] == ["ok"]

    def test_empty_clears(self):
        srv = self._bare_server()
        srv.set_flow_semantics(["a"])
        assert srv.set_flow_semantics([]) == 0
        assert srv._flow_semantics == []


class TestBatchQueryRendersSemantics:
    def _server_with_capture(self):
        from packages.joern.server import JoernServer
        srv = JoernServer.__new__(JoernServer)
        srv._flow_semantics = []
        srv._query_timeout_s = 1
        captured = {}

        class _Result:
            errors = []
            flows = []

        srv.query = (  # noqa: SLF001 — test seam
            lambda q, **kw: captured.update(script=q) or _Result()
        )
        return srv, captured

    def test_batch_default_has_no_semantics(self):
        srv, captured = self._server_with_capture()
        srv.run_taint_queries_batch([("src_fn", "sink_fn")])
        assert "raptorSemantics" not in captured["script"]
        assert "EngineContext(config = batchConfig)" in captured["script"]

    def test_batch_transport_contract(self):
        # /query-sync drops println output and truncates on huge val
        # echoes: flows must ride the final string expression, pairs
        # must run inside locally{} so no intermediate val echoes.
        srv, captured = self._server_with_capture()
        srv.run_taint_queries_batch([("src_fn", "sink_fn")])
        script = captured["script"]
        assert "println(" not in script
        assert script.rstrip().endswith(
            '"JOERN_FLOWS_START\\n" + raptorBatchLines.mkString("\\n") '
            '+ "\\nJOERN_FLOWS_END"'
        )
        assert "locally {\nval src0" in script
        # Single interpolator dollars — $$ would print literal $ln.
        assert "$$" not in script

    def test_batch_with_semantics_installs_context(self):
        srv, captured = self._server_with_capture()
        srv.set_flow_semantics(["sanitize"])
        srv.run_taint_queries_batch([("src_fn", "sink_fn")])
        script = captured["script"]
        assert "val raptorSemantics" in script
        assert (
            "EngineContext(semantics = raptorSemantics, "
            "config = batchConfig)"
        ) in script

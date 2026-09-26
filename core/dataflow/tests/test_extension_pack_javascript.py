"""javascript layout of ``core.dataflow.extension_pack``: verified
(type, path) row shapes, the js type/access cell grammars under
hostile input, the pinned barrier exclusion, the ``js_coordinate``
boundary rule, and the javascript branch of the TaintSpec converter.

Ground truth: ``codeql/javascript-all`` 2.10.1
(``semmle/javascript/frameworks/data/internal/
ApiGraphModelsExtensions.qll``) — ``sourceModel``/``sinkModel`` rows
are ``(type, path, kind)``, ``summaryModel`` rows are
``(type, path, input, output, kind)``; the trailing ``madId`` column
is assigned by the CLI, never authored. ``barrierModel`` exists
upstream and is deliberately NOT in this layout.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.dataflow.extension_pack import (
    ModelRow,
    SUPPORTED_LANGUAGES,
    _LANGUAGE_LAYOUTS,
    ROLE_BARRIER,
    _valid_js_access,
    js_coordinate,
    rows_from_taint_specs,
    write_extension_pack,
)
from core.evidence import EvidenceTier


def _row(**kw) -> ModelRow:
    base = dict(
        role="sink",
        provenance="framework_catalog",
        type_name="child_process",
        path="Member[exec].Argument[0]",
        model_kind="command-injection",
    )
    base.update(kw)
    return ModelRow(**base)


def _rows_of(model_file: Path) -> list[list]:
    return [
        json.loads(ln.strip()[2:])
        for ln in model_file.read_text().splitlines()
        if ln.strip().startswith("- [")
    ]


# ---------------------------------------------------------------------
# Layout + emission shapes
# ---------------------------------------------------------------------


class TestJavascriptEmission:
    def test_javascript_is_supported(self):
        assert "javascript" in SUPPORTED_LANGUAGES

    def test_sink_row_is_three_columns(self, tmp_path: Path):
        result = write_extension_pack(
            [_row()], language="javascript", out_dir=tmp_path,
        )
        assert result.counts == {"sinkModel": 1}
        text = result.model_file.read_text()
        assert "pack: codeql/javascript-all" in text
        assert _rows_of(result.model_file) == [
            ["child_process", "Member[exec].Argument[0]",
             "command-injection"],
        ]

    def test_source_row_is_three_columns(self, tmp_path: Path):
        result = write_extension_pack(
            [_row(role="source", type_name="express.Request",
                  path="Member[query]", model_kind="remote")],
            language="javascript", out_dir=tmp_path,
        )
        assert result.counts == {"sourceModel": 1}
        assert _rows_of(result.model_file) == [
            ["express.Request", "Member[query]", "remote"],
        ]

    def test_summary_row_is_five_columns(self, tmp_path: Path):
        result = write_extension_pack(
            [_row(role="summary", type_name="path", path="Member[join]",
                  access_input="Argument[0..]",
                  access_output="ReturnValue", model_kind="taint",
                  provenance="framework_catalog")],
            language="javascript", out_dir=tmp_path,
        )
        assert result.counts == {"summaryModel": 1}
        assert _rows_of(result.model_file) == [
            ["path", "Member[join]", "Argument[0..]", "ReturnValue",
             "taint"],
        ]

    def test_pack_manifest_targets_javascript_all(self, tmp_path: Path):
        result = write_extension_pack(
            [_row()], language="javascript", out_dir=tmp_path,
        )
        manifest = (result.pack_dir / "codeql-pack.yml").read_text()
        assert "codeql/javascript-all: \"*\"" in manifest
        assert "dataExtensions:" in manifest

    def test_emitted_pack_parses_as_yaml_extensions(self, tmp_path: Path):
        """Round-trip: the model file must be valid YAML whose shape
        matches the data-extension schema (extensions → addsTo/data).
        Skipped hermetically when PyYAML is absent on the runner; the
        per-row JSON parse above holds structure regardless."""
        yaml = pytest.importorskip("yaml")
        result = write_extension_pack(
            [
                _row(),
                _row(role="source", type_name="express.Request",
                     path="Member[body]", model_kind="remote"),
                _row(role="summary", type_name="path",
                     path="Member[resolve]", access_input="Argument[0..]",
                     access_output="ReturnValue", model_kind="taint"),
            ],
            language="javascript", out_dir=tmp_path,
        )
        doc = yaml.safe_load(result.model_file.read_text())
        assert set(doc) == {"extensions"}
        predicates = set()
        for ext in doc["extensions"]:
            assert set(ext) == {"addsTo", "data"}
            assert ext["addsTo"]["pack"] == "codeql/javascript-all"
            predicates.add(ext["addsTo"]["extensible"])
            widths = {len(r) for r in ext["data"]}
            expected = 5 if ext["addsTo"]["extensible"] == "summaryModel" else 3
            assert widths == {expected}
            for r in ext["data"]:
                assert all(isinstance(cell, str) for cell in r)
        assert predicates == {"sourceModel", "sinkModel", "summaryModel"}


# ---------------------------------------------------------------------
# Pinned invariant: no barrier predicate, ever
# ---------------------------------------------------------------------


class TestBarrierExclusion:
    def test_layout_has_no_barrier_role(self):
        assert ROLE_BARRIER not in _LANGUAGE_LAYOUTS["javascript"]

    def test_barrier_row_refused_with_directed_reason(self, tmp_path: Path):
        result = write_extension_pack(
            [_row(role="barrier", access_output="ReturnValue",
                  provenance="operator")],
            language="javascript", out_dir=tmp_path,
        )
        assert result.rows_written == 0
        (rej,) = result.rejected
        assert "barrier" in rej.reason
        assert "closed" in rej.reason

    def test_model_file_never_contains_barrier_predicate(self, tmp_path: Path):
        result = write_extension_pack(
            [_row(), _row(role="barrier", access_output="ReturnValue",
                          provenance="operator")],
            language="javascript", out_dir=tmp_path,
        )
        assert "barrierModel" not in result.model_file.read_text()


# ---------------------------------------------------------------------
# Cell grammars under hostile input
# ---------------------------------------------------------------------


HOSTILE_SUFFIXES = ["\n", "\x0b", "\x1b[31m", "\r"]


class TestJsTypeGrammar:
    @pytest.mark.parametrize("type_name", [
        "global", "child_process", "express.Request", "aws-sdk",
        "@google-cloud/spanner.Transaction", "sequelize.Sequelize",
        "fs", "shelljs", "express.~Request",
    ])
    def test_real_shapes_accepted(self, type_name, tmp_path: Path):
        result = write_extension_pack(
            [_row(type_name=type_name)],
            language="javascript", out_dir=tmp_path,
        )
        assert result.rows_written == 1, result.rejected

    @pytest.mark.parametrize("suffix", HOSTILE_SUFFIXES)
    def test_trailing_bytes_refused(self, suffix, tmp_path: Path):
        # \Z discipline: "child_process\n" must not validate as the
        # visually identical twin of "child_process".
        result = write_extension_pack(
            [_row(type_name="child_process" + suffix)],
            language="javascript", out_dir=tmp_path,
        )
        assert result.rows_written == 0
        assert "type" in result.rejected[0].reason

    @pytest.mark.parametrize("type_name", [
        "", "express..Request", ".express", "'pkg.name'.Type",
        "'underscore.string'",       # quoted dotted package: never emitted
        "underscore.string",         # unquoted dotted package: misparses
                                     # upstream as package+type (dead row)
        "(express)", "file:src/app.js", "express Request",
        "express\n.Request", "exp\x00ress", "@/x", "@scope/",
        "@UPPER/pkg", "Buffer",      # uppercase package: npm forbids it;
                                     # global classes ride the global type
        "express.Request.params",    # members never join the type cell
    ])
    def test_out_of_grammar_types_refused(self, type_name, tmp_path: Path):
        result = write_extension_pack(
            [_row(type_name=type_name)],
            language="javascript", out_dir=tmp_path,
        )
        assert result.rows_written == 0


class TestJsAccessGrammar:
    @pytest.mark.parametrize("path", [
        "Member[exec].Argument[0]",
        "Member[promises].Member[readFile].Argument[0]",
        "Member[query]",
        "Member[interceptors].Member[request].Member[use].Argument[0]",
        "Member[executeSql].Argument[0..]",
        "Member[run].ReturnValue.Awaited",
        "Member[batchUpdate].Argument[0].ArrayElement.Member[sql]",
        "Member[join].Argument[0..3]",
        "Instance.Member[query].Argument[0]",
        "NewCall.Member[stdout]",
        "Member[on,addListener].Argument[1].Parameter[0]",
        "WithArity[2].Argument[0]",
        "Member[all].Element",
        "Member[env].AnyMember",
        "Call.MapValue",
    ])
    def test_upstream_valid_paths_accepted(self, path):
        assert _valid_js_access(path), path

    @pytest.mark.parametrize("path", [
        # trailing/mid-cell control bytes (the \Z + charset discipline)
        "Member[exec].Argument[0]\n",
        "Member[exec]\n.Argument[0]",
        "Member[exec].Argument[0]\x0b",
        "Member[ex\nec].Argument[0]",
        "Member[exec].Argument[0] ",
        # structure violations
        "", ".", "Member[exec]..Argument[0]",
        "Member[]", "Argument[]", "Argument[a]", "Argument[-1]",
        "Argument[N-1]",              # upstream-valid, never emitted
        "Member[exec].Argument[0",    # unbalanced
        "Member[exec]].Argument[0]",  # unbalanced (early close)
        "Fuzzy",                      # upstream-valid, never emitted
        "GuardedRouteHandler",        # upstream-valid, never emitted
        "WithStringArgument[0=data]", # upstream-valid, never emitted
        "member[exec]",               # tokens are case-sensitive
        "Member[a.b]",                # dots inside Member args: refused
        "Argument[0]; DROP",
    ])
    def test_hostile_and_unemitted_paths_refused(self, path):
        assert not _valid_js_access(path), path

    def test_empty_path_only_by_explicit_allowance(self):
        assert not _valid_js_access("")
        assert _valid_js_access("", allow_empty=True)

    @pytest.mark.parametrize("suffix", HOSTILE_SUFFIXES)
    def test_row_with_hostile_path_never_written(self, suffix, tmp_path: Path):
        result = write_extension_pack(
            [_row(path="Member[exec].Argument[0]" + suffix)],
            language="javascript", out_dir=tmp_path,
        )
        assert result.rows_written == 0
        assert "path" in result.rejected[0].reason

    def test_summary_access_cells_validated(self, tmp_path: Path):
        result = write_extension_pack(
            [_row(role="summary", type_name="path", path="Member[join]",
                  access_input="Argument[0..]\n",
                  access_output="ReturnValue", model_kind="taint")],
            language="javascript", out_dir=tmp_path,
        )
        assert result.rows_written == 0
        assert "summary access" in result.rejected[0].reason

    def test_kind_cell_still_gated(self, tmp_path: Path):
        result = write_extension_pack(
            [_row(model_kind="command-injection\n")],
            language="javascript", out_dir=tmp_path,
        )
        assert result.rows_written == 0


# ---------------------------------------------------------------------
# js_coordinate boundary rule (pinned)
# ---------------------------------------------------------------------


class TestJsCoordinate:
    @pytest.mark.parametrize("dotted,expected", [
        ("eval", ("global", "Member[eval]")),
        ("Function", ("global", "Member[Function]")),
        ("Buffer.from", ("global", "Member[Buffer].Member[from]")),
        ("child_process.exec", ("child_process", "Member[exec]")),
        ("vm.Script", ("vm", "Member[Script]")),
        ("express.Request.params", ("express.Request", "Member[params]")),
        ("express.Response.sendFile",
         ("express.Response", "Member[sendFile]")),
        ("fs.promises.readFile", ("fs", "Member[promises].Member[readFile]")),
        ("lodash.template", ("lodash", "Member[template]")),
    ])
    def test_boundary_rule(self, dotted, expected):
        assert js_coordinate(dotted) == expected


# ---------------------------------------------------------------------
# TaintSpec converter, javascript branch
# ---------------------------------------------------------------------


def _spec(**kw):
    from core.iris.specs import TaintSpec
    base = dict(
        function="child_process.exec",
        file="src/app.js",
        role="sink",
        taint_classes=["command_injection"],
        params_affected=[0],
        confidence=0.9,
        evidence_tier=EvidenceTier.XREF_BACKED,
    )
    base.update(kw)
    return TaintSpec(**base)


class TestJavascriptTaintSpecConversion:
    def test_sink_spec_lands_on_js_coordinates(self):
        conv = rows_from_taint_specs([_spec()], language="javascript")
        (row,) = conv.rows
        assert row.type_name == "child_process"
        assert row.path == "Member[exec].Argument[0]"
        assert row.model_kind == "command-injection"

    def test_source_spec_gets_return_value(self):
        conv = rows_from_taint_specs(
            [_spec(role="source", function="fixture.taintedValue",
                   taint_classes=["remote"], return_tainted=True)],
            language="javascript",
        )
        (row,) = conv.rows
        assert row.type_name == "fixture"
        assert row.path == "Member[taintedValue].ReturnValue"

    def test_sanitiser_spec_refused_channel_closed(self):
        conv = rows_from_taint_specs(
            [_spec(role="sanitiser", function="myapp.clean")],
            language="javascript",
        )
        assert not conv.rows
        (rej,) = conv.rejected
        assert "barrier" in rej.reason

    def test_bare_name_propagator_rides_the_global_object(self):
        conv = rows_from_taint_specs(
            [_spec(role="propagator", function="decodeURIComponent",
                   taint_classes=[], params_affected=[0])],
            language="javascript",
        )
        (row,) = conv.rows
        assert row.role == "summary"
        assert row.type_name == "global"
        assert row.path == "Member[decodeURIComponent]"
        assert row.access_input == "Argument[0]"
        assert row.access_output == "ReturnValue"

    def test_hostile_function_name_dies_at_the_cell_grammar(self, tmp_path: Path):
        conv = rows_from_taint_specs(
            [_spec(function="child_process.exec\n")],
            language="javascript",
        )
        # The converter is shape-only; the emission gate is the grammar.
        result = write_extension_pack(
            conv.rows, language="javascript", out_dir=tmp_path,
        )
        assert result.rows_written == 0

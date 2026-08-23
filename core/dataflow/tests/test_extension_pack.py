"""Tests for ``core.dataflow.extension_pack`` (the PR2a emitter):
row shapes, provenance/cell gates, determinism, and the
TaintSpec/CandidateValidator converters. The harness/shim wiring is
covered in ``test_extension_pack_wiring.py``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.dataflow.extension_pack import (
    ACCEPTED_PROVENANCE,
    ModelRow,
    SUPPORTED_LANGUAGES,
    rows_from_candidate_validators,
    rows_from_taint_specs,
    write_extension_pack,
)
from core.evidence import EvidenceTier


def _row(**kw) -> ModelRow:
    base = dict(
        role="sink",
        provenance="study",
        name="do_exec",
        access_input="Argument[*0]",
        model_kind="command-injection",
    )
    base.update(kw)
    return ModelRow(**base)


# ---------------------------------------------------------------------
# Emission shapes
# ---------------------------------------------------------------------


class TestCppEmission:
    def test_sink_row_shape(self, tmp_path: Path):
        result = write_extension_pack(
            [_row(namespace="proj::net")], language="cpp", out_dir=tmp_path,
        )
        assert result.counts == {"sinkModel": 1}
        text = result.model_file.read_text()
        assert "pack: codeql/cpp-all" in text
        assert "extensible: sinkModel" in text
        row = json.loads(
            [ln for ln in text.splitlines() if ln.strip().startswith("- [")][0]
            .strip()[2:]
        )
        # namespace, type, subtypes, name, signature, ext, input, kind, prov
        assert row == ["proj::net", "", False, "do_exec", "", "",
                       "Argument[*0]", "command-injection", "ai-generated"]

    def test_source_summary_barrier_predicates(self, tmp_path: Path):
        rows = [
            _row(role="source", access_input="", access_output="ReturnValue",
                 model_kind="remote", name="read_pkt"),
            _row(role="summary", access_output="ReturnValue",
                 model_kind="taint", name="wrap"),
            _row(role="barrier", access_input="",
                 access_output="ReturnValue", model_kind="sql-injection",
                 name="escape_sql"),
        ]
        result = write_extension_pack(rows, language="cpp", out_dir=tmp_path)
        assert result.counts == {
            "barrierModel": 1, "sourceModel": 1, "summaryModel": 1,
        }
        text = result.model_file.read_text()
        # summaryModel carries both accesses (10 columns)
        summary_section = text.split("extensible: summaryModel")[1]
        summary_row = json.loads(
            summary_section.splitlines()[2].strip()[2:]
        )
        assert len(summary_row) == 10
        assert summary_row[6:9] == ["Argument[*0]", "ReturnValue", "taint"]

    def test_human_provenance_maps_to_manual(self, tmp_path: Path):
        result = write_extension_pack(
            [_row(provenance="operator")], language="cpp", out_dir=tmp_path,
        )
        assert '"manual"' in result.model_file.read_text()


class TestPythonEmission:
    def test_source_sink_shapes(self, tmp_path: Path):
        rows = [
            ModelRow(role="source", provenance="iris_refined",
                     type_name="proj.net", path="Member[fetch].ReturnValue",
                     model_kind="remote"),
            ModelRow(role="sink", provenance="iris_refined",
                     type_name="proj.db", path="Member[raw_query].Argument[0]",
                     model_kind="sql-injection"),
        ]
        result = write_extension_pack(rows, language="python", out_dir=tmp_path)
        assert result.counts == {"sinkModel": 1, "sourceModel": 1}
        text = result.model_file.read_text()
        assert "pack: codeql/python-all" in text
        assert '["proj.net", "Member[fetch].ReturnValue", "remote"]' in text

    def test_summary_shape_is_five_columns(self, tmp_path: Path):
        row = ModelRow(role="summary", provenance="study",
                       type_name="proj.util", path="Member[clean]",
                       access_input="Argument[0]",
                       access_output="ReturnValue", model_kind="taint")
        result = write_extension_pack([row], language="python", out_dir=tmp_path)
        text = result.model_file.read_text()
        data_row = json.loads(
            [ln for ln in text.splitlines() if ln.strip().startswith("- [")][0]
            .strip()[2:]
        )
        assert data_row == ["proj.util", "Member[clean]", "Argument[0]",
                            "ReturnValue", "taint"]

    def test_barrier_rejected_with_directed_reason(self, tmp_path: Path):
        row = ModelRow(role="barrier", provenance="study",
                       type_name="proj", path="Member[clean]",
                       access_output="ReturnValue",
                       model_kind="sql-injection")
        result = write_extension_pack([row], language="python", out_dir=tmp_path)
        assert result.rows_written == 0
        assert "barrier_synth" in result.rejected[0].reason


# ---------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------


class TestProvenanceGate:
    @pytest.mark.parametrize("prov,fragment", [
        ("llm_prior", "not evidence-backed"),
        ("llm_summarized", "not evidence-backed"),
        ("", "missing"),
        ("made-up-tier", "unknown"),
    ])
    def test_rejected_provenance(self, tmp_path: Path, prov, fragment):
        result = write_extension_pack(
            [_row(provenance=prov)], language="cpp", out_dir=tmp_path,
        )
        assert result.rows_written == 0
        assert fragment in result.rejected[0].reason

    def test_all_accepted_provenance_pass(self, tmp_path: Path):
        rows = [_row(provenance=p) for p in sorted(ACCEPTED_PROVENANCE)]
        result = write_extension_pack(rows, language="cpp", out_dir=tmp_path)
        assert not result.rejected
        # manual + ai-generated variants of the same coordinates
        assert result.counts["sinkModel"] == 2


class TestCellValidation:
    @pytest.mark.parametrize("bad", [
        dict(name='do_exec"], ["evil'),
        dict(name="do\nexec"),
        dict(namespace='ns"quote'),
        dict(access_input="Argument[0]; DROP"),
        dict(model_kind="Command Injection"),
        dict(model_kind=""),
    ])
    def test_injection_shaped_cells_rejected(self, tmp_path: Path, bad):
        result = write_extension_pack(
            [_row(**bad)], language="cpp", out_dir=tmp_path,
        )
        assert result.rows_written == 0, bad

    def test_python_type_grammar(self, tmp_path: Path):
        row = ModelRow(role="sink", provenance="study",
                       type_name="proj.db'; import os",
                       path="Member[q].Argument[0]",
                       model_kind="sql-injection")
        result = write_extension_pack([row], language="python", out_dir=tmp_path)
        assert result.rows_written == 0

    def test_stdlib_style_cells_pass(self, tmp_path: Path):
        # Shapes lifted from vendored stdlib model files must validate.
        row = ModelRow(role="sink", provenance="framework_catalog",
                       type_name="asyncpg.~Connection",
                       path="Member[copy_from_query,execute].Argument[0,query:]",
                       model_kind="sql-injection")
        result = write_extension_pack([row], language="python", out_dir=tmp_path)
        assert result.rows_written == 1, result.rejected


class TestPackShape:
    def test_unsupported_language_raises(self, tmp_path: Path):
        # java graduated to supported (layout verified against
        # codeql/java-all 9.0.4); go remains speculative and refuses.
        with pytest.raises(ValueError, match="unsupported"):
            write_extension_pack([_row()], language="go", out_dir=tmp_path)
        assert "go" not in SUPPORTED_LANGUAGES
        assert "java" in SUPPORTED_LANGUAGES

    def test_bad_pack_name_raises(self, tmp_path: Path):
        with pytest.raises(ValueError, match="scope/name"):
            write_extension_pack(
                [_row()], language="cpp", out_dir=tmp_path,
                pack_name="no-scope",
            )

    def test_qlpack_yaml_shape(self, tmp_path: Path):
        yaml = pytest.importorskip("yaml")
        result = write_extension_pack([_row()], language="cpp", out_dir=tmp_path)
        pack = yaml.safe_load((result.pack_dir / "codeql-pack.yml").read_text())
        assert pack["name"] == "raptor/learned-models-cpp"
        assert pack["extensionTargets"] == {"codeql/cpp-all": "*"}
        assert pack["dataExtensions"] == ["models/*.model.yml"]
        model = yaml.safe_load(result.model_file.read_text())
        ext = model["extensions"][0]
        assert ext["addsTo"] == {"pack": "codeql/cpp-all",
                                 "extensible": "sinkModel"}
        assert ext["data"][0][3] == "do_exec"

    def test_deterministic_and_deduped(self, tmp_path: Path):
        rows = [
            _row(name="b_sink"), _row(name="a_sink"), _row(name="b_sink"),
            _row(role="source", access_input="", access_output="ReturnValue",
                 model_kind="remote", name="src"),
        ]
        r1 = write_extension_pack(rows, language="cpp",
                                  out_dir=tmp_path / "one")
        r2 = write_extension_pack(list(reversed(rows)), language="cpp",
                                  out_dir=tmp_path / "two")
        assert r1.model_file.read_bytes() == r2.model_file.read_bytes()
        assert r1.counts["sinkModel"] == 2  # duplicate collapsed


# ---------------------------------------------------------------------
# Converters
# ---------------------------------------------------------------------


def _spec(**kw):
    from core.iris.specs import TaintSpec
    base = dict(
        function="proj::net::recv_msg",
        file="src/net.c",
        role="source",
        taint_classes=["remote"],
        return_tainted=True,
        confidence=0.9,
        evidence_tier=EvidenceTier.XREF_BACKED,
    )
    base.update(kw)
    return TaintSpec(**base)


class TestRowsFromTaintSpecs:
    def test_cpp_roles_map(self):
        specs = [
            _spec(),
            _spec(function="proj::db::run_q", role="sink",
                  taint_classes=["sql_injection"], params_affected=[1]),
            _spec(function="proj::esc", role="sanitiser",
                  taint_classes=["sql_injection"]),
            _spec(function="proj::wrap", role="propagator",
                  params_affected=[0]),
        ]
        conv = rows_from_taint_specs(specs, language="cpp")
        roles = sorted(r.role for r in conv.rows)
        assert roles == ["barrier", "sink", "source", "summary"]
        sink = next(r for r in conv.rows if r.role == "sink")
        assert sink.namespace == "proj::db"
        assert sink.name == "run_q"
        assert sink.access_input == "Argument[*1]"
        assert sink.model_kind == "sql-injection"
        assert not conv.rejected

    def test_python_sanitiser_rejected(self):
        conv = rows_from_taint_specs(
            [_spec(function="proj.esc", role="sanitiser",
                   taint_classes=["sql_injection"])],
            language="python",
        )
        assert not conv.rows
        assert "barrier" in conv.rejected[0].reason

    def test_tier_and_confidence_gates(self):
        conv = rows_from_taint_specs(
            [
                _spec(evidence_tier=EvidenceTier.HEURISTIC),
                _spec(confidence=0.2),
            ],
            language="cpp",
        )
        assert not conv.rows
        reasons = sorted(r.reason for r in conv.rejected)
        assert "below" in reasons[0] and "below" in reasons[1]

    def test_unmapped_sink_class_rejected(self):
        conv = rows_from_taint_specs(
            [_spec(role="sink", taint_classes=["quantum_hacking"])],
            language="cpp",
        )
        assert not conv.rows
        assert "no sink kind mapping" in conv.rejected[0].reason

    def test_converted_rows_survive_emission(self, tmp_path: Path):
        conv = rows_from_taint_specs(
            [_spec(),
             _spec(function="proj.db.run_q", role="sink",
                   taint_classes=["sql_injection"], params_affected=[0])],
            language="python",
        )
        # cpp-style :: name converts oddly for python; use python spec only
        rows = [r for r in conv.rows if r.role == "sink"]
        result = write_extension_pack(rows, language="python",
                                      out_dir=tmp_path)
        assert result.rows_written == len(rows), result.rejected


class TestRowsFromCandidateValidators:
    def _candidate(self, **kw):
        from core.dataflow.sanitizer_evidence import CandidateValidator
        base = dict(
            name="escape_sql",
            qualified_name="proj::db::escape_sql",
            semantics_tag="sql_escape",
            semantics_text="escapes quotes",
            confidence=0.9,
            source_file="src/db.c",
            source_line=10,
            extraction_provenance="llm",
        )
        base.update(kw)
        return CandidateValidator(**base)

    def test_cpp_barrier_row(self, tmp_path: Path):
        conv = rows_from_candidate_validators(
            [self._candidate()], language="cpp",
        )
        assert len(conv.rows) == 1
        row = conv.rows[0]
        assert row.role == "barrier"
        assert row.model_kind == "sql-injection"
        assert row.provenance == "llm_extracted"
        result = write_extension_pack(conv.rows, language="cpp",
                                      out_dir=tmp_path)
        assert result.counts == {"barrierModel": 1}

    def test_unmapped_tag_and_python_rejected(self):
        conv = rows_from_candidate_validators(
            [self._candidate(semantics_tag="rate_limit")], language="cpp",
        )
        assert not conv.rows and "no barrier-kind mapping" in conv.rejected[0].reason
        conv = rows_from_candidate_validators(
            [self._candidate()], language="python",
        )
        assert not conv.rows and "cpp-only" in conv.rejected[0].reason

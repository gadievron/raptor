"""Pack → models-as-data row conversion, the provenance seam, and the
per-run augmentation record.

Three layers pinned here:

* conversion — every emissible pack entry becomes rows on exact
  (type, path) coordinates, every non-converted entry is a counted
  refusal, and the arithmetic over the SHIPPED packs balances (no
  silent drops);
* the provenance seam — summary/barrier rows require operator-grade
  provenance and barrier rows never pass on the dynamic-language
  lanes, regardless of provenance;
* the record — versioned shape, and hostile bytes in rejected-row
  labels are escaped before they land in the file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.dataflow.extension_pack import (
    ROLE_BARRIER,
    ROLE_SINK,
    ROLE_SOURCE,
    ROLE_SUMMARY,
    ModelRow,
    write_extension_pack,
)
from core.taint.mad_rows import (
    PACK_SINK_KINDS,
    PACK_SOURCE_KINDS,
    RECORD_FILENAME,
    RECORD_SCHEMA_VERSION,
    AugmentationCell,
    augmented_surfaces,
    enforce_mad_provenance,
    rows_from_pack_set,
    write_augmentation_record,
)
from core.taint.packs import (
    FlowEdge,
    PackSet,
    PropagatorSpec,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
    default_pack_names,
    load_packs,
)


@pytest.fixture(scope="module")
def js_packs() -> PackSet:
    return load_packs(default_pack_names("javascript"))


@pytest.fixture(scope="module")
def py_packs() -> PackSet:
    return load_packs(default_pack_names("python"))


def _pack_set(**kwargs) -> PackSet:
    base = dict(packs=(), sources=(), sinks=(), sanitizers=(),
                propagators=(), curated_sanitizers=())
    base.update(kwargs)
    return PackSet(**base)


# ---------------------------------------------------------------------
# Kind maps
# ---------------------------------------------------------------------

#: models-as-data sink kinds consumed by stock queries in BOTH
#: verified (type, path) stdlib packs (codeql/python-all 7.x,
#: codeql/javascript-all 2.10.1) — the target vocabulary of
#: PACK_SINK_KINDS. A kind outside this set is a dead row.
CONSUMED_SINK_KINDS = {
    "code-injection", "command-injection", "path-injection",
    "sql-injection", "url-redirection", "html-injection",
    "log-injection", "unsafe-deserialization",
}


def test_every_mapped_sink_kind_is_consumed_upstream():
    assert set(PACK_SINK_KINDS.values()) <= CONSUMED_SINK_KINDS


def test_the_renaming_map_entries():
    # The two class names whose MaD spelling differs from the pack's.
    assert PACK_SINK_KINDS["path-traversal"] == "path-injection"
    assert PACK_SINK_KINDS["xss"] == "html-injection"


def test_source_kinds_map_to_remote_only():
    assert set(PACK_SOURCE_KINDS.values()) == {"remote"}


# ---------------------------------------------------------------------
# javascript conversion over the shipped packs
# ---------------------------------------------------------------------


def _row_index(rows):
    return {(r.role, r.type_name, r.path): r for r in rows}


def _sink_label(s):
    # Pins the producer's rejection-label format for sinks: the class
    # is part of the key, because (kind, match) alone cannot name a
    # sink uniquely across packs.
    return f"sink:{s.kind}:{s.match or s.kind}:{s.sink_class}"


def _source_label(s):
    # Pins the source rejection-label format: the taint-class list
    # (declared order, comma-joined) is part of the key — same
    # discrimination the sink label carries, because (kind, match)
    # alone cannot name a source uniquely across packs.
    return (f"source:{s.kind}:{s.match or s.kind}"
            f":{','.join(s.taint_classes)}")


def _sanitizer_label(s):
    # Pins the sanitizer rejection-label format: sink_classes is the
    # class-bearing field same-(kind, match) twins can differ in.
    return (f"sanitizer:{s.kind}:{s.match or s.kind}"
            f":{','.join(s.sink_classes)}")


def _propagator_label(p):
    # Pins the propagator rejection-label format: provenance is the
    # field that can split the fate of same-(kind, match) twins (the
    # matrix requires operator-grade provenance for summary rows), so
    # it is the discriminator.
    return f"propagator:{p.kind}:{p.match or p.kind}:{p.provenance}"


def test_javascript_conversion_pins(js_packs):
    conv = rows_from_pack_set(js_packs, language="javascript")
    idx = _row_index(conv.rows)

    exec_row = idx[(ROLE_SINK, "child_process",
                    "Member[exec].Argument[0]")]
    assert exec_row.model_kind == "command-injection"
    assert exec_row.provenance == "framework_catalog"

    eval_row = idx[(ROLE_SINK, "global", "Member[eval].Argument[0]")]
    assert eval_row.model_kind == "code-injection"

    # vm.Script is the constructor-call coordinate (class object as
    # member of the package), not a "vm.Script" type.
    assert (ROLE_SINK, "vm", "Member[Script].Argument[0]") in idx

    # Function declares args [0..3] → one row per index.
    fn_rows = [k for k in idx
               if k[0] == ROLE_SINK and k[2].startswith("Member[Function]")]
    assert sorted(fn_rows) == [
        (ROLE_SINK, "global", f"Member[Function].Argument[{i}]")
        for i in range(4)
    ]

    query_row = idx[(ROLE_SOURCE, "express.Request", "Member[query]")]
    assert query_row.model_kind == "remote"

    join_row = idx[(ROLE_SUMMARY, "path", "Member[join]")]
    assert join_row.access_input == "Argument[0..]"
    assert join_row.access_output == "ReturnValue"
    assert join_row.model_kind == "taint"


def test_javascript_template_sinks_are_counted_kind_refusals(js_packs):
    conv = rows_from_pack_set(js_packs, language="javascript")
    template_sinks = [s for s in js_packs.sinks
                      if s.sink_class == "template-injection"]
    assert template_sinks  # the seeds ship them
    refused = [r for r in conv.rejected
               if "no models-as-data sink kind" in r.reason]
    assert {r.row for r in refused} == {
        _sink_label(s) for s in template_sinks
    }
    staged = {r.model_kind for r in conv.rows if r.role == ROLE_SINK}
    assert "template-injection" not in staged


def test_javascript_sanitizers_are_counted_barrier_refusals(js_packs):
    conv = rows_from_pack_set(js_packs, language="javascript")
    refused = [r for r in conv.rejected if r.row.startswith("sanitizer:")]
    assert len(refused) == len(js_packs.sanitizers)
    assert all("barrier" in r.reason for r in refused)
    assert not any(r.role == ROLE_BARRIER for r in conv.rows)


def _accounting(conv, pack_set):
    """rows + refusals must balance the pack set — no silent drops.

    Every entry contributes rows OR exactly one refusal: sources map
    1:1, sinks fan out per declared positional argument, propagators
    per flow edge, sanitizers are always refusals.
    """
    rejected_labels = [r.row for r in conv.rejected]
    n_source_rows = sum(1 for r in conv.rows if r.role == ROLE_SOURCE)
    n_sink_rows = sum(1 for r in conv.rows if r.role == ROLE_SINK)
    n_summary_rows = sum(1 for r in conv.rows if r.role == ROLE_SUMMARY)
    n_source_rej = sum(1 for x in rejected_labels if x.startswith("source:"))
    n_sink_rej = sum(1 for x in rejected_labels if x.startswith("sink:"))
    n_san_rej = sum(1 for x in rejected_labels if x.startswith("sanitizer:"))
    n_prop_rej = sum(
        1 for x in rejected_labels if x.startswith("propagator:"))
    assert n_source_rows + n_source_rej == len(pack_set.sources)
    assert n_san_rej == len(pack_set.sanitizers)
    converted_sinks = [
        s for s in pack_set.sinks
        if _sink_label(s) not in set(rejected_labels)
    ]
    assert n_sink_rows == sum(len(s.args) for s in converted_sinks)
    assert n_sink_rej == len(pack_set.sinks) - len(converted_sinks)
    converted_props = [
        p for p in pack_set.propagators
        if _propagator_label(p) not in set(rejected_labels)
    ]
    assert n_summary_rows == sum(len(p.flows) for p in converted_props)
    assert n_prop_rej == len(pack_set.propagators) - len(converted_props)


def test_javascript_conversion_fully_accounts_the_shipped_set(js_packs):
    conv = rows_from_pack_set(js_packs, language="javascript")
    _accounting(conv, js_packs)
    # Shape sanity over the shipped seeds specifically.
    assert sum(1 for r in conv.rows if r.role == ROLE_SOURCE) == 5
    assert sum(1 for r in conv.rows if r.role == ROLE_SUMMARY) == 8


def test_javascript_rows_pass_the_real_emitter(js_packs, tmp_path):
    conv = rows_from_pack_set(js_packs, language="javascript")
    result = write_extension_pack(
        conv.rows, language="javascript", out_dir=tmp_path,
        pack_name="raptor/taint-mad-javascript",
    )
    assert result.rejected == ()
    assert result.rows_written == len(conv.rows)
    # framework_catalog rows land as human-attested "manual".
    text = result.model_file.read_text(encoding="utf-8")
    assert "ai-generated" not in text


# ---------------------------------------------------------------------
# python conversion over the shipped packs
# ---------------------------------------------------------------------


def test_python_conversion_pins(py_packs):
    conv = rows_from_pack_set(py_packs, language="python")
    idx = _row_index(conv.rows)

    os_system = idx[(ROLE_SINK, "os", "Member[system].Argument[0]")]
    assert os_system.model_kind == "command-injection"

    flask_request = idx[(ROLE_SOURCE, "flask", "Member[request]")]
    assert flask_request.model_kind == "remote"

    get_json = idx[(ROLE_SOURCE, "flask.request",
                    "Member[get_json].ReturnValue")]
    assert get_json.model_kind == "remote"

    # Argument[*] takes the bounded python spelling (the range form
    # is unrepresentable in the python access grammar).
    join_row = idx[(ROLE_SUMMARY, "os.path", "Member[join]")]
    assert join_row.access_input == "Argument[0,1,2,3,4,5,6,7]"
    assert join_row.access_output == "ReturnValue"


def test_python_bare_names_are_counted_coordinate_refusals(py_packs):
    conv = rows_from_pack_set(py_packs, language="python")
    bare = [r for r in conv.rejected if "bare-name" in r.reason]
    assert "source:call_return:input:user-input" in {r.row for r in bare}
    staged_types = {r.type_name for r in conv.rows}
    assert "input" not in staged_types


def test_python_conversion_fully_accounts_the_shipped_set(py_packs):
    conv = rows_from_pack_set(py_packs, language="python")
    _accounting(conv, py_packs)
    # method_name sinks (cursor.execute et al.) and route_param
    # sources are matrix refusals, present and counted.
    labels = {r.row for r in conv.rejected}
    assert any(x.startswith("sink:method_name:") for x in labels)
    assert any(x.startswith("source:") and ":route_param" in x
               for x in labels)


def test_python_rows_pass_the_real_emitter(py_packs, tmp_path):
    conv = rows_from_pack_set(py_packs, language="python")
    result = write_extension_pack(
        conv.rows, language="python", out_dir=tmp_path,
        pack_name="raptor/taint-mad-python",
    )
    assert result.rejected == ()
    assert result.rows_written == len(conv.rows)


# ---------------------------------------------------------------------
# Conversion gates on synthetic entries
# ---------------------------------------------------------------------


def test_unmapped_source_class_is_a_counted_refusal():
    ps = _pack_set(sources=(SourceSpec(
        kind="module_attribute", taint_classes=("environment",),
        match="os.environ", provenance="framework_catalog",
    ),))
    conv = rows_from_pack_set(ps, language="python")
    assert conv.rows == ()
    (rej,) = conv.rejected
    assert "no models-as-data source kind" in rej.reason


def test_argless_sink_is_a_counted_refusal():
    ps = _pack_set(sinks=(SinkSpec(
        kind="dotted_callee", sink_class="command-injection",
        cwe="CWE-78", match="subprocess.run", args=(),
        kwargs=("args",), provenance="framework_catalog",
    ),))
    conv = rows_from_pack_set(ps, language="python")
    assert conv.rows == ()
    (rej,) = conv.rejected
    assert "no positional argument" in rej.reason


def test_duplicate_kind_match_sinks_stay_uniquely_attributed():
    # Two packs may declare the SAME (kind, match) callee with
    # different sink classes — e.g. subprocess.run as command-injection
    # in one pack and secret-exposure in another. Only the mapped
    # class converts; the refusal label must carry the class so it
    # names exactly one entry and the accounting join cannot exclude
    # the converted twin.
    dup_convert = SinkSpec(
        kind="dotted_callee", sink_class="command-injection",
        cwe="CWE-78", match="subprocess.run", args=(0,),
        provenance="framework_catalog")
    dup_reject = SinkSpec(
        kind="dotted_callee", sink_class="secret-exposure",
        cwe="CWE-214", match="subprocess.run", args=(0,),
        kwargs=("args",), provenance="framework_catalog")
    ps = _pack_set(sinks=(dup_convert, dup_reject))
    conv = rows_from_pack_set(ps, language="python")
    # The mapped twin converts — exactly one row, unaffected by the
    # refusal of its namesake.
    assert [(r.type_name, r.path, r.model_kind) for r in conv.rows] == [
        ("subprocess", "Member[run].Argument[0]", "command-injection")]
    # The unmapped twin is a counted refusal whose label names it
    # unambiguously (class included).
    (rej,) = conv.rejected
    assert rej.row == "sink:dotted_callee:subprocess.run:secret-exposure"
    assert "no models-as-data sink kind" in rej.reason
    # And the arithmetic still balances over the duplicate pair.
    _accounting(conv, ps)


def test_duplicate_kind_match_sources_stay_uniquely_attributed():
    # Mirror of the duplicate-sink pin for the source channel: two
    # packs may declare the SAME (kind, match) source with different
    # taint classes — the class list alone decides whether a kind
    # mapping exists, so only one twin converts. The refusal label
    # must carry the classes so it names exactly one entry and the
    # accounting join cannot exclude the converted twin.
    dup_convert = SourceSpec(
        kind="call_return", taint_classes=("user-input",),
        match="requests.get", provenance="framework_catalog")
    dup_reject = SourceSpec(
        kind="call_return", taint_classes=("environment",),
        match="requests.get", provenance="framework_catalog")
    ps = _pack_set(sources=(dup_convert, dup_reject))
    conv = rows_from_pack_set(ps, language="python")
    # The mapped twin converts — exactly one row, unaffected by the
    # refusal of its namesake.
    assert [(r.type_name, r.path, r.model_kind) for r in conv.rows] == [
        ("requests", "Member[get].ReturnValue", "remote")]
    # The unmapped twin is a counted refusal whose label names it
    # unambiguously (classes included).
    (rej,) = conv.rejected
    assert rej.row == "source:call_return:requests.get:environment"
    assert rej.row != _source_label(dup_convert)
    assert "no models-as-data source kind" in rej.reason
    # And the arithmetic still balances over the duplicate pair.
    _accounting(conv, ps)


def test_duplicate_kind_match_propagators_stay_uniquely_attributed():
    # The propagator analogue: PropagatorSpec carries no class field —
    # the field that can split the fate of same-(kind, match) twins is
    # provenance (summary rows require operator-grade provenance at
    # the matrix gate). The refusal label carries it so the learned
    # twin's refusal cannot be attributed to the operator twin the
    # accounting join must keep.
    dup_convert = PropagatorSpec(
        kind="dotted_callee", match="shlex.join",
        flows=(FlowEdge(src="Argument[0]", dst="ReturnValue"),),
        provenance="framework_catalog")
    dup_reject = PropagatorSpec(
        kind="dotted_callee", match="shlex.join",
        flows=(FlowEdge(src="Argument[0]", dst="ReturnValue"),),
        provenance="iris_refined")
    ps = _pack_set(propagators=(dup_convert, dup_reject))
    conv = rows_from_pack_set(ps, language="python")
    # The operator-grade twin converts — one summary row per flow.
    assert [(r.role, r.type_name, r.path) for r in conv.rows] == [
        (ROLE_SUMMARY, "shlex", "Member[join]")]
    # The learned twin is a counted refusal whose label names it
    # unambiguously (provenance included).
    (rej,) = conv.rejected
    assert rej.row == "propagator:dotted_callee:shlex.join:iris_refined"
    assert rej.row != _propagator_label(dup_convert)
    assert "operator-grade" in rej.reason
    # And the arithmetic still balances over the duplicate pair.
    _accounting(conv, ps)


def test_duplicate_kind_match_sanitizer_labels_stay_distinct():
    # Sanitizers are ALWAYS counted refusals on these lanes (barrier
    # channel closed), so same-(kind, match) twins cannot split fate —
    # but their labels must still name each entry distinctly, and
    # sink_classes is the class-bearing field twins can differ in.
    twin_a = SanitizerSpec(
        kind="dotted_callee", match="shlex.quote", semantics="kill",
        sink_classes=("command-injection",),
        provenance="framework_catalog")
    twin_b = SanitizerSpec(
        kind="dotted_callee", match="shlex.quote", semantics="kill",
        sink_classes=("argument-injection",),
        provenance="framework_catalog")
    ps = _pack_set(sanitizers=(twin_a, twin_b))
    conv = rows_from_pack_set(ps, language="python")
    assert conv.rows == ()
    labels = [r.row for r in conv.rejected]
    assert labels == [
        "sanitizer:dotted_callee:shlex.quote:command-injection",
        "sanitizer:dotted_callee:shlex.quote:argument-injection",
    ]
    assert len(set(labels)) == 2
    _accounting(conv, ps)


def test_learned_propagator_is_a_matrix_refusal():
    ps = _pack_set(propagators=(PropagatorSpec(
        kind="dotted_callee", match="shlex.join",
        flows=(FlowEdge(src="Argument[0]", dst="ReturnValue"),),
        provenance="iris_refined",
    ),))
    conv = rows_from_pack_set(ps, language="python")
    assert conv.rows == ()
    (rej,) = conv.rejected
    assert "operator-grade" in rej.reason


# ---------------------------------------------------------------------
# The provenance seam
# ---------------------------------------------------------------------


def _summary(provenance):
    return ModelRow(role=ROLE_SUMMARY, type_name="pkg",
                    path="Member[fn]", access_input="Argument[0]",
                    access_output="ReturnValue", model_kind="taint",
                    provenance=provenance)


def test_learned_summary_rows_are_refused():
    conv = enforce_mad_provenance(
        [_summary("iris_refined")], language="javascript")
    assert conv.rows == ()
    (rej,) = conv.rejected
    assert "operator-grade" in rej.reason


def test_seam_refusal_labels_carry_provenance():
    # Two rows may share the summary() coordinate and differ only in
    # provenance — the exact field the seam's keep/reject decision
    # turns on. The refusal label carries it, so the learned twin's
    # refusal can never be attributed to the operator twin that
    # passed (the duplicate-twin discrimination, seam edition).
    kept = _summary("framework_catalog")
    refused = _summary("iris_refined")
    conv = enforce_mad_provenance([kept, refused], language="javascript")
    assert [r.provenance for r in conv.rows] == ["framework_catalog"]
    (rej,) = conv.rejected
    assert rej.row == "summary:pkg.Member[fn]:taint:iris_refined"


def test_operator_grade_summary_rows_pass():
    for prov in ("operator", "annotation", "framework_catalog"):
        conv = enforce_mad_provenance([_summary(prov)],
                                      language="javascript")
        assert len(conv.rows) == 1, prov
        assert conv.rejected == ()


def test_barrier_rows_never_pass_regardless_of_provenance():
    for language in ("python", "javascript"):
        row = ModelRow(role=ROLE_BARRIER, type_name="pkg",
                       path="Member[esc]", model_kind="sql-injection",
                       provenance="operator")
        conv = enforce_mad_provenance([row], language=language)
        assert conv.rows == (), language
        (rej,) = conv.rejected
        assert "suppression channel" in rej.reason


def test_learned_source_and_sink_rows_pass_the_seam():
    rows = [
        ModelRow(role=ROLE_SOURCE, type_name="pkg", path="Member[x]",
                 model_kind="remote", provenance="iris_refined"),
        ModelRow(role=ROLE_SINK, type_name="pkg",
                 path="Member[f].Argument[0]",
                 model_kind="command-injection",
                 provenance="iris_refined"),
    ]
    conv = enforce_mad_provenance(rows, language="javascript")
    assert len(conv.rows) == 2
    assert conv.rejected == ()


# ---------------------------------------------------------------------
# The augmentation record
# ---------------------------------------------------------------------


def _cell(**over):
    base = dict(
        language="javascript", pack_name="raptor/taint-mad-javascript",
        pack_dir="/run/taint-mad/javascript",
        model_file="/run/taint-mad/javascript/models/javascript.model.yml",
        packs=("javascript/web-injection-core",), rows_written=3,
        counts=(("sinkModel", 2), ("sourceModel", 1)),
        augmented_sink_kinds=("command-injection",),
        augmented_sink_classes=("command-injection",),
        augmented_cwes=("CWE-78",),
        augmented_source_kinds=("remote",),
        summary_rows=0,
        row_provenance=(("framework_catalog", 3),),
    )
    base.update(over)
    return AugmentationCell(**base)


def test_augmented_surfaces_join_rows_back_onto_the_packs(js_packs):
    conv = rows_from_pack_set(js_packs, language="javascript")
    classes, cwes, source_kinds = augmented_surfaces(js_packs, conv.rows)
    assert "command-injection" in classes
    assert "path-traversal" in classes         # pack-side spelling
    assert "template-injection" not in classes  # never staged
    assert "CWE-78" in cwes and "CWE-1336" not in cwes
    assert source_kinds == ("remote",)


def test_record_shape(tmp_path):
    path = write_augmentation_record(tmp_path, [_cell()])
    assert path.name == RECORD_FILENAME
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["schema_version"] == RECORD_SCHEMA_VERSION
    assert record["flag_family"] == "--taint-crossfile"
    cell = record["languages"]["javascript"]
    assert cell["counts"] == {"sinkModel": 2, "sourceModel": 1}
    assert cell["augmented_sink_kinds"] == ["command-injection"]
    assert cell["augmented_cwes"] == ["CWE-78"]
    assert cell["iris"] == {"specs": 0, "rows": 0, "evidence_tiers": {}}
    assert cell["rejected"] == []


def test_record_escapes_hostile_bytes_in_rejected_rows(tmp_path):
    from core.dataflow.extension_pack import RejectedRow
    hostile = RejectedRow(
        row="sink:dotted_callee:evil\x1b[31m\nname",
        reason="reason with \x07 bell " + "x" * 600,
    )
    path = write_augmentation_record(
        tmp_path, [_cell(rejected=(hostile,))])
    raw = path.read_bytes()
    assert b"\x1b" not in raw and b"\x07" not in raw
    record = json.loads(raw.decode("utf-8"))
    (rej,) = record["languages"]["javascript"]["rejected"]
    assert "\\x1b" in rej["row"] and "\\x0a" in rej["row"]
    assert "...[+" in rej["reason"]  # explicit elision marker


def test_record_write_creates_parent_dirs(tmp_path):
    nested = Path(tmp_path) / "a" / "b"
    path = write_augmentation_record(nested, [_cell()])
    assert path.parent == nested and path.is_file()

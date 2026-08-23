"""Argument-shape consistency comparator (§3.6).

Fixture pairs: the ``sizeof(ptr)`` deviant must confirm
promote-capable with the declared-type witness on the receipt; the
conforming twin and the below-threshold mixed group must stay silent;
stem confusions stay detection-grade.
"""

from __future__ import annotations

import textwrap

from core.audit.consistency_dimensions import (
    detect_argument_shape_deviations,
)
from core.audit.consistency_verify import argument_shape_verdict
from core.audit.evidence_grade import is_tool_evidence
from core.testing import requires_ts


def _sizeof_fixture(deviant_arg: str, *, n: int = 4) -> dict[str, str]:
    parts = []
    for i in range(n):
        parts.append(textwrap.dedent(f"""\
            void copy_{i}(const char *src) {{
                char buf{i}[64];
                fill_buffer(buf{i}, sizeof(buf{i}), src);
            }}
        """))
    parts.append(textwrap.dedent(f"""\
        void copy_dev(const char *src, char *out) {{
            fill_buffer(out, {deviant_arg}, src);
        }}
    """))
    return {"src/copy.c": "\n".join(parts)}


class TestSizeofTypeWitness:
    @requires_ts('c')
    def test_sizeof_pointer_among_buffer_sizes_is_type_witness(self):
        devs = detect_argument_shape_deviations(
            _sizeof_fixture("sizeof(out)"),
        )
        witness = [d for d in devs if d.type_witness]
        assert len(witness) == 1
        d = witness[0]
        assert d.callee == "fill_buffer"
        assert d.position == "arg1"
        assert d.enclosing_function == "copy_dev"
        assert d.majority_shape == "sizeof_array"
        assert d.deviant_shape == "sizeof_pointer"
        assert d.cwe == "CWE-467"
        assert d.n == 5 and d.conforming == 4
        pe = d.peer_evidence
        assert pe.contract_source == "type_witness"
        assert pe.registry_grade
        assert pe.rule_id == "consistency:argument-shape"
        assert pe.provenance.startswith("type_witness:")
        assert len(pe.exhibits) == 3

    def test_conforming_twin_not_flagged(self):
        texts = _sizeof_fixture("sizeof(buf_dev)")
        texts["src/copy.c"] = texts["src/copy.c"].replace(
            "void copy_dev(const char *src, char *out) {\n"
            "    fill_buffer(out, sizeof(buf_dev), src);\n}",
            "void copy_dev(const char *src) {\n"
            "    char buf_dev[64];\n"
            "    fill_buffer(buf_dev, sizeof(buf_dev), src);\n}",
        )
        devs = detect_argument_shape_deviations(texts)
        assert not [d for d in devs if d.type_witness]

    def test_sizeof_deref_is_not_a_deviation_witness(self):
        """``sizeof(*p)`` sizes the pointed-to element — it conforms
        with the array-sizing majority's intent and must not be the
        promote-capable sub-case."""
        devs = detect_argument_shape_deviations(
            _sizeof_fixture("sizeof(*out)"),
        )
        assert not [d for d in devs if d.type_witness]

    def test_mixed_group_below_ratio_no_finding(self):
        parts = []
        for i in range(2):
            parts.append(textwrap.dedent(f"""\
                void a{i}(const char *s) {{
                    char b{i}[8];
                    fill_buffer(b{i}, sizeof(b{i}), s);
                }}
            """))
        for i in range(2):
            parts.append(textwrap.dedent(f"""\
                void p{i}(const char *s, char *o{i}) {{
                    fill_buffer(o{i}, sizeof(o{i}), s);
                }}
            """))
        devs = detect_argument_shape_deviations(
            {"src/mixed.c": "\n".join(parts)},
        )
        assert devs == []

    def test_below_min_sites_no_group(self):
        devs = detect_argument_shape_deviations(
            _sizeof_fixture("sizeof(out)", n=2),
        )
        assert devs == []


class TestStemConfusion:
    @requires_ts('c')
    def test_capacity_among_length_stays_detection_grade(self):
        parts = []
        for i in range(9):
            parts.append(textwrap.dedent(f"""\
                void w{i}(msg_t *m, size_t data_len) {{
                    write_bytes(m, data_len);
                }}
            """))
        parts.append(textwrap.dedent("""\
            void w_dev(msg_t *m, size_t data_capacity) {
                write_bytes(m, data_capacity);
            }
        """))
        devs = detect_argument_shape_deviations(
            {"src/w.c": "\n".join(parts)},
        )
        stem = [d for d in devs if d.deviant_shape == "stem_capacity"]
        assert len(stem) == 1
        d = stem[0]
        assert not d.type_witness
        assert d.cwe == "CWE-131"
        assert d.peer_evidence.rule_id == \
            "consistency:argument-shape-majority"
        assert not d.peer_evidence.registry_grade


@requires_ts('c')
class TestVerdict:
    def test_type_witness_confirms_promote_capable(self):
        devs = detect_argument_shape_deviations(
            _sizeof_fixture("sizeof(out)"),
        )
        d = [x for x in devs if x.type_witness][0]
        res = argument_shape_verdict(d)
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:argument-shape"
        assert res.contract["source"] == "type_witness"
        assert res.contract["grade"] == "registry"
        assert is_tool_evidence(res.rule_id)

    def test_majority_variant_is_detection_grade(self):
        parts = []
        for i in range(9):
            parts.append(textwrap.dedent(f"""\
                void w{i}(msg_t *m, size_t data_len) {{
                    write_bytes(m, data_len);
                }}
            """))
        parts.append(textwrap.dedent("""\
            void w_dev(msg_t *m, size_t data_capacity) {
                write_bytes(m, data_capacity);
            }
        """))
        devs = detect_argument_shape_deviations(
            {"src/w.c": "\n".join(parts)},
        )
        res = argument_shape_verdict(devs[0])
        assert res.rule_id == "consistency:argument-shape-majority"
        # Aggregation firewall: never standalone tool evidence.
        assert not is_tool_evidence(res.rule_id)


class TestPrepassWiring:
    @requires_ts('c')
    def test_type_witness_becomes_llm_free_finding(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        res = run_consistency_prepass(
            _sizeof_fixture("sizeof(out)"), out_dir=tmp_path,
        )
        shape_findings = [
            f for f in res["findings"]
            if f["dimension"] == "argument-shape"
        ]
        assert len(shape_findings) == 1
        f = shape_findings[0]
        assert f["rule_id"] == "consistency:argument-shape"
        assert f["cwe"] == "CWE-467"
        assert f["detection_grade"] is False
        assert f["status"] in ("finding", "suspicious")
        assert res["telemetry"]["contract_sources"].get(
            "type_witness") == 1
        mech = [
            m for m in res["mechanical"]
            if m["detector"] == "argument_shape_deviation"
        ]
        assert mech

    def test_cwe_dispatch_entries_route_consistency(self):
        from core.audit.consistency_verify import consistency_applicable
        from core.audit.cwe_dispatch import CWE_TO_TOOL_DISPATCH

        for cwe in ("CWE-131", "CWE-467"):
            assert cwe in CWE_TO_TOOL_DISPATCH
            assert consistency_applicable(cwe)

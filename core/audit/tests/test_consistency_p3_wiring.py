"""Phase-3 consistency dimensions (§3.3 sanitize-before-sink, §3.4
guard presence): shared-machinery wiring pins.

Mirrors the phase-2 pin file: receipt-map completeness for the
promote-capable rule-ids, the single-namespace aggregation firewall
(any two consistency ``-majority`` stamps never jointly qualify —
across phases too), rule-id construction, the ``smt_witness``
contract-source registration, and one prepass run exercising both
new dimensions with per-dimension telemetry.
"""

from __future__ import annotations

import textwrap

from core.audit.evidence_grade import _RECEIPT_MAP, is_tool_evidence
from core.audit.peer_evidence import (
    CONTRACT_SOURCES,
    REGISTRY_CONTRACT_SOURCES,
    is_detection_rule_id,
    rule_id,
)
from core.testing import requires_ts

PROMOTE_CAPABLE_RULES = (
    "consistency:sanitize-sink",
    "consistency:guard-presence",
)

P3_DIMENSIONS = ("sanitize-sink", "guard-presence")

P2_DIMENSIONS = (
    "ordering", "argument-shape", "clone-drift", "interface",
)


class TestReceiptMap:
    def test_promote_capable_rule_ids_have_receipts(self):
        for rule in PROMOTE_CAPABLE_RULES:
            assert rule in _RECEIPT_MAP, rule


class TestRuleIds:
    def test_detection_variants_constructed_and_recognised(self):
        for dim in P3_DIMENSIONS:
            detect = rule_id(dim, detection=True)
            promote = rule_id(dim, detection=False)
            assert detect == f"consistency:{dim}-majority"
            assert is_detection_rule_id(detect)
            assert not is_detection_rule_id(promote)


class TestContractSources:
    def test_smt_witness_is_registry_grade(self):
        assert "smt_witness" in REGISTRY_CONTRACT_SOURCES
        assert "smt_witness" in CONTRACT_SOURCES

    def test_statistical_source_stays_detection_grade(self):
        assert "majority" not in REGISTRY_CONTRACT_SOURCES


class TestAggregationFirewall:
    def test_two_consistency_majority_stamps_never_jointly_promote(self):
        """Self-corroboration firewall (§4.2): the phase-3 dimensions
        share the majority-statistic epistemology with every other
        consistency dimension — two agreeing is one namespace."""
        for a in P3_DIMENSIONS:
            for b in P3_DIMENSIONS + P2_DIMENSIONS + ("return-check",):
                stamp = (
                    f"consistency:{a}-majority"
                    f"+consistency:{b}-majority"
                )
                assert not is_tool_evidence(stamp), stamp

    def test_majority_plus_independent_namespace_qualifies(self):
        assert is_tool_evidence(
            "compiler:analyzer+consistency:sanitize-sink-majority",
        )
        assert is_tool_evidence(
            "coccinelle+consistency:guard-presence-majority",
        )

    def test_promote_capable_rules_are_tool_evidence_alone(self):
        for rule in PROMOTE_CAPABLE_RULES:
            assert is_tool_evidence(rule), rule


@requires_ts('c')
class TestPrepassTelemetryDimensions:
    def test_both_dimensions_report_counters(self, tmp_path):
        """One fixture exercising both phase-3 dimensions in a single
        prepass run — each must surface its telemetry key."""
        from core.annotations.models import Annotation
        from core.annotations.storage import write_annotation
        from core.audit.consistency_prepass import run_consistency_prepass
        from core.evidence import EvidenceTier
        from core.iris.specs import TaintSpec
        from core.iris.store import save_specs

        parts = []
        # sanitize-before-sink: 3 escaped writers + 1 raw.
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                int writer_{i}(const char *raw) {{
                    char *q = escape_sql(raw);
                    db_exec(q);
                    return 0;
                }}
            """))
        parts.append(textwrap.dedent("""\
            int writer_dev(const char *raw) {
                db_exec(raw);
                return 0;
            }
        """))
        # guard presence: 3 null-checked derefs + 1 unguarded.
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                int use_{i}(map_t *m) {{
                    entry_t *e = lookup_entry(m);
                    if (!e)
                        return -1;
                    return e->value;
                }}
            """))
        parts.append(textwrap.dedent("""\
            int use_dev(map_t *m) {
                entry_t *e = lookup_entry(m);
                return e->value;
            }
        """))
        texts = {"src/all.c": "\n".join(parts)}

        out = tmp_path / "out"
        out.mkdir()
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        write_annotation(ann_dir, Annotation(
            file="src/all.c",
            function="db_exec",
            body="Raw SQL executor.",
            metadata={"status": "sink", "source": "human"},
        ))
        save_specs(out, [TaintSpec(
            function="escape_sql",
            file="src/all.c",
            role="sanitiser",
            evidence_tier=EvidenceTier.XREF_BACKED,
        )])
        prepass = run_consistency_prepass(
            texts, out_dir=out, annotations_dir=ann_dir,
        )
        dims = prepass["telemetry"]["dimensions"]
        for dim in P3_DIMENSIONS:
            assert dim in dims, dim
            assert dims[dim]["confirmed"] >= 1, dim
        detectors = {m["detector"] for m in prepass["mechanical"]}
        assert "sanitize_sink_deviation" in detectors
        assert "guard_presence_deviation" in detectors

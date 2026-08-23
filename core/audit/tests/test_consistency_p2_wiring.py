"""Phase-2 consistency dimensions: shared-machinery wiring pins.

One place asserting the cross-cutting rules every new dimension must
obey: receipt-map completeness for the promote-capable rule-ids, the
single-namespace aggregation firewall (two consistency ``-majority``
stamps never jointly qualify), rule-id construction, and the
telemetry dimension keys the prepass emits.
"""

from __future__ import annotations

import textwrap

from core.audit.evidence_grade import _RECEIPT_MAP, is_tool_evidence
from core.audit.peer_evidence import is_detection_rule_id, rule_id
from core.testing import requires_ts

PROMOTE_CAPABLE_RULES = (
    "consistency:return-check",
    "consistency:flag-mode",
    "consistency:cleanup",
    "consistency:argument-shape",
    "consistency:clone-drift",
)

P2_DIMENSIONS = (
    "ordering", "argument-shape", "clone-drift", "interface",
)


class TestReceiptMap:
    def test_promote_capable_rule_ids_have_receipts(self):
        for rule in PROMOTE_CAPABLE_RULES:
            assert rule in _RECEIPT_MAP, rule

    def test_bare_namespace_covers_detection_variants(self):
        assert "consistency" in _RECEIPT_MAP


class TestRuleIds:
    def test_detection_variants_constructed_and_recognised(self):
        for dim in P2_DIMENSIONS:
            detect = rule_id(dim, detection=True)
            promote = rule_id(dim, detection=False)
            assert detect == f"consistency:{dim}-majority"
            assert is_detection_rule_id(detect)
            assert not is_detection_rule_id(promote)


class TestAggregationFirewall:
    def test_two_consistency_majority_stamps_never_jointly_promote(self):
        """Self-corroboration firewall (§4.2): all consistency
        dimensions share the majority-statistic epistemology — two of
        them agreeing is one namespace, not two."""
        for a in P2_DIMENSIONS:
            for b in P2_DIMENSIONS:
                stamp = (
                    f"consistency:{a}-majority"
                    f"+consistency:{b}-majority"
                )
                assert not is_tool_evidence(stamp), stamp

    def test_majority_plus_independent_namespace_qualifies(self):
        assert is_tool_evidence(
            "compiler:analyzer+consistency:ordering-majority",
        )
        assert is_tool_evidence(
            "coccinelle+consistency:interface-majority",
        )

    def test_promote_capable_rules_are_tool_evidence_alone(self):
        for rule in PROMOTE_CAPABLE_RULES:
            assert is_tool_evidence(rule), rule


@requires_ts('c')
class TestPrepassTelemetryDimensions:
    def test_every_dimension_reports_a_counter(self, tmp_path):
        """One fixture exercising all phase-2 dimensions in a single
        prepass run — each must surface its telemetry key."""
        import json

        from core.audit.consistency_prepass import run_consistency_prepass
        from core.audit.sibling_analysis import SiblingGroup, SiblingPath

        parts = []
        # ordering: 3× check-then-open + deviant.
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                int handler_{i}(const char *p) {{
                    if (validate_path(p) != 0)
                        return -1;
                    open_resource(p);
                    return 0;
                }}
            """))
        parts.append(textwrap.dedent("""\
            int handler_dev(const char *p) {
                open_resource(p);
                if (validate_path(p) != 0)
                    return -1;
                return 0;
            }
        """))
        # argument shape: sizeof(buf) × 4 + sizeof(ptr) deviant.
        for i in range(4):
            parts.append(textwrap.dedent(f"""\
                void copy_{i}(const char *src) {{
                    char buf{i}[64];
                    fill_buffer(buf{i}, sizeof(buf{i}), src);
                }}
            """))
        parts.append(textwrap.dedent("""\
            void copy_dev(const char *src, char *out) {
                fill_buffer(out, sizeof(out), src);
            }
        """))
        texts = {"src/all.c": "\n".join(parts)}

        # clone drift: fix anchor against a drifted twin.
        guarded = textwrap.dedent("""\
            int wire_a(pkt_t *p, size_t n) {
                if (validate_len(p, n) != 0)
                    return -1;
                for (size_t i = 0; i < n; i++) {
                    acc += p->data[i] * scale_factor(p, i);
                    emit_sample(acc, p->flags, i);
                }
                flush_output(p, acc);
                return finalize_packet(p, acc, n);
            }
        """)
        drifted = guarded.replace("wire_a", "wire_b").replace(
            "if (validate_len(p, n) != 0)\n        return -1;\n    ", "",
        )
        texts["src/wa.c"] = guarded
        texts["src/wb.c"] = drifted
        (tmp_path / "fix-history.json").write_text(json.dumps({
            "variant_sites": [{
                "file": "src/wb.c", "name": "wire_b", "sha": "c" * 40,
                "guard": "validate_len", "sensitive": "finalize_packet",
                "fixed_file": "src/wa.c", "fixed_line": 2,
                "fixed_region": guarded,
            }],
        }))

        # interface: dispatch group with one handler skipping auth.
        handlers = []
        for n in ("read", "stat", "poll"):
            handlers.append(textwrap.dedent(f"""\
                int op_{n}(req_t *r) {{
                    if (!check_permission("admin"))
                        return -1;
                    do_{n}(r);
                    return 0;
                }}
            """))
        handlers.append(
            "int op_write(req_t *r) {\n    do_write(r);\n"
            "    return 0;\n}\n"
        )
        texts["src/ops.c"] = "\n".join(handlers)
        group = SiblingGroup(
            group_id="dispatch:src/ops.c:ops",
            sibling_type="dispatch_site",
            description="ops",
            siblings=[
                SiblingPath(label=f"op_{n}", file="src/ops.c",
                            function=f"op_{n}")
                for n in ("read", "stat", "poll", "write")
            ],
        )

        res = run_consistency_prepass(
            texts, out_dir=tmp_path, peer_groups=[group],
        )
        dims = res["telemetry"]["dimensions"]
        for dim in P2_DIMENSIONS:
            assert dims.get(dim, {}).get("confirmed", 0) >= 1, dim

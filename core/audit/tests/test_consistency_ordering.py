"""Ordering (A-then-B) consistency comparator (§3.5).

One fixture pair per shape, real-world-shaped, hermetic. The
dimension is detection-grade throughout — every receipt must carry
the ``-majority`` rule-id variant, and the TOCTOU flavor is claimed
only with the mechanical shared-argument witness.
"""

from __future__ import annotations

import textwrap

from core.audit.consistency_dimensions import (
    DIMENSION_ORDERING,
    LearnedPair,
    detect_ordering_deviations,
)
from core.audit.evidence_grade import is_tool_evidence
from core.testing import requires_ts


def _check_then_open(n_majority: int, deviant_body: str) -> dict[str, str]:
    parts = []
    for i in range(n_majority):
        parts.append(textwrap.dedent(f"""\
            int handler_{i}(const char *p) {{
                if (validate_path(p) != 0)
                    return -1;
                open_resource(p);
                return 0;
            }}
        """))
    parts.append(deviant_body)
    return {"src/handlers.c": "\n".join(parts)}


_DEVIANT_SHARED_ARG = textwrap.dedent("""\
    int handler_dev(const char *p) {
        open_resource(p);
        if (validate_path(p) != 0)
            return -1;
        return 0;
    }
""")

_DEVIANT_DISTINCT_ARGS = textwrap.dedent("""\
    int handler_dev(const char *q, const char *cfg) {
        open_resource(q);
        if (validate_path(cfg) != 0)
            return -1;
        return 0;
    }
""")

_CONFORMING_TWIN = textwrap.dedent("""\
    int handler_dev(const char *p) {
        if (validate_path(p) != 0)
            return -1;
        open_resource(p);
        return 0;
    }
""")


class TestCheckBeforeUse:
    @requires_ts('c')
    def test_toctou_shape_needs_shared_argument_witness(self):
        devs = detect_ordering_deviations(
            _check_then_open(3, _DEVIANT_SHARED_ARG),
        )
        assert len(devs) == 1
        d = devs[0]
        assert d.enclosing_function == "handler_dev"
        assert d.first_op == "validate_path"
        assert d.second_op == "open_resource"
        assert d.flavor == "toctou-shape"
        assert d.cwe == "CWE-367"
        assert d.n == 4 and d.conforming == 3
        assert not d.data_dependent
        # Honesty: the shape witness does not prove a race window.
        assert "no race window proven" in d.description

    @requires_ts('c')
    def test_without_witness_no_toctou_claim(self):
        devs = detect_ordering_deviations(
            _check_then_open(3, _DEVIANT_DISTINCT_ARGS),
        )
        assert len(devs) == 1
        assert devs[0].flavor == "check-before-use"
        assert devs[0].cwe == "CWE-696"

    def test_conforming_twin_not_flagged(self):
        devs = detect_ordering_deviations(
            _check_then_open(3, _CONFORMING_TWIN),
        )
        assert devs == []

    def test_below_min_group_no_deviation(self):
        devs = detect_ordering_deviations(
            _check_then_open(1, _DEVIANT_SHARED_ARG),
        )
        assert devs == []


class TestReceipts:
    @requires_ts('c')
    def test_detection_grade_receipt_with_ordered_exhibits(self):
        devs = detect_ordering_deviations(
            _check_then_open(3, _DEVIANT_SHARED_ARG),
        )
        pe = devs[0].peer_evidence
        assert pe is not None
        assert pe.dimension == DIMENSION_ORDERING
        assert pe.formation == "same_callee_pair"
        assert pe.group_key == "validate_path->open_resource"
        assert pe.contract_source == "majority"
        assert pe.rule_id == "consistency:ordering-majority"
        assert pe.n == 4 and pe.conforming == 3
        # Ordered exhibits: each conforming sibling shows both line
        # positions; the deviant shows the inverted order.
        assert len(pe.exhibits) == 3
        assert all("precedes" in e.snippet for e in pe.exhibits)
        assert "open_resource()" in pe.deviant.snippet
        assert "precedes" in pe.deviant.snippet

    def test_majority_rule_id_never_standalone_tool_evidence(self):
        """Aggregation firewall: the detection variant is a
        statistical prior, not verification."""
        assert not is_tool_evidence("consistency:ordering-majority")
        assert is_tool_evidence(
            "compiler:analyzer+consistency:ordering-majority",
        )


@requires_ts('c')
class TestDataDependency:
    def test_forced_order_marked_data_dependent(self):
        """The deviant's earlier call binds the handle the later call
        consumes — the observed order is forced, not a bug."""
        parts = []
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                int user_{i}(conn_t *c) {{
                    if (check_conn(c) != 0)
                        return -1;
                    conn_t *h{i} = open_conn(c);
                    return 0;
                }}
            """))
        parts.append(textwrap.dedent("""\
            int user_dev(cfg_t *cfg) {
                conn_t *h = open_conn(cfg);
                if (check_conn(h) != 0)
                    return -1;
                return 0;
            }
        """))
        devs = detect_ordering_deviations({"src/conn.c": "\n".join(parts)})
        assert len(devs) == 1
        assert devs[0].data_dependent


@requires_ts('c')
class TestInitBeforeUse:
    def test_learned_acquire_flavor(self):
        parts = []
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                int sender_{i}(msg_t *m) {{
                    ctx_t *c{i} = grab_ctx(m);
                    send_data(m);
                    return 0;
                }}
            """))
        parts.append(textwrap.dedent("""\
            int sender_dev(msg_t *m) {
                send_data(m);
                ctx_t *c = grab_ctx(m);
                return 0;
            }
        """))
        devs = detect_ordering_deviations(
            {"src/send.c": "\n".join(parts)},
            pairs=[LearnedPair(
                acquire="grab_ctx", release="drop_ctx",
                kind="lock", source="domain_model",
                provenance="paired_operations:lock",
            )],
        )
        assert len(devs) == 1
        assert devs[0].flavor == "init-before-use"
        assert devs[0].cwe == "CWE-908"


@requires_ts('c')
class TestPrepassWiring:
    def test_ordering_leads_and_telemetry(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        res = run_consistency_prepass(
            _check_then_open(3, _DEVIANT_SHARED_ARG),
            out_dir=tmp_path,
        )
        dims = res["telemetry"]["dimensions"]
        assert dims.get("ordering", {}).get("confirmed", 0) >= 1
        ordering_leads = [
            ld for ld in res["leads"] if ld["dimension"] == "ordering"
        ]
        assert ordering_leads
        assert ordering_leads[0]["rule_id"] == \
            "consistency:ordering-majority"
        mech = [
            m for m in res["mechanical"]
            if m["detector"] == "ordering_deviation"
        ]
        assert mech and mech[0]["cwe"] == "CWE-367"

    def test_data_dependent_counted_inconclusive_no_lead(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        parts = []
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                int user_{i}(conn_t *c) {{
                    if (check_conn(c) != 0)
                        return -1;
                    conn_t *h{i} = open_conn(c);
                    return 0;
                }}
            """))
        parts.append(textwrap.dedent("""\
            int user_dev(cfg_t *cfg) {
                conn_t *h = open_conn(cfg);
                if (check_conn(h) != 0)
                    return -1;
                return 0;
            }
        """))
        res = run_consistency_prepass(
            {"src/conn.c": "\n".join(parts)}, out_dir=tmp_path,
        )
        reasons = res["telemetry"]["inconclusive_reasons"]
        assert reasons.get("order-data-dependent") == 1
        assert not [
            ld for ld in res["leads"] if ld["dimension"] == "ordering"
        ]

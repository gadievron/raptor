"""Interface-implementor parity comparator (§3.8).

Peer groups come from the layered resolver's mechanical layers (L2
dispatch-site, L4 type-cohort); the comparator votes structural
safety properties through ``find_asymmetries``. Escalation-only:
every receipt is the ``-majority`` detection variant.
"""

from __future__ import annotations

import textwrap

from core.audit.consistency_dimensions import (
    detect_interface_deviations,
)
from core.audit.evidence_grade import is_tool_evidence
from core.audit.sibling_analysis import SiblingGroup, SiblingPath
from core.testing import requires_ts

_CHECKED_HANDLER = textwrap.dedent("""\
    int op_{name}(req_t *r) {{
        if (!check_permission("admin"))
            return -1;
        if (r == NULL)
            return -1;
        do_{name}(r);
        return 0;
    }}
""")

_UNCHECKED_HANDLER = textwrap.dedent("""\
    int op_write(req_t *r) {
        do_write(r);
        return 0;
    }
""")


def _dispatch_group(names: list[str]) -> SiblingGroup:
    return SiblingGroup(
        group_id="dispatch:src/ops.c:ops",
        sibling_type="dispatch_site",
        description="Dispatch handlers in ops",
        siblings=[
            SiblingPath(label=n, file="src/ops.c", function=n)
            for n in names
        ],
    )


def _fixture(deviant: bool) -> dict[str, str]:
    parts = [
        _CHECKED_HANDLER.format(name=n)
        for n in ("read", "stat", "poll")
    ]
    if deviant:
        parts.append(_UNCHECKED_HANDLER)
    else:
        parts.append(_CHECKED_HANDLER.format(name="write"))
    return {"src/ops.c": "\n".join(parts)}


_MEMBERS = ["op_read", "op_stat", "op_poll", "op_write"]


class TestDispatchGroupParity:
    @requires_ts('c')
    def test_handler_skipping_auth_check_flagged(self):
        devs = detect_interface_deviations(
            _fixture(deviant=True), [_dispatch_group(_MEMBERS)],
        )
        auth = [d for d in devs if d.property_name == "auth_check"]
        assert len(auth) == 1
        d = auth[0]
        assert d.enclosing_function == "op_write"
        assert d.n == 4 and d.conforming == 3
        assert d.cwe == "CWE-862"
        pe = d.peer_evidence
        assert pe.dimension == "interface"
        assert pe.formation == "interface"
        assert pe.group_key == "dispatch:src/ops.c:ops"
        assert pe.contract_source == "majority"
        assert pe.rule_id == "consistency:interface-majority"
        assert pe.exhibits and all(
            "performs auth_check" in e.snippet for e in pe.exhibits
        )
        # The null-guard omission is also a minority-lacks vote.
        null = [d for d in devs if d.property_name == "null_guard"]
        assert null and null[0].cwe == "CWE-20"

    def test_conforming_twin_not_flagged(self):
        devs = detect_interface_deviations(
            _fixture(deviant=False), [_dispatch_group(_MEMBERS)],
        )
        assert devs == []

    def test_below_min_group_no_vote(self):
        texts = {
            "src/ops.c": "\n".join([
                _CHECKED_HANDLER.format(name="read"),
                _UNCHECKED_HANDLER,
            ]),
        }
        devs = detect_interface_deviations(
            texts, [_dispatch_group(["op_read", "op_write"])],
        )
        assert devs == []

    def test_non_mechanical_layers_skipped(self):
        """Verb-prefix (L5) and paired-op (L6) groups are naming
        heuristics — the interface dimension only trusts the
        mechanical membership layers."""
        group = _dispatch_group(_MEMBERS)
        group.sibling_type = "peer_functions"
        assert detect_interface_deviations(
            _fixture(deviant=True), [group],
        ) == []

    @requires_ts('c')
    def test_type_cohort_layer_accepted(self):
        group = _dispatch_group(_MEMBERS)
        group.sibling_type = "type_cohort"
        devs = detect_interface_deviations(
            _fixture(deviant=True), [group],
        )
        assert devs
        assert devs[0].peer_evidence.provenance.startswith(
            "interface:type_cohort:",
        )

    def test_detection_variant_never_standalone_evidence(self):
        assert not is_tool_evidence("consistency:interface-majority")


class TestPrepassWiring:
    @requires_ts('c')
    def test_interface_leads_and_telemetry(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        res = run_consistency_prepass(
            _fixture(deviant=True),
            out_dir=tmp_path,
            peer_groups=[_dispatch_group(_MEMBERS)],
        )
        dims = res["telemetry"]["dimensions"]
        assert dims.get("interface", {}).get("confirmed", 0) >= 1
        iface_leads = [
            ld for ld in res["leads"] if ld["dimension"] == "interface"
        ]
        assert iface_leads
        assert iface_leads[0]["rule_id"] == \
            "consistency:interface-majority"
        assert not [
            f for f in res["findings"] if f["dimension"] == "interface"
        ], "interface parity is escalation-only — never an LLM-free finding"

    def test_no_peer_groups_no_dimension(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        res = run_consistency_prepass(
            _fixture(deviant=True), out_dir=tmp_path,
        )
        assert "interface" not in res["telemetry"]["dimensions"]

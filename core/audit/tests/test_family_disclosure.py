"""Conforming-member identity disclosure on peer receipts.

``PeerEvidence.family`` names WHO the conforming peers are (file /
function / line), capped at ``MAX_FAMILY_DISCLOSED`` and serialized
additively; the census detectors that hold member identities stamp
it, and the prepass threads it onto lead dicts as
``family_functions``. Both cap directions are pinned (a small family
is never truncated; an oversized one always is) alongside the
absent-direction (dimensions that do not disclose members emit no
key).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from core.audit.consistency_prepass import (
    _attach_family,
    _lead_from_result,
)
from core.audit.guard_predicate import _evidence, _PredicateSite
from core.audit.peer_evidence import (
    MAX_FAMILY_DISCLOSED,
    FamilyMember,
    PeerEvidence,
)
from core.testing import requires_ts


def _members(n: int) -> list[FamilyMember]:
    return [
        FamilyMember("src/a.c", f"fn_{i}", 10 + i) for i in range(n)
    ]


class TestReceiptFamilyField:
    def test_small_family_never_truncated(self):
        pe = PeerEvidence(
            dimension="guard-predicate", formation="loop_guard",
            group_key="buf[i]", family=_members(8),
        )
        assert len(pe.family) == 8

    def test_oversized_family_always_capped(self):
        pe = PeerEvidence(
            dimension="guard-predicate", formation="loop_guard",
            group_key="buf[i]",
            family=_members(MAX_FAMILY_DISCLOSED + 5),
        )
        assert len(pe.family) == MAX_FAMILY_DISCLOSED

    def test_serialization_is_additive(self):
        bare = PeerEvidence(
            dimension="flag-mode", formation="same_callee",
            group_key="open",
        )
        assert "family" not in bare.to_dict()
        with_family = PeerEvidence(
            dimension="interface", formation="interface",
            group_key="g", family=_members(2),
        )
        d = with_family.to_dict()
        assert d["family"] == [
            {"file": "src/a.c", "function": "fn_0", "line": 10},
            {"file": "src/a.c", "function": "fn_1", "line": 11},
        ]
        json.dumps(d)


def _site(fn: str, line: int = 10) -> _PredicateSite:
    return _PredicateSite(
        file="src/a.c", line=line, enclosing_function=fn, leg="loop",
        base="buf", index="i", field_name="", tested_var="i",
        relop="<", bound_expr="n", bound_is_call=False,
        macro_tokens=frozenset(), has_null_arm=False,
        snippet="for (i = 0; i < n; i++)",
    )


class TestGuardPredicateDiscloses:
    def test_family_names_conforming_functions(self):
        conforming = [_site(f"walk_{i}", 20 + i) for i in range(4)]
        pe = _evidence(
            ("loop", "buf", "i"), _site("walk_dev", 90),
            conforming, 5, 0,
        )
        assert [m.function for m in pe.family] == [
            "walk_0", "walk_1", "walk_2", "walk_3",
        ]
        assert all(m.file == "src/a.c" for m in pe.family)

    def test_oversized_group_discloses_capped(self):
        conforming = [
            _site(f"walk_{i}", 20 + i)
            for i in range(MAX_FAMILY_DISCLOSED + 4)
        ]
        pe = _evidence(
            ("loop", "buf", "i"), _site("walk_dev", 90),
            conforming, len(conforming) + 1, 0,
        )
        assert len(pe.family) == MAX_FAMILY_DISCLOSED


@requires_ts("c")
class TestBoundaryUnitDiscloses:
    def test_bound_census_family(self):
        from core.audit.boundary_unit import (
            detect_boundary_unit_deviations,
        )

        def loop_fn(name: str, bound: str) -> str:
            return (
                f"int {name}(int *a, int n)\n"
                "{\n"
                "    int i, t = 0;\n"
                f"    for (i = 0; i < {bound}; i++)\n"
                "        t += a[i];\n"
                "    return t;\n"
                "}\n"
            )

        src = "".join(
            loop_fn(f"sum_{c}", "n") for c in "abc"
        ) + loop_fn("sum_d", "n + 1")
        devs, _stats = detect_boundary_unit_deviations(
            {"peers.c": src}, seed=b"pin",
        )
        assert len(devs) == 1
        family = devs[0].peer_evidence.family
        assert sorted(m.function for m in family) == [
            "sum_a", "sum_b", "sum_c",
        ]


@requires_ts("c")
class TestInterfaceDiscloses:
    def test_parity_family_names_majority(self):
        import textwrap

        from core.audit.consistency_dimensions import (
            detect_interface_deviations,
        )
        from core.audit.sibling_analysis import (
            SiblingGroup,
            SiblingPath,
        )

        checked = textwrap.dedent("""\
            int op_{name}(req_t *r) {{
                if (!check_permission("admin"))
                    return -1;
                do_{name}(r);
                return 0;
            }}
        """)
        unchecked = textwrap.dedent("""\
            int op_write(req_t *r) {
                do_write(r);
                return 0;
            }
        """)
        texts = {"src/ops.c": "\n".join(
            [checked.format(name=n) for n in ("read", "stat", "poll")]
            + [unchecked],
        )}
        group = SiblingGroup(
            group_id="dispatch:src/ops.c:ops",
            sibling_type="dispatch_site",
            description="Dispatch handlers in ops",
            siblings=[
                SiblingPath(label=n, file="src/ops.c", function=n)
                for n in ("op_read", "op_stat", "op_poll", "op_write")
            ],
        )
        devs = detect_interface_deviations(texts, [group])
        auth = [d for d in devs if d.property_name == "auth_check"]
        assert len(auth) == 1
        family = auth[0].peer_evidence.family
        assert sorted(m.function for m in family) == [
            "op_poll", "op_read", "op_stat",
        ]
        assert all(m.file == "src/ops.c" for m in family)


class TestLeadThreading:
    def _pe(self, family: list[FamilyMember]) -> PeerEvidence:
        return PeerEvidence(
            dimension="guard-predicate", formation="loop_guard",
            group_key="buf[i]", n=5, conforming=4, ratio=0.8,
            family=family, contract_source="majority",
        )

    def _res(self, pe: PeerEvidence | None) -> SimpleNamespace:
        return SimpleNamespace(
            dimension="guard-predicate", callee="buf[i]",
            rule_id="consistency:guard-predicate-majority",
            reason="4/5 sites guard buf[i]", peer_evidence=pe,
        )

    def test_lead_carries_family_functions(self):
        lead = _lead_from_result(
            self._res(self._pe(_members(3))),
            file="src/a.c", function="walk_dev", line=90,
            security_relevant=True,
        )
        assert lead["family_functions"] == [
            {"file": "src/a.c", "function": "fn_0", "line": 10},
            {"file": "src/a.c", "function": "fn_1", "line": 11},
            {"file": "src/a.c", "function": "fn_2", "line": 12},
        ]

    def test_no_disclosure_no_key(self):
        lead = _lead_from_result(
            self._res(self._pe([])),
            file="src/a.c", function="walk_dev", line=90,
            security_relevant=True,
        )
        assert "family_functions" not in lead

    def test_attach_family_tolerates_receiptless(self):
        lead = _attach_family({"dimension": "interface"}, None)
        assert "family_functions" not in lead

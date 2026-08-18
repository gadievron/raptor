"""Bounds/null-guard presence consistency dimension (§3.4).

Fixture pairs per the design's test plan: the deviant handed to a
stubbed SMT returning feasible → upgraded (witnessed) finding;
infeasible → refuted with the enumerated reason; no witness →
detection-grade. Plus the §3.4 task split this dimension owes:
guard-elsewhere (caller-guarded, depth-3 walk, receipt names the
searched set) vs genuinely-unguarded.
"""

from __future__ import annotations

import textwrap
from types import SimpleNamespace

from core.audit.consistency_dimensions import (
    DIMENSION_GUARD_PRESENCE,
    GUARD_KIND_BOUNDS,
    GUARD_KIND_NULL,
    detect_guard_presence_deviations,
)
from core.audit.consistency_verify import (
    RULE_GUARD_PRESENCE,
    guard_presence_verdict,
)
from core.testing import requires_ts


def _null_fixture(*, deviant: bool, conforming: int = 3) -> dict[str, str]:
    parts = []
    for i in range(conforming):
        parts.append(textwrap.dedent(f"""\
            int use_{i}(map_t *m) {{
                entry_t *e = lookup_entry(m);
                if (!e)
                    return -1;
                return e->value;
            }}
        """))
    if deviant:
        parts.append(textwrap.dedent("""\
            int use_dev(map_t *m) {
                entry_t *e = lookup_entry(m);
                return e->value;
            }
        """))
    return {"src/map.c": "\n".join(parts)}


def _bounds_fixture(*, deviant: bool, conforming: int = 3) -> dict[str, str]:
    parts = []
    for i in range(conforming):
        parts.append(textwrap.dedent(f"""\
            int sum_{i}(pkt_t *p, int i) {{
                if (i < p->count)
                    return p->data[i];
                return 0;
            }}
        """))
    if deviant:
        parts.append(textwrap.dedent("""\
            int sum_dev(pkt_t *p, int i) {
                return p->data[i];
            }
        """))
    return {"src/pkt.c": "\n".join(parts)}


class TestNullLeg:
    @requires_ts('c')
    def test_unguarded_deref_among_checked_siblings(self):
        devs = detect_guard_presence_deviations(
            _null_fixture(deviant=True),
        )
        assert len(devs) == 1
        d = devs[0]
        assert d.kind == GUARD_KIND_NULL
        assert d.group_key == "lookup_entry"
        assert d.guard_target == "e"
        assert d.enclosing_function == "use_dev"
        assert (d.n, d.conforming) == (4, 3)
        assert d.cwe == "CWE-476"
        assert d.param_derived is False  # local capture
        pe = d.peer_evidence
        assert pe.dimension == DIMENSION_GUARD_PRESENCE
        assert pe.formation == "same_callee"
        assert pe.rule_id == "consistency:guard-presence-majority"
        assert len(pe.exhibits) == 3
        assert all("guards 'e'" in e.snippet for e in pe.exhibits)

    def test_conforming_twin_not_flagged(self):
        assert detect_guard_presence_deviations(
            _null_fixture(deviant=False),
        ) == []

    def test_group_too_small_not_flagged(self):
        assert detect_guard_presence_deviations(
            _null_fixture(deviant=True, conforming=1),
        ) == []


class TestBoundsLeg:
    @requires_ts('c')
    def test_unbounded_subscript_among_checked_siblings(self):
        devs = detect_guard_presence_deviations(
            _bounds_fixture(deviant=True),
        )
        assert len(devs) == 1
        d = devs[0]
        assert d.kind == GUARD_KIND_BOUNDS
        assert d.group_key == "data"
        assert d.guard_target == "i"
        assert d.cwe == "CWE-125"
        assert d.param_derived is True  # index and base are parameters
        assert d.peer_evidence.formation == "same_field"

    def test_loop_header_bound_conforms(self):
        texts = _bounds_fixture(deviant=True)
        texts["src/pkt.c"] = texts["src/pkt.c"].replace(
            "int sum_dev(pkt_t *p, int i) {\n    return p->data[i];",
            "int sum_dev(pkt_t *p, int i) {\n"
            "    int acc = 0;\n"
            "    for (i = 0; i < p->count; i++)\n"
            "        acc += p->data[i];\n"
            "    return acc;",
        )
        assert detect_guard_presence_deviations(texts) == []


@requires_ts('c')
class TestSmtEscalation:
    def _deviant(self, conforming: int = 9):
        return detect_guard_presence_deviations(
            _null_fixture(deviant=True, conforming=conforming),
        )[0]

    def test_stubbed_feasible_upgrades_to_witnessed_finding(self):
        dev = self._deviant()
        res = guard_presence_verdict(
            dev,
            smt_check=lambda d: SimpleNamespace(
                feasible=True, reasoning="sat", witness={"e": 0},
            ),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_GUARD_PRESENCE
        assert res.contract is not None
        assert res.contract["source"] == "smt_witness"
        assert res.contract["grade"] == "registry"
        assert res.peer_evidence.contract_source == "smt_witness"
        assert res.peer_evidence.registry_grade

    def test_stubbed_infeasible_refutes_with_enumerated_reason(self):
        dev = self._deviant()
        res = guard_presence_verdict(
            dev,
            smt_check=lambda d: SimpleNamespace(
                feasible=False, reasoning="unsat", witness=None,
            ),
        )
        assert res.outcome == "refuted"
        assert res.reason.startswith("deviant-path-infeasible:")

    def test_no_witness_stays_detection_grade(self):
        dev = self._deviant()
        res = guard_presence_verdict(dev, smt_check=lambda d: None)
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:guard-presence-majority"
        assert res.contract is None
        assert res.peer_evidence.contract_source == "majority"

    def test_feasible_below_promote_floor_stays_detection_grade(self):
        # 3/4 = 0.75 < the 0.9 promote-adjacent floor: the solver
        # witness alone must not promote a weak majority.
        dev = self._deviant(conforming=3)
        res = guard_presence_verdict(
            dev,
            smt_check=lambda d: SimpleNamespace(
                feasible=True, reasoning="sat", witness=None,
            ),
        )
        assert res.rule_id == "consistency:guard-presence-majority"


def _caller_inventory(caller_src: str, fixture: dict[str, str]):
    import re

    from core.inventory.call_graph import extract_call_graph_c

    texts = dict(fixture)
    texts["src/pkt.c"] = texts["src/pkt.c"] + "\n" + caller_src
    items = [
        {"kind": "function", "name": m.group(1), "line_start": i + 1}
        for i, line in enumerate(texts["src/pkt.c"].splitlines())
        for m in [re.match(r"int (\w+)\(", line)]
        if m
    ]
    inventory = {
        "files": [{
            "path": "src/pkt.c",
            "language": "c",
            "items": items,
            "call_graph": extract_call_graph_c(
                texts["src/pkt.c"],
            ).to_dict(),
        }],
    }
    return texts, inventory


_GUARDED_CALLER = textwrap.dedent("""\
    int outer_guarded(pkt_t *p, int idx, int max_n) {
        if (idx < max_n)
            return sum_dev(p, idx);
        return 0;
    }
""")

_RAW_CALLER = textwrap.dedent("""\
    int outer_raw(pkt_t *p, int idx) {
        return sum_dev(p, idx);
    }
""")


@requires_ts('c')
class TestGuardElsewhereWalk:
    def _run(self, caller_src: str):
        texts, inventory = _caller_inventory(
            caller_src, _bounds_fixture(deviant=True),
        )
        devs = [
            d for d in detect_guard_presence_deviations(texts)
            if d.enclosing_function == "sum_dev"
        ]
        assert devs and devs[0].param_derived
        return guard_presence_verdict(
            devs[0],
            inventory=inventory,
            source_texts=texts,
            smt_check=lambda d: None,
        )

    def test_caller_guarded_is_guard_elsewhere_inconclusive(self):
        res = self._run(_GUARDED_CALLER)
        assert res.outcome == "inconclusive"
        assert res.reason.startswith("guard-elsewhere:")
        assert "outer_guarded" in res.reason
        # The receipt names the searched set (the honesty rule).
        assert "searched 1 caller(s) within 3 hops" in res.reason
        walk = res.corroboration[0]["caller_guard_walk"]
        assert walk["status"] == "searched"
        assert walk["searched"] == ["outer_guarded"]
        assert walk["guarding"][0]["caller"] == "outer_guarded"

    def test_genuinely_unguarded_confirms_and_names_the_search(self):
        res = self._run(_RAW_CALLER)
        assert res.outcome == "confirmed"
        assert "genuinely-unguarded within the searched caller set" \
            in res.reason
        assert "outer_raw" in res.reason
        walk = res.corroboration[0]["caller_guard_walk"]
        assert walk["guarding"] == []
        assert walk["searched"] == ["outer_raw"]

    def test_no_inventory_walk_unavailable_stays_detection(self):
        devs = detect_guard_presence_deviations(
            _bounds_fixture(deviant=True),
        )
        res = guard_presence_verdict(devs[0], smt_check=lambda d: None)
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:guard-presence-majority"


@requires_ts('c')
class TestPrepassIntegration:
    def test_detection_grade_lead_and_telemetry(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        out = tmp_path / "out"
        out.mkdir()
        prepass = run_consistency_prepass(
            _bounds_fixture(deviant=True), out_dir=out,
        )
        dims = prepass["telemetry"]["dimensions"]
        assert dims[DIMENSION_GUARD_PRESENCE]["confirmed"] == 1
        mech = [
            m for m in prepass["mechanical"]
            if m["detector"] == "guard_presence_deviation"
        ]
        assert mech and mech[0]["cwe"] == "CWE-125"
        assert mech[0]["rule_id"] == "consistency:guard-presence-majority"
        # Detection-grade never lands in the LLM-free findings.
        assert not [
            f for f in prepass["findings"]
            if f["dimension"] == DIMENSION_GUARD_PRESENCE
        ]
        leads = [
            ld for ld in prepass["leads"]
            if ld["dimension"] == DIMENSION_GUARD_PRESENCE
        ]
        assert leads and leads[0]["contract_source"] == "majority"

    def test_guard_elsewhere_surfaces_in_reason_histogram(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        out = tmp_path / "out"
        out.mkdir()
        texts, inventory = _caller_inventory(
            _GUARDED_CALLER, _bounds_fixture(deviant=True),
        )
        prepass = run_consistency_prepass(
            texts, out_dir=out, inventory=inventory,
        )
        assert prepass["telemetry"]["inconclusive_reasons"].get(
            "guard-elsewhere") == 1

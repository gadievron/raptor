"""Differential family execution — gate, classifier, rails.

The load-bearing invariants pinned here:

- the eligibility gate is dimension/family-keyed and refuses
  non-uniform or non-args-shaped families with a reason;
- an observation exists ONLY for an authenticated protocol status —
  everything else is a member error and poisons its vector;
- the single confirming pattern is deviant-accepts /
  every-executed-peer-rejects under an acceptance contract; value
  contracts never confirm; agreement is never more than a failure
  to promote;
- the conforming quorum and the census family floor gate the
  verdicts, and every compute rail refuses in both directions.
"""

from __future__ import annotations

from core.audit.dark_verify import DarkVerifyResult
from core.audit.differential import (
    ARGS_SHAPED_LANGS,
    CONTRACT_ACCEPT_REJECT,
    CONTRACT_EXCEPTION_PARITY,
    CONTRACT_RETURN_EQUIVALENCE,
    DIMENSION_FLOOR_KEY,
    MAX_CONFORMING_EXECUTED,
    MAX_DIFFERENTIAL_EXECUTIONS,
    MAX_DIFFERENTIAL_WALL_S,
    MAX_VECTORS_PER_LEAD,
    MIN_CONFORMING_EXECUTED,
    OBS_ACCEPT,
    OBS_ERROR,
    OBS_REJECT,
    VERDICT_CONFIRMED,
    VERDICT_FAMILY_AGREES,
    VERDICT_INCONCLUSIVE,
    VERDICT_NONDIRECTIONAL,
    DifferentialBudget,
    MemberObservation,
    VectorVerdict,
    classify_lead,
    classify_vector,
    differential_applicable,
    observation_from_result,
    usable_family,
)

# -- eligibility gate ---------------------------------------------------------


def _family(n: int, ext: str = "py") -> list[dict[str, object]]:
    return [
        {"file": f"pkg/peer_{i}.{ext}", "function": f"peer_{i}",
         "line": 10 + i}
        for i in range(n)
    ]


def _lead(**over) -> dict[str, object]:
    lead: dict[str, object] = {
        "dimension": "guard-predicate",
        "file": "pkg/dev.py",
        "function": "deviant",
        "line": 42,
        "family_functions": _family(4),
    }
    lead.update(over)
    return lead


class TestGate:
    def test_eligible_lead_passes(self):
        ok, reason = differential_applicable(_lead())
        assert ok and reason == ""

    def test_all_keyed_dimensions_eligible(self):
        for dim in DIMENSION_FLOOR_KEY:
            ok, _ = differential_applicable(_lead(dimension=dim))
            assert ok

    def test_unkeyed_dimension_refused(self):
        ok, reason = differential_applicable(_lead(dimension="ordering"))
        assert not ok and "ordering" in reason

    def test_missing_family_refused(self):
        lead = _lead()
        del lead["family_functions"]
        ok, reason = differential_applicable(lead)
        assert not ok and "family" in reason

    def test_too_few_members_refused(self):
        ok, reason = differential_applicable(
            _lead(family_functions=_family(MIN_CONFORMING_EXECUTED - 1)),
        )
        assert not ok and "member" in reason

    def test_deviant_never_its_own_peer(self):
        # Three peers plus the deviant listed in its own family: the
        # deviant must not pad the quorum.
        family = _family(MIN_CONFORMING_EXECUTED - 1) + [
            {"file": "pkg/dev.py", "function": "deviant", "line": 42},
        ]
        ok, _ = differential_applicable(_lead(family_functions=family))
        assert not ok
        members = usable_family(_lead(family_functions=family))
        assert all(m["function"] != "deviant" for m in members)

    def test_native_language_refused(self):
        ok, reason = differential_applicable(_lead(
            file="src/dev.c", family_functions=_family(4, ext="c"),
        ))
        assert not ok and "argument vector" in reason

    def test_mixed_family_language_refused(self):
        family = _family(3) + [
            {"file": "pkg/peer_x.rb", "function": "peer_x", "line": 9},
        ]
        ok, reason = differential_applicable(
            _lead(family_functions=family),
        )
        assert not ok and "uniform" in reason

    def test_args_shaped_set_excludes_native(self):
        assert "python" in ARGS_SHAPED_LANGS
        for lang in ("c", "cpp", "go", "rust", "java"):
            assert lang not in ARGS_SHAPED_LANGS

    def test_args_shaped_set_excludes_unclassified_boundaries(self):
        # Ruby/PHP/Perl call boundaries refuse a mis-shaped vector
        # with an error their harnesses report as a plain exception —
        # indistinguishable from the member's own guard rejecting the
        # input, so signature heterogeneity would read as semantic
        # reject-divergence. JS/TS/Lua undefined/nil-fill missing
        # arguments (the member body genuinely runs), and python's
        # harness classifies binding refusals distinctly.
        for lang in ("ruby", "php", "perl"):
            assert lang not in ARGS_SHAPED_LANGS
        for lang in ("javascript", "typescript", "lua"):
            assert lang in ARGS_SHAPED_LANGS

    def test_unclassified_boundary_lead_refused(self):
        for ext in ("rb", "php", "pl"):
            ok, reason = differential_applicable(_lead(
                file=f"pkg/dev.{ext}",
                family_functions=_family(4, ext=ext),
            ))
            assert not ok and "argument vector" in reason

    def test_arg_filling_boundary_lead_eligible(self):
        for ext in ("js", "lua"):
            ok, reason = differential_applicable(_lead(
                file=f"pkg/dev.{ext}",
                family_functions=_family(4, ext=ext),
            ))
            assert ok and reason == ""


# -- observation extraction ---------------------------------------------------


def _result(status: str, **kw) -> DarkVerifyResult:
    base = dict(finding_key="k", verdict="inconclusive",
                observed_status=status)
    base.update(kw)
    return DarkVerifyResult(**base)


class TestObservation:
    def test_returned_is_accept(self):
        obs = observation_from_result(
            _result("returned", actual_return="7"),
            member="peer_0", file="pkg/peer_0.py",
        )
        assert (obs.kind, obs.value) == (OBS_ACCEPT, "7")

    def test_exception_is_reject(self):
        obs = observation_from_result(
            _result("exception", actual_exception="ValueError: bad"),
            member="peer_0", file="pkg/peer_0.py",
        )
        assert (obs.kind, obs.value) == (OBS_REJECT, "ValueError: bad")

    def test_everything_else_is_error(self):
        for status in ("", "import_error", "binding_error",
                       "arg_binding_error", "segv"):
            obs = observation_from_result(
                _result(status), member="p", file="p.py",
            )
            assert obs.kind == OBS_ERROR

    def test_arg_binding_refusal_is_never_a_reject(self):
        # The sharpest direction: a member whose signature cannot
        # bind the shared vector raised at the call boundary — its
        # body never ran. Counting that as OBS_REJECT would mint
        # semantic divergence out of pure signature heterogeneity.
        obs = observation_from_result(
            _result("arg_binding_error",
                    match_detail="arguments do not bind"),
            member="peer_0", file="pkg/peer_0.py",
        )
        assert obs.kind == OBS_ERROR
        assert obs.kind != OBS_REJECT
        assert "bind" in obs.detail


# -- vector classification ----------------------------------------------------


def _obs(kind: str, member: str = "peer", value: str = "") -> MemberObservation:
    return MemberObservation(
        member=member, file=f"pkg/{member}.py", kind=kind, value=value,
    )


def _conf(*kinds: str, values: tuple[str, ...] = ()) -> list[MemberObservation]:
    return [
        _obs(k, member=f"peer_{i}",
             value=values[i] if i < len(values) else "")
        for i, k in enumerate(kinds)
    ]


class TestVectorClassification:
    def test_deviant_error_poisons(self):
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, _obs(OBS_ERROR, "dev"),
            _conf(OBS_REJECT, OBS_REJECT, OBS_REJECT), vector_index=0,
        )
        assert v.verdict == VERDICT_INCONCLUSIVE

    def test_missing_deviant_poisons(self):
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, None,
            _conf(OBS_REJECT, OBS_REJECT, OBS_REJECT), vector_index=0,
        )
        assert v.verdict == VERDICT_INCONCLUSIVE

    def test_conforming_error_poisons_and_names_member(self):
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, _obs(OBS_ACCEPT, "dev"),
            _conf(OBS_REJECT, OBS_ERROR, OBS_REJECT), vector_index=0,
        )
        assert v.verdict == VERDICT_INCONCLUSIVE
        assert "peer_1" in v.reason

    def test_binding_poisoned_peer_never_confirms(self):
        # End-to-end through observation extraction: the deviant
        # accepts and two peers reject, but the third peer's
        # signature never bound the vector. The confirming pattern
        # (deviant accepts, EVERY peer rejects) must not be assembled
        # over a family whose "rejections" include a boundary refusal
        # — the vector is poisoned, never confirmed.
        deviant = observation_from_result(
            _result("returned", actual_return="7"),
            member="dev", file="pkg/dev.py",
        )
        conforming = [
            observation_from_result(
                _result("exception", actual_exception="ValueError"),
                member=f"peer_{i}", file=f"pkg/peer_{i}.py",
            )
            for i in range(2)
        ] + [
            observation_from_result(
                _result("arg_binding_error",
                        match_detail="arguments do not bind"),
                member="peer_2", file="pkg/peer_2.py",
            ),
        ]
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, deviant, conforming, vector_index=0,
        )
        assert v.verdict == VERDICT_INCONCLUSIVE
        assert v.verdict != VERDICT_CONFIRMED
        assert "peer_2" in v.reason

    def test_quorum_below_floor_poisons(self):
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, _obs(OBS_ACCEPT, "dev"),
            _conf(*[OBS_REJECT] * (MIN_CONFORMING_EXECUTED - 1)),
            vector_index=0,
        )
        assert v.verdict == VERDICT_INCONCLUSIVE
        assert str(MIN_CONFORMING_EXECUTED) in v.reason

    def test_accept_vs_all_reject_confirms(self):
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, _obs(OBS_ACCEPT, "dev", "7"),
            _conf(OBS_REJECT, OBS_REJECT, OBS_REJECT), vector_index=0,
        )
        assert v.verdict == VERDICT_CONFIRMED

    def test_exception_parity_same_axis(self):
        v = classify_vector(
            CONTRACT_EXCEPTION_PARITY, _obs(OBS_ACCEPT, "dev"),
            _conf(OBS_REJECT, OBS_REJECT, OBS_REJECT), vector_index=0,
        )
        assert v.verdict == VERDICT_CONFIRMED

    def test_unanimous_accept_agrees(self):
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, _obs(OBS_ACCEPT, "dev"),
            _conf(OBS_ACCEPT, OBS_ACCEPT, OBS_ACCEPT), vector_index=0,
        )
        assert v.verdict == VERDICT_FAMILY_AGREES

    def test_unanimous_reject_agrees(self):
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, _obs(OBS_REJECT, "dev"),
            _conf(OBS_REJECT, OBS_REJECT, OBS_REJECT), vector_index=0,
        )
        assert v.verdict == VERDICT_FAMILY_AGREES

    def test_deviant_stricter_is_nondirectional(self):
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, _obs(OBS_REJECT, "dev"),
            _conf(OBS_ACCEPT, OBS_ACCEPT, OBS_ACCEPT), vector_index=0,
        )
        assert v.verdict == VERDICT_NONDIRECTIONAL

    def test_mixed_conforming_is_nondirectional(self):
        v = classify_vector(
            CONTRACT_ACCEPT_REJECT, _obs(OBS_ACCEPT, "dev"),
            _conf(OBS_REJECT, OBS_ACCEPT, OBS_REJECT), vector_index=0,
        )
        assert v.verdict == VERDICT_NONDIRECTIONAL

    def test_return_equivalence_agreement(self):
        v = classify_vector(
            CONTRACT_RETURN_EQUIVALENCE, _obs(OBS_ACCEPT, "dev", "7"),
            _conf(OBS_ACCEPT, OBS_ACCEPT, OBS_ACCEPT,
                  values=("7", "7", "7")), vector_index=0,
        )
        assert v.verdict == VERDICT_FAMILY_AGREES

    def test_return_equivalence_value_divergence_nondirectional(self):
        v = classify_vector(
            CONTRACT_RETURN_EQUIVALENCE, _obs(OBS_ACCEPT, "dev", "9"),
            _conf(OBS_ACCEPT, OBS_ACCEPT, OBS_ACCEPT,
                  values=("7", "7", "7")), vector_index=0,
        )
        assert v.verdict == VERDICT_NONDIRECTIONAL

    def test_return_equivalence_never_confirms(self):
        # Even the deviant-accepts / all-reject pattern stays
        # nondirectional under a value contract: only acceptance
        # contracts may vouch for a direction.
        v = classify_vector(
            CONTRACT_RETURN_EQUIVALENCE, _obs(OBS_ACCEPT, "dev", "7"),
            _conf(OBS_REJECT, OBS_REJECT, OBS_REJECT), vector_index=0,
        )
        assert v.verdict == VERDICT_NONDIRECTIONAL

    def test_return_equivalence_peer_disagreement_nondirectional(self):
        v = classify_vector(
            CONTRACT_RETURN_EQUIVALENCE, _obs(OBS_ACCEPT, "dev", "7"),
            _conf(OBS_ACCEPT, OBS_ACCEPT, OBS_ACCEPT,
                  values=("7", "8", "7")), vector_index=0,
        )
        assert v.verdict == VERDICT_NONDIRECTIONAL


# -- lead fold ----------------------------------------------------------------


def _vv(verdict: str, n_conforming: int = 3, index: int = 0) -> VectorVerdict:
    return VectorVerdict(
        vector_index=index, verdict=verdict, reason=verdict,
        contract=CONTRACT_ACCEPT_REJECT,
        deviant=_obs(OBS_ACCEPT, "dev"),
        conforming=_conf(*[OBS_REJECT] * n_conforming),
    )


class TestLeadFold:
    def test_one_confirmed_vector_confirms(self):
        lead = classify_lead(
            CONTRACT_ACCEPT_REJECT,
            [_vv(VERDICT_FAMILY_AGREES), _vv(VERDICT_CONFIRMED, 4, 1)],
            family_floor=3,
        )
        assert lead.verdict == VERDICT_CONFIRMED
        assert lead.executed_conforming == 4
        assert lead.meets_family_floor

    def test_floor_not_met_recorded(self):
        lead = classify_lead(
            CONTRACT_ACCEPT_REJECT, [_vv(VERDICT_CONFIRMED, 3)],
            family_floor=4,
        )
        assert lead.verdict == VERDICT_CONFIRMED
        assert not lead.meets_family_floor

    def test_floor_met_at_boundary(self):
        lead = classify_lead(
            CONTRACT_ACCEPT_REJECT, [_vv(VERDICT_CONFIRMED, 4)],
            family_floor=4,
        )
        assert lead.meets_family_floor

    def test_divergence_without_direction(self):
        lead = classify_lead(
            CONTRACT_ACCEPT_REJECT,
            [_vv(VERDICT_FAMILY_AGREES), _vv(VERDICT_NONDIRECTIONAL)],
            family_floor=3,
        )
        assert lead.verdict == VERDICT_NONDIRECTIONAL
        assert not lead.meets_family_floor

    def test_unanimous_agreement(self):
        lead = classify_lead(
            CONTRACT_ACCEPT_REJECT,
            [_vv(VERDICT_FAMILY_AGREES), _vv(VERDICT_FAMILY_AGREES)],
            family_floor=3,
        )
        assert lead.verdict == VERDICT_FAMILY_AGREES
        assert not lead.meets_family_floor

    def test_all_inconclusive(self):
        lead = classify_lead(
            CONTRACT_ACCEPT_REJECT, [_vv(VERDICT_INCONCLUSIVE)],
            family_floor=3,
        )
        assert lead.verdict == VERDICT_INCONCLUSIVE

    def test_no_vectors(self):
        lead = classify_lead(CONTRACT_ACCEPT_REJECT, [], family_floor=3)
        assert lead.verdict == VERDICT_INCONCLUSIVE

    def test_excluded_members_travel(self):
        excluded = [{"member": "peer_9", "reason": "over family cap"}]
        lead = classify_lead(
            CONTRACT_ACCEPT_REJECT, [_vv(VERDICT_FAMILY_AGREES)],
            family_floor=3, excluded=excluded,
        )
        assert lead.excluded == excluded
        assert lead.to_dict()["excluded"] == excluded


# -- compute rails ------------------------------------------------------------


class TestRails:
    def test_rail_values_are_pinned(self):
        # Deliberate-change tripwires: moving any rail in either
        # direction must update this pin alongside the rationale
        # comment at the constant.
        assert MAX_DIFFERENTIAL_EXECUTIONS == 150
        assert MAX_DIFFERENTIAL_WALL_S == 900.0
        assert MIN_CONFORMING_EXECUTED == 3
        assert MAX_CONFORMING_EXECUTED == 8
        assert MAX_VECTORS_PER_LEAD == 3

    def test_rail_relationships(self):
        assert MAX_CONFORMING_EXECUTED >= MIN_CONFORMING_EXECUTED
        assert MAX_VECTORS_PER_LEAD >= 1
        # One fully-fanned lead must fit inside the run budget.
        assert (
            (1 + MAX_CONFORMING_EXECUTED) * MAX_VECTORS_PER_LEAD
            <= MAX_DIFFERENTIAL_EXECUTIONS
        )

    def test_execution_budget_both_directions(self):
        b = DifferentialBudget(max_executions=5, max_wall_s=999.0)
        assert b.try_charge(4)
        assert b.over_reason() is None
        assert b.try_charge(1)
        assert not b.try_charge(1)
        assert "execution budget" in (b.over_reason() or "")

    def test_charge_never_partially_applies(self):
        b = DifferentialBudget(max_executions=5, max_wall_s=999.0)
        assert b.try_charge(4)
        assert not b.try_charge(2)
        assert b.executions == 4

    def test_wall_budget_both_directions(self):
        t = {"now": 0.0}
        b = DifferentialBudget(
            max_executions=999, max_wall_s=10.0,
            clock=lambda: t["now"],
        )
        assert b.try_charge()
        t["now"] = 9.9
        assert b.over_reason() is None
        assert b.try_charge()
        t["now"] = 10.0
        assert "wall budget" in (b.over_reason() or "")
        assert not b.try_charge()

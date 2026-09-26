"""Metamorphic relation witness — three controls, parser, verdicts.

The load-bearing invariants: a relation earns trust only through the
channel controls executed on the real target (determinism and
sensitivity) PLUS the relation-validity control executed on the
conforming peers; an untrusted relation can never violate OR hold; a
violation is provisional until the family vouches for the relation;
relation-holds is a failure to promote and nothing more; any member
error poisons the witness.
"""

from __future__ import annotations

import json

from core.audit.differential import (
    MAX_RELATION_PAIRS,
    OBS_ACCEPT,
    OBS_ERROR,
    OBS_REJECT,
    VERDICT_INCONCLUSIVE,
    VERDICT_RELATION_HOLDS,
    VERDICT_RELATION_VIOLATED,
    DifferentialVector,
    MemberObservation,
    MetamorphicRelation,
    MetamorphicVerdict,
    build_relation_prompt,
    classify_relation,
    parse_relation_response,
    validate_relation_on_family,
)

# -- fixtures -----------------------------------------------------------------


def _obs(kind: str, value: str = "") -> MemberObservation:
    return MemberObservation(
        member="target", file="pkg/dev.py", kind=kind, value=value,
    )


def _relation() -> MetamorphicRelation:
    return MetamorphicRelation(
        relation="order-insensitive over its list argument",
        pairs=[(DifferentialVector(args=[[1, 2]]),
                DifferentialVector(args=[[2, 1]]))],
        differ=(DifferentialVector(args=[[1]]),
                DifferentialVector(args=[[1, 2, 3]])),
    )


_GOOD_DETERMINISM = (_obs(OBS_ACCEPT, "3"), _obs(OBS_ACCEPT, "3"))
_GOOD_SENSITIVITY = (_obs(OBS_ACCEPT, "1"), _obs(OBS_ACCEPT, "6"))


def _classify(**over):
    kw = dict(
        determinism=_GOOD_DETERMINISM,
        sensitivity=_GOOD_SENSITIVITY,
        pairs=[(_obs(OBS_ACCEPT, "3"), _obs(OBS_ACCEPT, "3"))],
    )
    kw.update(over)
    return classify_relation(_relation(), **kw)


# -- classification -----------------------------------------------------------


class TestControls:
    def test_trusted_relation_holds(self):
        v = _classify()
        assert v.verdict == VERDICT_RELATION_HOLDS
        assert v.controls_passed
        assert v.pair_index == -1

    def test_violation_confirmed_under_passed_controls(self):
        v = _classify(pairs=[
            (_obs(OBS_ACCEPT, "3"), _obs(OBS_ACCEPT, "3")),
            (_obs(OBS_ACCEPT, "3"), _obs(OBS_ACCEPT, "5")),
        ])
        assert v.verdict == VERDICT_RELATION_VIOLATED
        assert v.controls_passed
        assert v.pair_index == 1

    def test_kind_divergence_is_a_violation(self):
        v = _classify(pairs=[
            (_obs(OBS_ACCEPT, "3"), _obs(OBS_REJECT, "ValueError: x")),
        ])
        assert v.verdict == VERDICT_RELATION_VIOLATED

    def test_failed_determinism_poisons_even_a_diverging_pair(self):
        # A flaky function would mint violations out of noise: the
        # diverging pair must NOT classify once the determinism
        # control failed.
        v = _classify(
            determinism=(_obs(OBS_ACCEPT, "3"), _obs(OBS_ACCEPT, "4")),
            pairs=[(_obs(OBS_ACCEPT, "3"), _obs(OBS_ACCEPT, "5"))],
        )
        assert v.verdict == VERDICT_INCONCLUSIVE
        assert not v.controls_passed
        assert "determinism" in v.reason

    def test_failed_sensitivity_poisons_even_a_holding_pair(self):
        # An undiscriminating observation channel makes every pair
        # vacuously "hold" — no verdict may rest on it.
        v = _classify(
            sensitivity=(_obs(OBS_ACCEPT, "1"), _obs(OBS_ACCEPT, "1")),
        )
        assert v.verdict == VERDICT_INCONCLUSIVE
        assert not v.controls_passed
        assert "sensitivity" in v.reason

    def test_any_error_poisons(self):
        for stage in ("determinism", "sensitivity", "pairs"):
            broken = (_obs(OBS_ERROR), _obs(OBS_ACCEPT, "3"))
            v = _classify(**{
                stage: broken if stage != "pairs" else [broken],
            })
            assert v.verdict == VERDICT_INCONCLUSIVE, stage
            assert not v.controls_passed, stage

    def test_no_pairs_is_inconclusive(self):
        v = _classify(pairs=[])
        assert v.verdict == VERDICT_INCONCLUSIVE
        assert v.controls_passed

    def test_violation_starts_unvalidated(self):
        # classify_relation never grants family validation itself — a
        # violation straight out of the channel controls is
        # provisional until the peers vouch for the relation.
        v = _classify(pairs=[
            (_obs(OBS_ACCEPT, "3"), _obs(OBS_ACCEPT, "5")),
        ])
        assert v.verdict == VERDICT_RELATION_VIOLATED
        assert not v.family_validated

    def test_serialization_carries_observations(self):
        d = _classify().to_dict()
        assert d["verdict"] == VERDICT_RELATION_HOLDS
        # 2 determinism + 2 sensitivity + 2 pair observations.
        assert len(d["observations"]) == 6
        assert d["family_validated"] is False


# -- relation-validity control -------------------------------------------------


def _peer_pair(
    i: int, *, hold: bool = True, error: bool = False,
) -> tuple[MemberObservation, MemberObservation]:
    def _p(kind: str, value: str) -> MemberObservation:
        return MemberObservation(
            member=f"peer_{i}", file=f"pkg/peer_{i}.py",
            kind=kind, value=value,
        )
    if error:
        return _p(OBS_ERROR, ""), _p(OBS_ACCEPT, "3")
    return _p(OBS_ACCEPT, "3"), _p(OBS_ACCEPT, "3" if hold else "9")


def _violated() -> MetamorphicVerdict:
    return _classify(pairs=[
        (_obs(OBS_ACCEPT, "3"), _obs(OBS_ACCEPT, "5")),
    ])


class TestRelationValidityControl:
    def test_family_holding_validates_the_violation(self):
        peers = [_peer_pair(i) for i in range(3)]
        v = validate_relation_on_family(_violated(), peers, quorum=3)
        assert v.verdict == VERDICT_RELATION_VIOLATED
        assert v.family_validated
        assert "conforming peers" in v.reason
        # 6 target observations + 2 per peer.
        assert len(v.observations) == 12

    def test_peer_violating_poisons_as_false_relation(self):
        # The channel controls verified the comparison can SEE
        # differences — never that the claimed equivalence is a true
        # invariant. A relation the family also violates is a false
        # relation: poison, never promote.
        peers = [_peer_pair(0), _peer_pair(1, hold=False), _peer_pair(2)]
        v = validate_relation_on_family(_violated(), peers, quorum=3)
        assert v.verdict == VERDICT_INCONCLUSIVE
        assert not v.family_validated
        assert "false relation" in v.reason
        assert "peer_1" in v.reason

    def test_peer_error_poisons(self):
        peers = [_peer_pair(0), _peer_pair(1, error=True), _peer_pair(2)]
        v = validate_relation_on_family(_violated(), peers, quorum=3)
        assert v.verdict == VERDICT_INCONCLUSIVE
        assert not v.family_validated

    def test_below_quorum_poisons(self):
        peers = [_peer_pair(0), _peer_pair(1)]
        v = validate_relation_on_family(_violated(), peers, quorum=3)
        assert v.verdict == VERDICT_INCONCLUSIVE
        assert not v.family_validated
        assert "need 3" in v.reason

    def test_non_violation_passes_through(self):
        held = _classify()
        assert held.verdict == VERDICT_RELATION_HOLDS
        v = validate_relation_on_family(held, [], quorum=3)
        assert v is held

    def test_validated_serialization(self):
        peers = [_peer_pair(i) for i in range(3)]
        d = validate_relation_on_family(
            _violated(), peers, quorum=3,
        ).to_dict()
        assert d["family_validated"] is True
        assert d["verdict"] == VERDICT_RELATION_VIOLATED


# -- parser -------------------------------------------------------------------


def _vec(*args) -> dict:
    return {"args": list(args), "kwargs": {}}


def _response(**over) -> str:
    data = {
        "relation": "order-insensitive",
        "pairs": [{"left": _vec([1, 2]), "right": _vec([2, 1])}],
        "differ": {"left": _vec([1]), "right": _vec([1, 2, 3])},
    }
    data.update(over)
    return json.dumps(data)


class TestParseRelationResponse:
    def test_valid_response(self):
        rel = parse_relation_response(_response())
        assert rel is not None
        assert rel.relation == "order-insensitive"
        assert len(rel.pairs) == 1
        assert rel.pairs[0][0].args == [[1, 2]]
        assert rel.differ is not None

    def test_missing_differ_refuses_response(self):
        raw = json.loads(_response())
        del raw["differ"]
        assert parse_relation_response(json.dumps(raw)) is None

    def test_malformed_differ_refuses_response(self):
        assert parse_relation_response(
            _response(differ={"left": _vec(1)}),
        ) is None

    def test_missing_relation_refused(self):
        assert parse_relation_response(_response(relation="")) is None

    def test_malformed_pairs_dropped(self):
        rel = parse_relation_response(_response(pairs=[
            "junk",
            {"left": _vec(1)},
            {"left": {"args": "not a list"}, "right": _vec(1)},
            {"left": _vec(1), "right": _vec(2)},
        ]))
        assert rel is not None
        assert len(rel.pairs) == 1

    def test_no_usable_pairs_refused(self):
        assert parse_relation_response(_response(pairs=["junk"])) is None

    def test_pair_cap_applied(self):
        many = [
            {"left": _vec(i), "right": _vec(i + 1)}
            for i in range(MAX_RELATION_PAIRS + 4)
        ]
        rel = parse_relation_response(_response(pairs=many))
        assert rel is not None
        assert len(rel.pairs) == MAX_RELATION_PAIRS

    def test_relation_prose_bounded(self):
        rel = parse_relation_response(_response(relation="r" * 5000))
        assert rel is not None
        assert len(rel.relation) == 300


# -- prompt -------------------------------------------------------------------


class TestBuildRelationPrompt:
    def test_envelope_shape(self):
        lead = {
            "file": "pkg/dev.py",
            "function": "deviant",
            "description": "canonicalizes before checking in 3/4 siblings",
        }
        user, system = build_relation_prompt(lead)
        assert "pkg/dev.py" in user
        assert "deviant" in user
        assert "canonicalizes before checking" in user
        assert "should-differ" in system
        assert "## Task" in system

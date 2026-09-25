"""Interface-implementor parity over route families (L10).

The route-family layer stamps every member with a two-valued
auth-DECORATION property; the interface dimension votes it as its
own property so "peers carry the auth decorator, this one doesn't"
rides the standing comparator — detection-grade, prepass-lead-only,
no new verdict path. The decoration fact is deliberately never
folded into the body-evidence ``auth_check`` vote: target-authored
decorator text must not be able to mask a body-evidence lead.
"""

from __future__ import annotations

import textwrap

from core.analysis.peer_groups import (
    GROUP_TYPE_ROUTE_FAMILY,
    ROUTE_AUTH_PROPERTY,
)
from core.audit.consistency_dimensions import (
    _INTERFACE_GROUP_TYPES,
    _ROUTE_AUTH_PRESENCE_PROPERTY,
    detect_interface_deviations,
)
from core.audit.peer_evidence import is_detection_rule_id
from core.audit.sibling_analysis import SiblingGroup, SiblingPath
from core.testing import requires_ts

_PLAIN_BODY = textwrap.dedent("""\
    def {name}():
        value = load("{name}")
        return value
""")

_BODY_AUTH = textwrap.dedent("""\
    def {name}():
        if not is_authenticated():
            return None
        value = load("{name}")
        return value
""")


def _sources(names_bodies: list[tuple[str, str]]) -> dict[str, str]:
    return {"app.py": "\n".join(
        tpl.format(name=n) for n, tpl in names_bodies
    )}


def _route_group(members: list[tuple[str, bool]]) -> SiblingGroup:
    """``members`` = [(function, decorator_present)]. The layer
    stamps every member two-valued."""
    return SiblingGroup(
        group_id="route_family:flask:decorator:api",
        sibling_type=GROUP_TYPE_ROUTE_FAMILY,
        description="flask decorator route handlers under /api",
        siblings=[
            SiblingPath(
                label=n, file="app.py", function=n,
                properties={ROUTE_AUTH_PROPERTY: present},
            )
            for n, present in members
        ],
    )


class TestGroupTypeAdmission:
    def test_route_family_admitted_and_pinned(self):
        """The frozenset literal must track the layer's group-type
        string — a silent miss here is exactly the drift failure
        mode the widening comment names."""
        assert GROUP_TYPE_ROUTE_FAMILY in _INTERFACE_GROUP_TYPES
        assert "dispatch_site" in _INTERFACE_GROUP_TYPES
        assert "type_cohort" in _INTERFACE_GROUP_TYPES

    def test_presence_property_literal_pinned(self):
        assert _ROUTE_AUTH_PRESENCE_PROPERTY == ROUTE_AUTH_PROPERTY


class TestRouteFamilyParity:
    @requires_ts("python")
    def test_missing_decorator_deviant_flagged(self):
        members = [("h_a", True), ("h_b", True), ("h_c", True),
                   ("h_d", False)]
        sources = _sources([(n, _PLAIN_BODY) for n, _p in members])
        devs = detect_interface_deviations(
            sources, [_route_group(members)],
        )
        deco = [d for d in devs
                if d.property_name == ROUTE_AUTH_PROPERTY]
        assert len(deco) == 1
        d = deco[0]
        assert d.enclosing_function == "h_d"
        assert d.n == 4 and d.conforming == 3
        assert d.cwe == "CWE-862"
        pe = d.peer_evidence
        assert pe is not None
        assert pe.contract_source == "majority"
        assert pe.provenance \
            == f"interface:route_family:{ROUTE_AUTH_PROPERTY}"
        # Detection-grade throughout: the -majority variant never
        # promotes alone.
        assert is_detection_rule_id(pe.rule_id)
        assert pe.rule_id == "consistency:interface-majority"

    @requires_ts("python")
    def test_description_claims_decoration_difference_only(self):
        members = [("h_a", True), ("h_b", True), ("h_c", True),
                   ("h_d", False)]
        sources = _sources([(n, _PLAIN_BODY) for n, _p in members])
        devs = detect_interface_deviations(
            sources, [_route_group(members)],
        )
        d = [x for x in devs
             if x.property_name == ROUTE_AUTH_PROPERTY][0]
        # The lead states the DECORATION difference — it never
        # claims the peers perform an auth check, are protected, or
        # that the deviant is wrong (a recorded decorator may not
        # wrap the registered callable).
        assert d.description == (
            "3/4 implementors in route_family:flask:decorator:api "
            "carry the auth decorator; h_d does not"
        )
        pe = d.peer_evidence
        assert pe.deviant.snippet \
            == "h_d does not carry the auth decorator"
        assert all(e.snippet.endswith("carries the auth decorator")
                   for e in pe.exhibits)

    @requires_ts("python")
    def test_decorator_stamp_never_masks_a_body_evidence_lead(self):
        """Masking regression: peers check auth in-body, the deviant
        does not — but the deviant carries a RECORDED auth decorator
        (position unknown; possibly above the registration decorator
        and wrapping nothing). The stamp must not raise the
        deviant's auth_check: the body-evidence lead survives."""
        members = [("h_a", False), ("h_b", False), ("h_c", False),
                   ("h_d", True)]
        sources = _sources([
            ("h_a", _BODY_AUTH), ("h_b", _BODY_AUTH),
            ("h_c", _BODY_AUTH), ("h_d", _PLAIN_BODY),
        ])
        devs = detect_interface_deviations(
            sources, [_route_group(members)],
        )
        auth = [d for d in devs if d.property_name == "auth_check"]
        assert [d.enclosing_function for d in auth] == ["h_d"]
        assert auth[0].conforming == 3
        # And the decoration property flags nothing here: the
        # security direction is minority-LACKS-what-majority-has,
        # and the decorated member is the minority.
        assert [d for d in devs
                if d.property_name == ROUTE_AUTH_PROPERTY] == []

    @requires_ts("python")
    def test_stamps_never_raise_auth_check(self):
        """All members decorated, all bodies plain: if stamps fed
        auth_check this would read uniformly-checked; instead each
        property stays uniform on its own vote and nothing fires."""
        members = [(n, True) for n in ("h_a", "h_b", "h_c", "h_d")]
        sources = _sources([(n, _PLAIN_BODY) for n, _p in members])
        devs = detect_interface_deviations(
            sources, [_route_group(members)],
        )
        assert [d for d in devs
                if d.property_name in ("auth_check",
                                       ROUTE_AUTH_PROPERTY)] == []

    @requires_ts("python")
    def test_uniform_absence_yields_nothing(self):
        """No deviant → no deviation: this comparator reports
        difference between peers only, never a verdict on a family
        that agrees with itself."""
        members = [(n, False) for n in ("h_a", "h_b", "h_c", "h_d")]
        sources = _sources([(n, _PLAIN_BODY) for n, _p in members])
        devs = detect_interface_deviations(
            sources, [_route_group(members)],
        )
        assert [d for d in devs
                if d.property_name in ("auth_check",
                                       ROUTE_AUTH_PROPERTY)] == []

    @requires_ts("python")
    def test_stamps_ignored_on_other_group_types(self):
        """The adapter is gated on the route-family group type: the
        same attached property on a dispatch-site group votes
        nothing and steers nothing."""
        members = [("h_a", True), ("h_b", True), ("h_c", True),
                   ("h_d", False)]
        group = _route_group(members)
        group.group_id = "dispatch:app.py:ops"
        group.sibling_type = "dispatch_site"
        sources = _sources([(n, _PLAIN_BODY) for n, _p in members])
        devs = detect_interface_deviations(sources, [group])
        assert [d for d in devs
                if d.property_name in ("auth_check",
                                       ROUTE_AUTH_PROPERTY)] == []

    @requires_ts("python")
    def test_unresolved_members_shrink_below_floor(self):
        """Members whose bodies are not in the source set drop out
        (a CBV class name never resolves to a function span); a
        family below the floor votes nothing."""
        members = [("h_a", True), ("h_b", True), ("gone_x", True),
                   ("gone_y", False)]
        sources = _sources([("h_a", _PLAIN_BODY),
                            ("h_b", _PLAIN_BODY)])
        devs = detect_interface_deviations(
            sources, [_route_group(members)],
        )
        assert devs == []

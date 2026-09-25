"""Tests for uniformly-weak family reporting.

The all-members-weak family produces zero deviants in every majority
comparator; these tests pin the record that now covers it — certain-
membership families only, auth/bounds properties only, hint tier
always, fail-closed on unresolved members, capped, and rendered as
context that must never classify alone.
"""

from __future__ import annotations

import textwrap

from core.audit.sibling_analysis import SiblingGroup, SiblingPath
from core.audit.uniform_absence import (
    MAX_UNIFORM_ABSENCE_RECORDS,
    seed_uniform_absence,
    uniform_absence_records,
)
from core.testing import requires_ts

_UNGUARDED = textwrap.dedent("""\
    def {name}(req):
        value = load(req)
        return value
""")

_AUTHED = textwrap.dedent("""\
    def {name}(req):
        if not is_authenticated():
            return None
        value = load(req)
        return value
""")


def _sources(names, authed=()):
    return {"app.py": "\n".join(
        (_AUTHED if n in authed else _UNGUARDED).format(name=n)
        for n in names
    )}


def _group(names, gtype="interface_slot", gid="interface_slot:x"):
    return SiblingGroup(
        group_id=gid,
        sibling_type=gtype,  # type: ignore[arg-type]
        description="test family",
        siblings=[
            SiblingPath(label=n, file="app.py", function=n)
            for n in names
        ],
    )


NAMES = ("handle_a", "handle_b", "handle_c")


@requires_ts("python")
def test_all_weak_family_emits_hint_record():
    sources = _sources(NAMES)
    records = uniform_absence_records(sources, [_group(NAMES)])
    auth = [r for r in records if r["property"] == "auth_check"]
    assert len(auth) == 1
    rec = auth[0]
    assert rec["kind"] == "uniform_absence"
    assert rec["tier"] == "hint"
    assert rec["n"] == 3
    assert "unexamined is not safe" in rec["description"]


@requires_ts("python")
def test_one_conforming_member_means_no_record():
    # A family with any member carrying the property is majority
    # territory — the deviance comparator owns it, not this module.
    sources = _sources(NAMES, authed=("handle_b",))
    records = uniform_absence_records(sources, [_group(NAMES)])
    assert [r for r in records if r["property"] == "auth_check"] == []


@requires_ts("python")
def test_heuristic_group_types_never_report():
    sources = _sources(NAMES)
    for gtype in ("peer_functions", "co_callee", "type_cohort",
                  "clone_family", "dispatch_site"):
        records = uniform_absence_records(
            sources, [_group(NAMES, gtype=gtype)],
        )
        assert records == [], gtype


@requires_ts("python")
def test_unresolved_member_poisons_the_claim():
    # One member's body is unreadable: an absence claim over a
    # partially-read family would overstate what was examined.
    sources = _sources(NAMES[:2])
    records = uniform_absence_records(sources, [_group(NAMES)])
    assert records == []


@requires_ts("python")
def test_below_floor_family_skipped():
    sources = _sources(NAMES[:2])
    records = uniform_absence_records(
        sources, [_group(NAMES[:2])], min_group=3,
    )
    assert records == []


@requires_ts("python")
def test_record_cap_bounds_a_family_flood():
    names_by_group = [
        tuple(f"g{i}_handle_{j}" for j in range(3))
        for i in range(MAX_UNIFORM_ABSENCE_RECORDS + 4)
    ]
    sources = {"app.py": "\n".join(
        _UNGUARDED.format(name=n)
        for names in names_by_group for n in names
    )}
    groups = [
        _group(names, gid=f"interface_slot:g{i}")
        for i, names in enumerate(names_by_group)
    ]
    records = uniform_absence_records(sources, groups)
    assert len(records) == MAX_UNIFORM_ABSENCE_RECORDS


def test_seeding_attaches_without_priority_movement():
    records = [{
        "kind": "uniform_absence",
        "group_id": "interface_slot:x",
        "property": "auth_check",
        "n": 3,
        "tier": "hint",
        "members": [
            {"file": "app.py", "function": "handle_a", "line": 1},
        ],
        "members_total": 3,
        "description": "d",
    }]
    gaps = [
        {"file": "app.py", "name": "handle_a", "priority_score": 1.5},
        {"file": "app.py", "name": "other"},
    ]
    seeded = seed_uniform_absence(gaps, records)
    assert seeded == 1
    assert gaps[0]["uniform_absence"] == records
    # Hint tier: the queue is never steered by this record.
    assert gaps[0]["priority_score"] == 1.5
    assert "uniform_absence" not in gaps[1]


def test_prompt_render_frames_as_hint():
    from core.audit.context import format_context_for_prompt

    ctx = {
        "file": "app.py", "function": "handle_a",
        "line_start": 1, "line_end": 3,
        "source": "def handle_a(req):\n    return load(req)\n",
        "uniform_absence": [{
            "kind": "uniform_absence",
            "group_id": "interface_slot:ops_slot:pkt_ops.send",
            "property": "auth_check",
            "n": 3,
            "tier": "hint",
            "members": [
                {"file": "app.py", "function": "handle_a", "line": 1},
            ],
            "members_total": 3,
            "description": "d",
        }],
    }
    prompt = format_context_for_prompt(ctx)
    assert "Uniformly-absent family properties" in prompt
    assert "auth_check" in prompt
    # The verdict-discipline framing rides in the section itself.
    assert "Never classify on this record alone" in prompt

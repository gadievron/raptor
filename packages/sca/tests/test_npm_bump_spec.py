"""Tests for _bump_npm_spec — npm harden spec rewriting.

Regression focus: an explicit comparator range must keep its upper bound
(``>=2.0.0 <3.0.0`` -> ``>=2.8.0 <3.0.0``), not collapse to a bare
``2.8.0`` that silently drops the operator's ceiling.
"""
from __future__ import annotations

import pytest

from packages.sca.update import _bump_npm_spec


@pytest.mark.parametrize("current,target,expected", [
    # operator forms are preserved (already corridors — unchanged behaviour)
    ("^2.0.0", "2.8.0", "^2.8.0"),
    ("~2.0.0", "2.8.0", "~2.8.0"),
    ("2.0.0",  "2.8.0", "2.8.0"),          # exact
    ("*",      "2.8.0", "2.8.0"),
    # THE FIX: explicit range bumps the floor, keeps the ceiling
    (">=2.0.0 <3.0.0", "2.8.0", ">=2.8.0 <3.0.0"),
    (">=2.0.0",        "2.8.0", ">=2.8.0"),
    (">2.0.0 <3.0.0",  "2.8.0", ">2.8.0 <3.0.0"),   # strict > kept
    (">=2 <3",         "2.8.0", ">=2.8.0 <3"),       # partial bounds kept
    ("<=2.9.0 >=2.0.0", "2.8.0", "<=2.9.0 >=2.8.0"),  # order-independent
    # target at/above the declared ceiling -> manual review (no invalid range)
    (">=2.0.0 <3.0.0", "3.5.0", None),
    (">=2.0.0 <3.0.0", "3.0.0", None),
    # target BELOW the declared floor -> manual review (don't widen down)
    (">=2.0.0", "1.0.0", None),
    (">=2.0.0 <3.0.0", "1.5.0", None),
    # ambiguous / unbumpable -> manual review
    (">=1.0.0 || >=2.0.0", "2.8.0", None),   # OR range
    ("<3.0.0",             "2.8.0", None),    # upper-only, no floor
    ("git+https://x/y.git", "2.8.0", None),   # VCS
    ("npm:lodash@^4",       "2.8.0", None),   # alias
])
def test_bump_npm_spec(current, target, expected):
    # installed arg is the planner's from_version; for a RANGE dep it is
    # the whole spec string — pass `current` to mirror that.
    assert _bump_npm_spec(current, current, target) == expected


def test_rewrite_package_json_reason_distinguishes_declined_from_missing():
    """A dep that's present but declined (target outside its declared
    range) must NOT be reported as 'no matching spec found' — that would
    mislead the operator's skip report into thinking the dep is absent."""
    from pathlib import Path

    from packages.sca.update import _PlanEntry, _rewrite_package_json

    text = '{\n  "dependencies": {\n    "capped": ">=1.0.0 <2.0.0"\n  }\n}\n'
    # target 2.5.0 is past the <2.0.0 ceiling -> _bump_npm_spec declines.
    plan = _PlanEntry(ecosystem="npm", name="capped",
                      installed=">=1.0.0 <2.0.0", target="2.5.0",
                      manifest=Path("/x/package.json"), advisory_ids=[])
    new, applied, reason = _rewrite_package_json(text, plan)
    assert applied is False
    assert new == text                          # unchanged, valid JSON
    assert "not safely bumpable" in (reason or "")

    # a genuinely absent dep still reports 'no matching spec found'.
    plan2 = _PlanEntry(ecosystem="npm", name="absent",
                       installed="1.0.0", target="2.0.0",
                       manifest=Path("/x/package.json"), advisory_ids=[])
    _, applied2, reason2 = _rewrite_package_json(text, plan2)
    assert applied2 is False
    assert reason2 == "no matching spec found"

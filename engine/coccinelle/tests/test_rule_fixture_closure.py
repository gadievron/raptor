"""Fixture-coverage closure gate for promotion-capable rules.

The rule universe is derived mechanically — glob ``rules/*.cocci``,
read each rule's role through ``core.audit.sweep.get_rule_role`` (the
exact routine that grants direct status promotion) — never from a
hand-typed list. Every ``@role: verification`` rule must ship a
``tests/test_<stem>_rule.py`` carrying at least one positive (fires)
and one negative (stays silent) fixture: a false positive in a
verification rule mints a false "confirmed" verdict, so an untested
one is an unprobed verdict minter.

The presence check is a content heuristic (assertion-shape scan), not
a semantics proof — its job is to guarantee SOME fixture pair exists
for every promotion-capable rule; fixture quality is review's job.

``_UNCOVERED_ALLOWLIST`` records the rules that predate this gate.
It is meant as a ratchet: entries may only be removed (by writing
fixtures). The stale directions are mechanically enforced (a covered,
renamed, or demoted entry fails the gate); the no-new-entries
direction is a review convention — nothing mechanical stops a commit
that adds a rule and an allowlist entry together, so reviewers must
reject allowlist additions.

Runs hermetically — pure file inspection, no spatch needed.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.audit.sweep import get_rule_role

_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
_TESTS_DIR = Path(__file__).resolve().parent

# Fixture-coverage debt recorded 2026-09-21: verification rules that
# existed before this gate. Burn these down — write fixtures, delete
# the entry. Never add to this set; new rules ship with fixtures.
_UNCOVERED_ALLOWLIST = {
    "gfp_kernel_under_spinlock",
    "is_err_not_ptr_err",
    "rcu_dereference_outside_rcu",
    "rcu_no_lock",
}

# Positive lane: an exact-count expectation (results[0] subscripting,
# len(...) == N with N >= 1, or list-equality against a non-empty
# literal). Negative lane: an emptiness expectation. Shapes mirror
# the conventions across the existing rule test files.
_POSITIVE_RE = re.compile(r'\[0\]|len\(.*\)\s*==\s*[1-9]|==\s*\[\s*"')
_NEGATIVE_RE = re.compile(r'==\s*\[\]|assert not \w|len\(.*\)\s*==\s*0')


def _verification_rules() -> list[Path]:
    rules = [
        p for p in sorted(_RULES_DIR.glob("*.cocci"))
        if get_rule_role(str(p)) == "verification"
    ]
    # Guard the derivation itself — an empty glob or a role-parse
    # regression must not turn this gate into a vacuous pass.
    assert len(rules) >= 40, (
        f"only {len(rules)} verification rules derived — universe "
        f"derivation looks broken"
    )
    return rules


def test_every_verification_rule_has_fixture_pair():
    missing: list[str] = []
    for rule in _verification_rules():
        if rule.stem in _UNCOVERED_ALLOWLIST:
            continue
        test_file = _TESTS_DIR / f"test_{rule.stem}_rule.py"
        if not test_file.is_file():
            missing.append(f"{rule.stem}: no {test_file.name}")
            continue
        text = test_file.read_text(encoding="utf-8")
        if not _POSITIVE_RE.search(text):
            missing.append(f"{rule.stem}: no positive (fires) fixture")
        if not _NEGATIVE_RE.search(text):
            missing.append(f"{rule.stem}: no negative (silent) fixture")
    assert not missing, (
        "promotion-capable rules without fixture coverage (a false "
        "positive here mints a false 'confirmed' verdict):\n  "
        + "\n  ".join(missing)
    )


def test_allowlist_is_a_ratchet():
    verification_stems = {p.stem for p in _verification_rules()}
    stale: list[str] = []
    for stem in sorted(_UNCOVERED_ALLOWLIST):
        if stem not in verification_stems:
            stale.append(
                f"{stem}: not a verification rule (renamed, removed, "
                f"or demoted) — drop the allowlist entry"
            )
            continue
        test_file = _TESTS_DIR / f"test_{stem}_rule.py"
        if test_file.is_file():
            stale.append(
                f"{stem}: {test_file.name} exists — drop the "
                f"allowlist entry so the gate enforces it"
            )
    assert not stale, "stale allowlist entries:\n  " + "\n  ".join(stale)

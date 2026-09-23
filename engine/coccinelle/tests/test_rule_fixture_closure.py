"""Fixture-coverage closure gate for promotion-capable rules.

The rule universe is derived mechanically — glob ``rules/*.cocci``
and scan each rule's FULL text for its ``@role:`` declaration —
never from a hand-typed list, and deliberately NOT through
``core.audit.sweep.get_rule_role``: the gate's universe must not
depend on the reader whose failure it exists to catch.  When the
universe derived through the runtime reader, a reader regression
(a byte-capped read that lost a directive to header growth) shrank
the universe and dropped the demoted rule's fixture requirement in
the same stroke — a self-referential blind spot the gate greened
right through.  ``test_declared_role_matches_runtime_reader`` now
cross-checks the independent scan against ``get_rule_role`` for
every rule, so a reader/declaration divergence fails CI loudly.
A rule whose role cannot be determined from its text (no directive,
conflicting directives, or an unknown role token) FAILS the gate —
it never silently drops out of the universe.

Every ``@role: verification`` rule must ship a
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

# Fixture-coverage debt, fully burned down 2026-09-21: every
# verification rule now ships a fixture pair. Never add to this set;
# new rules ship with fixtures.
_UNCOVERED_ALLOWLIST: set[str] = set()

# Positive lane: an exact-count expectation (results[0] subscripting,
# len(...) == N with N >= 1, or list-equality against a non-empty
# literal). Negative lane: an emptiness expectation. Shapes mirror
# the conventions across the existing rule test files.
_POSITIVE_RE = re.compile(r'\[0\]|len\(.*\)\s*==\s*[1-9]|==\s*\[\s*"')
_NEGATIVE_RE = re.compile(r'==\s*\[\]|assert not \w|len\(.*\)\s*==\s*0')

# Independent full-file directive scan. Same directive shape as the
# runtime reader's regex, applied to the WHOLE file — kept separate
# from core.audit.sweep._ROLE_RE on purpose (sharing the reader's
# machinery would re-create the self-reference this scan breaks).
_DECLARED_ROLE_RE = re.compile(r"^//\s*@role:\s*(\w+)", re.MULTILINE)


def _declared_role(rule: Path) -> str:
    """Reader-independent role: full-file scan of the declaration.

    Condemn-toward-visibility: a rule whose role cannot be determined
    fails here (which fails every gate that derives through this),
    never silently defaults — a silent default is exactly how a
    promotion-capable rule drops out of the fixture universe unseen.
    """
    tokens = {
        m.group(1).lower()
        for m in _DECLARED_ROLE_RE.finditer(
            rule.read_text(encoding="utf-8")
        )
    }
    assert tokens, (
        f"{rule.name}: no // @role: directive found in the full file — "
        f"every stock rule must declare its role explicitly; an "
        f"undeclarable rule must not silently drop out of the "
        f"promotion-gate universe"
    )
    assert len(tokens) == 1, (
        f"{rule.name}: conflicting @role directives {sorted(tokens)}"
    )
    (role,) = tokens
    assert role in ("detection", "verification"), (
        f"{rule.name}: unknown @role token {role!r} — the role cannot "
        f"be determined, fix the directive"
    )
    return role


def _verification_rules() -> list[Path]:
    rules = [
        p for p in sorted(_RULES_DIR.glob("*.cocci"))
        if _declared_role(p) == "verification"
    ]
    # Guard the derivation itself — an empty glob or a role-parse
    # regression must not turn this gate into a vacuous pass.
    assert len(rules) >= 40, (
        f"only {len(rules)} verification rules derived — universe "
        f"derivation looks broken"
    )
    return rules


def test_declared_role_matches_runtime_reader():
    """Declared-vs-runtime cross-check over the whole library.

    ``get_rule_role`` is the routine that actually grants promotion at
    run time; ``_declared_role`` is what the rule's text says.  Any
    divergence means the runtime reader cannot see a declaration (the
    2048-byte-prefix regression demoted format_string this way and
    simultaneously hid it from this gate's universe) — fail loudly,
    naming the rule and both answers.
    """
    diverged = [
        f"{p.name}: declared {_declared_role(p)!r} but get_rule_role "
        f"returns {get_rule_role(str(p))!r}"
        for p in sorted(_RULES_DIR.glob("*.cocci"))
        if _declared_role(p) != get_rule_role(str(p))
    ]
    assert not diverged, (
        "runtime role reader diverges from the rules' declared roles "
        "(promotion authority and fixture-universe membership are "
        "silently wrong for these rules):\n  " + "\n  ".join(diverged)
    )


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


def test_undeterminable_roles_are_condemned(tmp_path):
    """Condemn-toward-visibility unit pins: a rule whose role cannot
    be determined fails the derivation loudly instead of silently
    defaulting out of the universe."""
    import pytest

    no_directive = tmp_path / "no_directive.cocci"
    no_directive.write_text("// a rule\n@r@\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="no // @role: directive"):
        _declared_role(no_directive)

    typo = tmp_path / "typo.cocci"
    typo.write_text("// @role: verificaton\n@r@\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="unknown @role token"):
        _declared_role(typo)

    conflict = tmp_path / "conflict.cocci"
    conflict.write_text(
        "// @role: verification\n// @role: detection\n@r@\n",
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="conflicting @role"):
        _declared_role(conflict)

    # An INDENTED directive is not the canonical spelling — neither
    # the runtime reader nor this scan honours it, and the loud
    # failure here is what keeps that consistent divergence visible.
    indented = tmp_path / "indented.cocci"
    indented.write_text("  // @role: verification\n@r@\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="no // @role: directive"):
        _declared_role(indented)

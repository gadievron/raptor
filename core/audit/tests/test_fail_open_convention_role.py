"""Consumer-side caps on registry-sourced convention patterns.

``_convention_role`` compiles ``SecurityConvention.pattern`` strings
from the runtime learned-vocabulary registry and searches them over
attacker-authored ``enclosing_source``. The repo-wide regex census
covers repo-authored pattern LITERALS only, so the consumer carries
its own caps: a pattern longer than identifier-scale is refused, and
the haystack is searched only within a bounded window. Both
directions are pinned here so a cap change is a deliberate decision.
"""

from __future__ import annotations

from types import SimpleNamespace

from core.audit.fail_open_roles import (
    _CONVENTION_PATTERN_MAX_LEN,
    _CONVENTION_SOURCE_WINDOW,
    RoleContext,
    _convention_role,
)


def _conv(pattern: str) -> SimpleNamespace:
    return SimpleNamespace(concern="auth", occurrences=99, pattern=pattern)


def _ctx(pattern: str) -> RoleContext:
    return RoleContext(conventions=[_conv(pattern)])


def test_in_cap_pattern_matches_names_and_source() -> None:
    ctx = _ctx(r"\bcheck_token\s*\(")
    ev = _convention_role(["check_token"], "", ctx)
    assert ev is None  # name alone lacks the call shape
    ev = _convention_role(
        ["handler"], "if (!check_token (req)) return;", ctx)
    assert ev is not None
    assert ev.kind == "auth"
    assert ev.source == "convention"


def test_overlong_pattern_is_refused() -> None:
    # Learned names are identifiers; a pattern past the cap is junk
    # (or a registry producer gone census-dishonest) and must not
    # compile-and-scan attacker-authored source.
    pattern = r"\b" + "a" * (_CONVENTION_PATTERN_MAX_LEN + 1) + r"\s*\("
    src = "a" * (_CONVENTION_PATTERN_MAX_LEN + 1) + " (x)"
    assert _convention_role(["f"], src, _ctx(pattern)) is None
    # A pattern inside the cap still scans: the refusal is the length
    # cap, not the convention mechanism.
    short = r"\bcheck_token\s*\("
    assert len(short) <= _CONVENTION_PATTERN_MAX_LEN
    assert _convention_role(
        ["f"], "check_token ()", _ctx(short)) is not None


def test_haystack_is_searched_only_within_the_window() -> None:
    ctx = _ctx(r"\bcheck_token\s*\(")
    needle = "check_token ()"
    # Match past the window: not searched (the bounded direction).
    beyond = " " * _CONVENTION_SOURCE_WINDOW + needle
    assert _convention_role(["f"], beyond, ctx) is None
    # Match at the window's tail: still found (the kept direction).
    inside = " " * (_CONVENTION_SOURCE_WINDOW - len(needle)) + needle
    assert _convention_role(["f"], inside, ctx) is not None

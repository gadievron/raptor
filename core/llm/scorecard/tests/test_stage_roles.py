"""Per-stage-role tagging helper for scorecard decision-classes.

Pins the naming rule: canonical form is ``"role"`` or
``"role:sub_topic"``, both lowercase, no whitespace in sub_topic.

Motivated by CVE-Genie (arXiv:2509.01835 §4) which pivots model
performance by stage role — we need the same axis on our scorecard
writes so "which model wins where" is computable.
"""

from __future__ import annotations

import pytest

from core.llm.scorecard.stage_roles import (
    KNOWN_STAGE_ROLES,
    parse_stage_role,
    stage_role_decision_class,
)


class TestBuild:
    def test_bare_role(self):
        assert stage_role_decision_class("mutator") == "mutator"

    def test_role_with_sub_topic(self):
        assert stage_role_decision_class("mutator", "cwe-121") == (
            "mutator:cwe-121"
        )

    def test_verification_critic_is_known(self):
        # The verification critic must be in the known set so its
        # writes don't raise.
        assert stage_role_decision_class("verification_critic") == (
            "verification_critic"
        )
        assert stage_role_decision_class(
            "verification_critic", "cwe-22",
        ) == "verification_critic:cwe-22"

    def test_uppercase_normalised(self):
        # Bare roles ARE lowercased; but only if the role itself is a
        # known key. The canonicaliser doesn't case-fold the input
        # against the known set — that's intentional so a typo like
        # "MUTATER" doesn't sneak through as "mutater".
        # Regression: sub_topic gets normalised too.
        assert stage_role_decision_class(
            "mutator", "CWE-121",
        ) == "mutator:cwe-121"

    def test_unknown_role_raises(self):
        with pytest.raises(ValueError, match="unknown stage_role"):
            stage_role_decision_class("brand_new_stage")

    def test_whitespace_in_sub_topic_raises(self):
        with pytest.raises(ValueError, match="whitespace"):
            stage_role_decision_class("mutator", "cwe 121")

    def test_embedded_newline_in_sub_topic_raises(self):
        # Regression: pre-fix only ``" "`` and ``"\t"`` were rejected,
        # so a producer that built sub_topic with an embedded newline
        # could land ``"mutator:cwe\n121"`` in the scorecard, breaking
        # greppability and CLI table rendering that splits on newlines.
        # Trailing whitespace/newlines are stripped so they don't land
        # in the rendered form and are safe — only EMBEDDED whitespace
        # threatens the invariant.
        with pytest.raises(ValueError, match="whitespace"):
            stage_role_decision_class("mutator", "cwe\n121")
        with pytest.raises(ValueError, match="whitespace"):
            stage_role_decision_class("mutator", "cwe\r121")
        with pytest.raises(ValueError, match="whitespace"):
            stage_role_decision_class("mutator", "cwe\v121")

    def test_control_char_in_sub_topic_raises(self):
        # Non-printable control chars would render as gibberish in
        # logs. ``\x00`` (NUL), ``\x07`` (BEL), ``\x1b`` (ESC) all
        # rejected.
        for bad in ("cwe\x00", "cwe\x07", "cwe\x1b121"):
            with pytest.raises(ValueError, match="non-printable"):
                stage_role_decision_class("mutator", bad)

    def test_empty_sub_topic_falls_back_to_bare_role(self):
        assert stage_role_decision_class("judge", "") == "judge"

    def test_whitespace_only_sub_topic_falls_back(self):
        # After .strip() the sub is empty; canonical form is bare role.
        assert stage_role_decision_class("judge", "   ") == "judge"


class TestParse:
    def test_bare_role(self):
        assert parse_stage_role("mutator") == ("mutator", "")

    def test_role_with_sub_topic(self):
        assert parse_stage_role("mutator:cwe-121") == (
            "mutator", "cwe-121",
        )

    def test_legacy_decision_class_parses_permissively(self):
        # Legacy "exploit_chain_closure" strings that predate the
        # canonical stage-role tagging must parse to
        # ("exploit_chain_closure", "") without raising —
        # the parser is deliberately permissive so pivot reports over
        # historical scorecard data don't crash.
        assert parse_stage_role("exploit_chain_closure") == (
            "exploit_chain_closure", "",
        )

    def test_empty_string(self):
        assert parse_stage_role("") == ("", "")


class TestKnownStageRoles:
    def test_frozenset_shape(self):
        # Guard against accidental in-place mutation of the exported
        # frozenset — a producer editing the set would be a bug.
        assert isinstance(KNOWN_STAGE_ROLES, frozenset)

    def test_covers_documented_substrates(self):
        # Every substrate that currently calls the scorecard OR is
        # planned to must appear.
        for expected in (
            "mutator", "refuter", "judge",
            "verification_critic", "actor",
            "success_lifter", "extract_lesson",
        ):
            assert expected in KNOWN_STAGE_ROLES, expected


class TestRoundTrip:
    """Build → parse round-trips are byte-identical after
    canonicalisation. Reports pivoting on the role prefix should get
    the same aggregation whether they read the built string or the
    parsed role."""

    def test_bare_role(self):
        built = stage_role_decision_class("mutator")
        role, sub = parse_stage_role(built)
        assert role == "mutator"
        assert sub == ""

    def test_with_sub_topic(self):
        built = stage_role_decision_class("verification_critic", "cwe-121")
        role, sub = parse_stage_role(built)
        assert role == "verification_critic"
        assert sub == "cwe-121"

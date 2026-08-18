"""Tests for the grammar reference constants.

The Coccinelle reference mandates named rules (RAPTOR's harness cannot
inject structured output into anonymous ``@@`` rules).  These tests pin
that every example in the reference follows its own mandate — the only
anonymous header allowed is the one explicitly labelled WRONG.
"""

from __future__ import annotations

from packages.checker_synthesis.grammars import COCCINELLE_GRAMMAR


def _fenced_blocks(text: str) -> list[list[str]]:
    """Extract fenced code blocks as lists of (lstripped) lines."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            if current is None:
                current = []
            else:
                blocks.append(current)
                current = None
            continue
        if current is not None:
            current.append(line.strip())
    return blocks


def _rule_blocks() -> list[list[str]]:
    """Blocks whose first line is a SmPL rule header."""
    return [
        b for b in _fenced_blocks(COCCINELLE_GRAMMAR)
        if b and b[0].startswith("@")
    ]


class TestNamedRuleConsistency:
    def test_only_the_wrong_example_is_anonymous(self):
        """Every anonymous @@ header must carry the WRONG label."""
        for block in _rule_blocks():
            header = block[0]
            if header.startswith("@@"):
                assert "WRONG" in header, (
                    "anonymous @@ example without WRONG label "
                    f"contradicts the named-rule mandate: {block!r}"
                )

    def test_disjunction_example_uses_named_rule(self):
        """The disjunction example emits output, so it must be named."""
        disjunction = [
            b for b in _rule_blocks()
            if any("snprintf@pos" in line for line in b)
        ]
        assert disjunction, "disjunction example missing from reference"
        for block in disjunction:
            assert not block[0].startswith("@@"), (
                "disjunction example uses an anonymous rule while "
                "declaring a position metavariable"
            )

    def test_position_declaring_rules_are_named(self):
        """Rules that declare positions emit output — never anonymous."""
        for block in _rule_blocks():
            if "WRONG" in block[0]:
                continue
            if any(line.startswith("position ") for line in block):
                assert not block[0].startswith("@@"), (
                    f"position-declaring rule is anonymous: {block!r}"
                )

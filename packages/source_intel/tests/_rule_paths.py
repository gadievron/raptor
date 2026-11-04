"""Paths to real shipped rule axes for focused integration contracts."""

from pathlib import Path


def shipped_axis_rules(axis: str) -> Path:
    """Keep native matching and parsing, without running unrelated axes."""
    rules = (Path(__file__).resolve().parents[3]
             / "engine/coccinelle/source_intel" / axis)
    assert any(rules.glob("*.cocci")), f"shipped {axis} rules are missing"
    return rules

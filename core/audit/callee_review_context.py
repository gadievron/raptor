"""Shared rendering of advisory prior callee assessments."""
from __future__ import annotations


def render_callee_context(value, *, defend_identifier) -> str:
    """Render only supported assessment fields using the prompt's identifier defence."""
    fields = ("callee", "assumption", "callee_status", "callee_hypothesis")
    if not isinstance(value, dict) or not any(value.get(key) for key in fields):
        return ""
    callee = defend_identifier(value.get("callee", "?"), max_length=128)
    assumption = defend_identifier(value.get("assumption", ""), max_length=300)
    status = defend_identifier(value.get("callee_status", "?"), max_length=64)
    hypothesis = defend_identifier(value.get("callee_hypothesis", ""), max_length=400)
    scope = defend_identifier(value.get("scope_note", "Original callee source binding unavailable; advisory assessment only."), max_length=512)
    return (
        "\n### Callee-contract violation\n"
        f"Prior caller assessment recorded an assumption about `{callee}`: "
        f"{assumption}.\n\n"
        f"Advisory prior callee assessment for `{callee}`: "
        f"**{status}**: {hypothesis}\n\n"
        f"Assessment source scope: {scope}\n\n"
        "This assessment is a review lead, not proof of actual callee behaviour "
        "or refutation of the caller assumption. Re-evaluate this function "
        "against source evidence and determine whether the assumption holds "
        "and whether this function is vulnerable."
    )

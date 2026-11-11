"""Shared rendering of advisory mechanical disagreement claims."""
from __future__ import annotations


def render_disagreement_context(value, *, defend_identifier) -> str:
    """Render bounded notes and typed claims without granting evidence authority."""
    if not isinstance(value, dict):
        return ""
    resolution = value.get("resolution", "")
    reachable = value.get("mechanical_reachable")
    has_flow = value.get("mechanical_has_flow")
    if (not isinstance(resolution, str)
            or any(item is not None and type(item) is not bool for item in (reachable, has_flow))):
        return ""
    if not resolution and reachable is None and has_flow is None:
        return ""
    resolution = defend_identifier(resolution, max_length=512)

    def claim(item):
        return "unknown" if item is None else "true" if item else "false"

    return (
        "\n### Advisory mechanical disagreement\n"
        "A prior mechanical claim differs from the earlier model assessment. "
        "This context does not establish successful tool execution, an actual "
        "flow, or confirmation or refutation of a concern.\n"
        f"Claimed reachability: {claim(reachable)}.\n"
        f"Claimed dataflow: {claim(has_flow)}.\n"
        f"Resolution note: {resolution or 'not supplied'}.\n"
        "Review the supplied source independently, consider alternative "
        "hypotheses, and state unresolved assumptions and signal limitations."
    )

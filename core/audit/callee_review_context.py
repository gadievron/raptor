"""Shared rendering of advisory prior callee assessments."""
from __future__ import annotations


def render_callee_context(value, *, defend_identifier) -> str:
    """Render only supported assessment fields using the prompt's identifier defence."""
    if isinstance(value, dict) and "assessments" in value:
        return _render_assessment_bundle(value, defend_identifier=defend_identifier)
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


def _render_assessment_bundle(value, *, defend_identifier) -> str:
    from .callee_assessment_context import (MAX_CALLEE_ASSESSMENTS, MAX_CALLEE_ASSUMPTIONS,
                                            assessment_occurrence_anchor)

    rows = value.get("assessments")
    limitations = value.get("limitations", ())
    if (not isinstance(rows, (list, tuple)) or not 1 <= len(rows) <= MAX_CALLEE_ASSESSMENTS
            or not isinstance(limitations, (list, tuple)) or len(limitations) > 16
            or any(not isinstance(note, str) for note in limitations)):
        return ""
    identities = set()
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("file"), str) or not row["file"]
                or not isinstance(row.get("function"), str) or not row["function"]
                or type(row.get("line_start")) is not int or row["line_start"] <= 0
                or row.get("status") not in ("clean", "finding", "suspicious")
                or not isinstance(row.get("assumptions", ()), (list, tuple))
                or len(row.get("assumptions", ())) > MAX_CALLEE_ASSUMPTIONS
                or any(not isinstance(assumption, str) for assumption in row.get("assumptions", ()))):
            return ""
        identity = (row["file"], row["function"], row["line_start"])
        if identity in identities:
            return ""
        identities.add(identity)
    paragraphs = [
        "\n### Related callee assessments",
        "These are advisory prior model assessments, not proof of actual callee behaviour "
        "or confirmation or refutation of a caller concern. Review the supplied source "
        "independently and consider alternative hypotheses. Callee relations and assessment "
        "coverage may be incomplete; only the bounded text below is supplied.",
    ]
    for row in sorted(rows, key=lambda item: (item["file"], item["function"], item["line_start"])):
        file = defend_identifier(row["file"], max_length=512)
        function = defend_identifier(row["function"], max_length=128)
        status = defend_identifier(row["status"], max_length=64)
        hypothesis = defend_identifier(row.get("hypothesis", ""), max_length=400)
        body = defend_identifier(row.get("body", ""), max_length=500)
        scope = defend_identifier(row.get("scope_note", "Original callee source binding unavailable; advisory assessment only."), max_length=512)
        anchor = assessment_occurrence_anchor((row["file"], row["function"], row["line_start"]))
        paragraphs.extend([
            f"\nAssessment occurrence: sha256 {anchor}",
            f"Advisory prior callee assessment for `{file}:{function}:{row['line_start']}`: "
            f"**{status}**: {hypothesis}",
            f"Prior assessment notes: {body or 'not supplied'}.",
            f"Assessment source scope: {scope}",
        ])
        assumptions = sorted(set(row.get("assumptions", ())))
        if assumptions:
            paragraphs.append("Explicit caller assumptions: " + "; ".join(
                defend_identifier(assumption, max_length=300) for assumption in assumptions))
        else:
            paragraphs.append("No explicit caller assumption was recorded for this relation.")
    if limitations:
        paragraphs.append("\nRelation and assessment limitations: " + "; ".join(
            defend_identifier(note, max_length=256) for note in sorted(set(limitations))))
    return "\n".join(paragraphs)

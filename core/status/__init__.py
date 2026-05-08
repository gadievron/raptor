"""Status / verdict string normalisation — single source of truth.

Moved from ``packages/exploitability_validation/orchestrator`` so
``core/llm`` and other shared modules can normalise status strings
without crossing layers (core → packages was a layering inversion;
deferred via inline import but still a runtime cross-package
coupling that broke clean dependency analysis).

Consumers:

* ``packages/exploitability_validation/orchestrator`` — the
  validate pipeline writes findings with normalised status
* ``core/llm/response_validation`` — per-field LLM response
  normalisation pre-emits canonical status before downstream
  consumers see it

Canonical form is snake_case lowercase. Legacy ALL_CAPS, Title Case,
and pre-cleanup variants alias to the canonical form. Unknown
values fall through to a generic lowercase + space/hyphen → underscore
transform so producers of new status values aren't blocked on a
table update.
"""

from typing import Optional


# Alias map: any legacy/mixed-case variant → canonical snake_case.
# Add entries here when upstream producers use a different convention.
_STATUS_ALIASES = {
    # ALL_CAPS legacy (orchestrator pre-cleanup, LLM skill output, docs)
    "EXPLOITABLE": "exploitable",
    "CONFIRMED": "confirmed",
    "CONFIRMED_CONSTRAINED": "confirmed_constrained",
    "CONFIRMED_BLOCKED": "confirmed_blocked",
    "CONFIRMED_UNVERIFIED": "confirmed_unverified",
    "RULED_OUT": "ruled_out",
    "NOT_EXPLOITABLE": "unlikely",
    # Title-case legacy (old feasibility verdicts, LLM output)
    "Exploitable": "exploitable",
    "Confirmed": "confirmed",
    "Ruled Out": "ruled_out",
    "Disproven": "disproven",
    "Not disproven": "not_disproven",
    "Likely exploitable": "likely_exploitable",
    "Difficult": "difficult",
    "Unlikely": "unlikely",
    "Unknown": "unknown",
    "Likely": "likely_exploitable",
    # Passthrough — already canonical
    "exploitable": "exploitable",
    "confirmed": "confirmed",
    "confirmed_constrained": "confirmed_constrained",
    "confirmed_blocked": "confirmed_blocked",
    "confirmed_unverified": "confirmed_unverified",
    "ruled_out": "ruled_out",
    "likely_exploitable": "likely_exploitable",
    "difficult": "difficult",
    "unlikely": "unlikely",
    "unknown": "unknown",
}


def normalize_status(value: Optional[str]) -> Optional[str]:
    """Normalize any status/verdict string to canonical snake_case.

    Handles ALL_CAPS, Title Case, and snake_case inputs.
    Unknown values are lowercased with spaces replaced by underscores.
    Non-string inputs are coerced to string first.
    """
    if not value:
        return value
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    if not value:
        return None
    canonical = _STATUS_ALIASES.get(value)
    if canonical:
        return canonical
    # Fallback: lowercase, replace spaces/hyphens with underscores
    return value.lower().replace(" ", "_").replace("-", "_")


def normalize_findings(data: dict) -> None:
    """Normalize all status/verdict fields in a findings dict in-place."""
    for finding in data.get("findings", []):
        if not isinstance(finding, dict):
            continue
        if finding.get("status"):
            finding["status"] = normalize_status(finding["status"])
        if finding.get("final_status"):
            finding["final_status"] = normalize_status(finding["final_status"])

        ruling = finding.get("ruling")
        if ruling and ruling.get("status"):
            ruling["status"] = normalize_status(ruling["status"])

        feasibility = finding.get("feasibility")
        if feasibility:
            if feasibility.get("verdict"):
                feasibility["verdict"] = normalize_status(feasibility["verdict"])
            if feasibility.get("status"):
                feasibility["status"] = normalize_status(feasibility["status"])


__all__ = ["normalize_status", "normalize_findings"]

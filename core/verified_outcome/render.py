"""Human-readable summary of verified outcomes (operator-facing).

Distinct from ``exemplars.py`` (which renders a prompt block for an LLM):
this renders a terminal/report summary for an operator — "what has RAPTOR
actually confirmed across this run / project, and by which oracle." It is the
command-agnostic value surface for the unified record: confirmations from
/fuzz, /agentic, /crash-analysis, /validate land in one view.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable, List

from core.security.log_sanitisation import escape_nonprintable
from core.verified_outcome.types import Oracle, OutcomeStatus, VerifiedOutcome


def _safe(value, *, cap: int = 200) -> str:
    """Defang an untrusted-derived field for terminal output: coerce, escape
    control chars / newlines (a malicious file path must not inject ANSI or
    spoof the table), length-cap."""
    text = escape_nonprintable(str(value), preserve_newlines=False)
    return text if len(text) <= cap else text[:cap] + "…"

# Title Case for human output (project OUTPUT STYLE: never snake_case or
# ALL_CAPS in terminal/report text).
_STATUS_LABEL = {
    OutcomeStatus.VERIFIED: "Verified",
    OutcomeStatus.REFUTED: "Refuted",
    OutcomeStatus.INCONCLUSIVE: "Inconclusive",
}


def render_outcome_summary(outcomes: Iterable[VerifiedOutcome]) -> str:
    """Render a grouped summary: total, an oracle × status table, and a list
    of the confirmed (Verified) findings. Returns a single trailing-newline
    string; safe on an empty corpus."""
    items: List[VerifiedOutcome] = list(outcomes)
    if not items:
        return "No verified outcomes found.\n"

    lines: List[str] = [f"Verified outcomes: {len(items)} total", ""]

    by = Counter((o.oracle, o.status) for o in items)
    lines.append("By oracle x status:")
    for oracle in Oracle:
        cells = [
            (st, by[(oracle, st)])
            for st in OutcomeStatus
            if by[(oracle, st)]
        ]
        if not cells:
            continue
        cell_str = "  ".join(f"{_STATUS_LABEL[st]}={n}" for st, n in cells)
        lines.append(f"  {oracle.value:<8} {cell_str}")

    verified = [o for o in items if o.status is OutcomeStatus.VERIFIED]
    if verified:
        lines += ["", f"Confirmed ({len(verified)}):"]
        for o in verified:
            fid = _safe(o.finding_id) if o.finding_id else "(unlinked)"
            cwe = _safe(o.cwe_id) if o.cwe_id else "?"
            where = _safe(o.file) if o.file else "?"
            obs = o.evidence.get("observed_outcome", "")
            repro = "reproducible" if o.reproducible else "point-in-time"
            detail = (
                f"{o.oracle.value}: {_safe(obs)}; {repro}"
                if obs else f"{o.oracle.value}; {repro}"
            )
            lines.append(f"  - {fid}  {cwe}  {where}  [{detail}]")

    return "\n".join(lines).rstrip() + "\n"

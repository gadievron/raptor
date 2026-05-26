"""Render RAPTOR's own verified outcomes as prompt exemplars.

The Tier-3 retrieval wire: given a finding under review and the collected
:class:`VerifiedOutcome` corpus, produce a markdown block of the finding's
*nearest previously-confirmed* outcomes. A consumer concatenates this next to
the hand-authored CVE exemplars from ``core.llm.cwe_strategies`` — the
difference is these are RAPTOR's *own ground truth* (oracle-confirmed), so the
set grows and sharpens as RAPTOR runs.

Discipline (mirrors the cwe_strategies "Worked examples" intent): these prime
*how a bug-class manifests and is confirmed here*, not patterns to match. The
verified-outcome record carries the finding/oracle/evidence, not the original
reasoning or exploit code — so the block calibrates, it doesn't hand the model
a template. (Fetching the witness bytes for code-bearing exemplars is a
follow-on; this cut stays store-read-free.)
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.security.log_sanitisation import escape_nonprintable
from core.security.prompt_envelope import neutralize_tag_forgery
from core.verified_outcome.collect import (
    ScoredOutcome,
    collect_outcomes,
    rank_outcomes_for_finding,
)
from core.verified_outcome.types import OutcomeStatus, VerifiedOutcome


def _safe(value: Any, *, cap: int = 120) -> str:
    """Defang an untrusted-derived field value for a prompt.

    Finding metadata — especially ``file`` (a scanned-repo path) and
    ``finding_id`` — originates from outside RAPTOR. The standard prompt
    defense is the envelope (this block is placed inside the consumer's
    untrusted-block envelope), with ``neutralize_tag_forgery`` defanging any
    forged envelope/slot tags in the value. ``escape_nonprintable`` then
    strips control chars / newlines (so a crafted value can't break the
    exemplar line's formatting), and we length-cap. Coercion to str also
    guards the codebase's "dict fields aren't type-guaranteed" hazard.
    """
    text = escape_nonprintable(
        neutralize_tag_forgery(str(value)), preserve_newlines=False,
    )
    return text if len(text) <= cap else text[:cap] + "…"

_HEADER = "## RAPTOR-verified exemplars"
_INTRO = (
    "Findings like this one that RAPTOR has *previously confirmed* by "
    "execution / adjudication. Use them to calibrate how this bug-class "
    "manifests and is confirmed here — not as patterns to match."
)


def _render_one(scored: ScoredOutcome) -> str:
    o = scored.outcome
    label = _safe(o.finding_id) if o.finding_id else "(unlinked)"
    where = " in ".join(_safe(p) for p in (o.cwe_id, o.file) if p) or "unknown location"
    evidence_bits = []
    obs = o.evidence.get("observed_outcome")
    if obs:
        evidence_bits.append(_safe(obs))
    for k in ("signal", "sanitizer"):
        if o.evidence.get(k):
            evidence_bits.append(f"{k}={_safe(o.evidence[k])}")
    evidence = ", ".join(evidence_bits) or "no detail"
    repro = "reproducible" if o.reproducible else "point-in-time (not replayable)"
    # oracle/status are enum values (closed set); reason is RAPTOR-internal.
    return (
        f"**{label} — {where}** (match: {scored.reason})\n"
        f"Confirmed by `{o.oracle.value}` → {o.status.value}; "
        f"evidence: {evidence}; {repro}."
    )


def render_verified_exemplars(
    finding: Dict[str, Any],
    outcomes: Iterable[VerifiedOutcome],
    *,
    top_k: int = 3,
    statuses: Tuple[OutcomeStatus, ...] = (OutcomeStatus.VERIFIED,),
    max_bytes: int = 4096,
) -> str:
    """Render the finding's nearest verified outcomes as a prompt block.

    Returns ``""`` when nothing relevant matches, so callers can concatenate
    unconditionally. Bounded by ``top_k`` (ranking) and ``max_bytes`` (trailing
    entries dropped until within budget; at least one entry is always kept when
    any matched).
    """
    ranked = rank_outcomes_for_finding(
        outcomes, finding, top_k=top_k, statuses=statuses,
    )
    if not ranked:
        return ""

    header = [_HEADER, "", _INTRO, ""]
    entries: List[str] = []
    for s in ranked:
        entries.append(_render_one(s))

    while True:
        block = "\n\n".join(["\n".join(header).rstrip()] + entries).rstrip() + "\n"
        if len(block.encode("utf-8")) <= max_bytes or len(entries) == 1:
            return block
        entries.pop()


def exemplar_block_for_finding(
    finding: Dict[str, Any],
    *,
    outcomes: Optional[Iterable[VerifiedOutcome]] = None,
    output_dir: Any = None,
    use_active_project: bool = True,
    top_k: int = 3,
    statuses: Tuple[OutcomeStatus, ...] = (OutcomeStatus.VERIFIED,),
    max_bytes: int = 4096,
) -> str:
    """Collect (if needed) and render the verified-exemplar block for one
    finding, in a single best-effort call.

    Two modes:

      * **Cached** — pass a pre-collected ``outcomes`` (collect once per run
        via :func:`collect_outcomes`, then call this per finding). Used by
        high-volume consumers like ``/agentic``.
      * **Convenience** — leave ``outcomes`` ``None`` and this collects from
        ``output_dir`` plus, when ``use_active_project``, the active project's
        sibling runs (resolved via ``core.run.output``). Used by lower-volume
        consumers (``/validate`` per finding, ``/understand`` per
        pattern/trace) that don't want to thread a corpus.

    Returns ``""`` on any failure or empty match — callers append
    unconditionally. The active-project resolution is lazy + best-effort so
    importing this module stays cheap and the call never raises.
    """
    try:
        resolved = outcomes
        if resolved is None:
            project_root = None
            if use_active_project:
                try:
                    from pathlib import Path

                    from core.run.output import _resolve_active_project
                    active = _resolve_active_project()
                    if active:
                        project_root = Path(active[0])
                except Exception:
                    project_root = None
            resolved = collect_outcomes(output_dir, project_root=project_root)
        return render_verified_exemplars(
            finding, resolved,
            top_k=top_k, statuses=statuses, max_bytes=max_bytes,
        )
    except Exception:
        return ""

"""Finding-survival metric: per-evidence-channel /validate outcomes.

Pure read-side aggregation over the review journal — no behaviour
change to the audit loop.  ``core.audit.feedback`` (the Reflexion
import) appends correction entries carrying ``validate_verdict``
(``confirmed`` / ``disproven`` / ``unknown``) and ``prior_review``;
the original review entries carry ``evidence_tools`` (e.g.
``"smt:check-overflow"``, ``"semgrep:<rule>"``,
``"llm-claimed:<hypothesis>"``, ``"prefilter:<pattern>"``).

This module joins the two by ``file:function`` and counts, per
evidence CHANNEL (the prefix of the evidence tool before the first
``:``), how many audit claims survived /validate versus were
disproven.  That answers "which evidence channel's confirmations
actually hold up?" — the ground-truth feedback signal for tuning
the tool chain.

Notes on the join:

* Only corrections whose ``prior_review`` was a claim (``finding`` /
  ``suspicious``) count — a ``clean`` verdict later confirmed by
  /validate is a *miss*, not a surviving claim, and carries no
  evidence channel to credit.
* Correction entries themselves don't carry ``evidence_tools``; the
  channels come from the latest earlier journal entry for the same
  key that has them.  Claims with no recorded evidence tool are
  bucketed under ``"(none)"``.
* A claim backed by several tools of the same channel counts once
  per channel; a claim backed by several channels counts once in
  EACH channel (each channel made the claim).
* The most recent correction per key wins — re-validation supersedes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .journal import ReviewJournalEntry

logger = logging.getLogger(__name__)

# Journal verdicts that constitute an audit claim /validate can
# adjudicate.  ``clean`` / ``dormant`` are non-claims.
CLAIM_VERDICTS = frozenset({"finding", "suspicious"})

# Channel bucket for claims recorded without any evidence tool.
NO_CHANNEL = "(none)"


def _channels(evidence_tools: list[str]) -> set[str]:
    """Distinct channel prefixes for a claim's evidence tools."""
    out: set[str] = set()
    for tool in evidence_tools or []:
        tool = str(tool).strip()
        if not tool:
            continue
        out.add(tool.split(":", 1)[0].strip().lower() or NO_CHANNEL)
    return out or {NO_CHANNEL}


def aggregate_survival(out_dir: Path) -> dict[str, dict[str, int]]:
    """Aggregate /validate survival per evidence channel.

    Args:
        out_dir: Audit run directory containing
            ``review-journal.jsonl``.

    Returns:
        ``{channel: {"survived": n, "disproven": n, "unknown": n}}``.
        Empty dict when the journal is missing or carries no
        /validate corrections for claims.
    """
    try:
        from .journal import load_entries
        entries = load_entries(Path(out_dir))
    except Exception:  # read-side metric, never raise
        logger.debug("survival: journal load failed", exc_info=True)
        return {}
    if not entries:
        return {}

    # Latest correction per key: a correction is an entry with a
    # validate_verdict whose prior_review was a claim.
    corrections: dict[str, ReviewJournalEntry] = {}
    for e in entries:
        if not e.validate_verdict:
            continue
        if (e.prior_review or "").strip().lower() not in CLAIM_VERDICTS:
            continue
        prev = corrections.get(e.key)
        if prev is None or e.ts > prev.ts:
            corrections[e.key] = e

    if not corrections:
        return {}

    # Latest evidence_tools-bearing entry per key at each timestamp —
    # walk once, keep the newest entry with tools no newer than the
    # correction.  (Corrections themselves rarely carry tools; when
    # they do, they win.)
    tools_by_key: dict[str, list[ReviewJournalEntry]] = {}
    for e in entries:
        if not e.evidence_tools:
            continue
        tools_by_key.setdefault(e.key, []).append(e)

    result: dict[str, dict[str, int]] = {}
    for key, corr in corrections.items():
        source = None
        if corr.evidence_tools:
            source = corr
        else:
            candidates = [
                e for e in tools_by_key.get(key, []) if e.ts <= corr.ts
            ]
            if candidates:
                source = max(candidates, key=lambda e: e.ts)

        channels = _channels(source.evidence_tools if source else [])
        verdict = (corr.validate_verdict or "").strip().lower()
        if verdict == "confirmed":
            bucket = "survived"
        elif verdict == "disproven":
            bucket = "disproven"
        else:
            bucket = "unknown"

        for channel in channels:
            counts = result.setdefault(
                channel, {"survived": 0, "disproven": 0, "unknown": 0},
            )
            counts[bucket] += 1

    return result


def format_survival(agg: dict[str, dict[str, int]]) -> list[str]:
    """Human-readable lines for the survival table.

    Sorted by adjudicated volume descending so the busiest channel
    reads first.  Survival rate excludes ``unknown`` verdicts from
    the denominator — they are unadjudicated, not evidence either way.
    """
    lines: list[str] = []
    if not agg:
        return lines

    def _volume(item: tuple[str, dict[str, int]]) -> tuple[int, str]:
        channel, c = item
        return (-(c["survived"] + c["disproven"] + c["unknown"]), channel)

    lines.append("Finding survival by evidence channel (/validate):")
    for channel, c in sorted(agg.items(), key=_volume):
        adjudicated = c["survived"] + c["disproven"]
        if adjudicated:
            rate = f"{c['survived'] * 100.0 / adjudicated:.0f}%"
        else:
            rate = "n/a"
        extra = f", {c['unknown']} unknown" if c["unknown"] else ""
        lines.append(
            f"  {channel}: {c['survived']} survived / "
            f"{c['disproven']} disproven (survival {rate}{extra})"
        )
    return lines

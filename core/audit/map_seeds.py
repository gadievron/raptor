"""Hypothesis seeding from the run's own context map.

The /understand map phase records sink details with reachability
prose (``reaches_from``) and analyst notes that can state a finding
in all but name — e.g. a redirect sink whose note names
client-controllable headers reaching the redirect base. Before this
seeder, nothing converted those records into review hypotheses: if
the named function fell out of every review pass, the map's own
signal died in context-map.json.

Seeding is hint-tier by construction (the fix_history /
consistency-prepass ``injected_hypotheses`` precedent): hypotheses
are cheap, the review must still confirm or refute each one against
the code, and verdicts stay with the tools — G1 holds because the
hypothesis exists before any finding. The context map is
LLM-produced text over attacker-visible source: mechanism strings
are rendered through the injected-hypotheses prompt section, which
neutralises tag forgery and charset-restricts confidence/source.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

SEED_SOURCE = "context_map_sink"

# Bounded prompt surface: per-gap and per-run caps keep a huge or
# hostile sink table from flooding every review prompt.
MAX_SEEDS_PER_GAP = 2
MAX_SEEDS_PER_RUN = 40
_MECHANISM_MAX = 300

# Function names quoted in a sink record's ``reaches_from`` prose —
# ``resolve_base() (…)`` names the function whose review should test
# the reachability claim. The call paren must be adjacent and the
# name length bounded: the record text is LLM-written over hostile
# source, so the scanning pattern keeps no unbounded repeat with a
# failable continuation (ReDoS-idiom census discipline).
_REACHES_FN = re.compile(r"\b([A-Za-z_]\w{2,127})\(")


def _sink_records(context_map: dict[str, Any]) -> list[dict[str, Any]]:
    """Detail-bearing sink records. ``sink_details`` carries the rich
    schema (id/file/line/function/reaches_from/notes); the legacy
    ``sinks`` list of ``{type, location}`` pairs is accepted as a
    degraded fallback."""
    details = context_map.get("sink_details")
    if isinstance(details, list) and any(
            isinstance(s, dict) for s in details):
        return [s for s in details if isinstance(s, dict)]
    out: list[dict[str, Any]] = []
    for s in context_map.get("sinks") or []:
        if not isinstance(s, dict):
            continue
        loc = str(s.get("location") or "")
        file_part, _, line_part = loc.rpartition(":")
        try:
            line = int(line_part)
        except ValueError:
            file_part, line = loc, 0
        out.append({
            "type": s.get("type", ""),
            "file": file_part,
            "line": line,
        })
    return out


def _mechanism(record: dict[str, Any]) -> str:
    parts: list[str] = []
    rid = str(record.get("id") or "").strip()
    rtype = str(record.get("type") or "").strip()
    head = "context-map sink"
    if rid:
        head += f" {rid}"
    if rtype:
        head += f" ({rtype})"
    parts.append(head)
    for key, label in (
        ("operation", "operation"),
        ("reaches_from", "reaches from"),
        ("notes", "notes"),
    ):
        val = str(record.get(key) or "").strip()
        if val:
            parts.append(f"{label}: {val}")
    return "; ".join(parts)[:_MECHANISM_MAX]


def _gap_index(
    gaps: list[dict[str, Any]],
) -> tuple[dict[tuple[str, str], list], dict[str, list], dict[str, list]]:
    by_key: dict[tuple[str, str], list] = {}
    by_name: dict[str, list] = {}
    by_file: dict[str, list] = {}
    for gap in gaps:
        by_key.setdefault(
            (gap.get("file", ""), gap.get("name", "")), [],
        ).append(gap)
        by_name.setdefault(gap.get("name", ""), []).append(gap)
        by_file.setdefault(gap.get("file", ""), []).append(gap)
    return by_key, by_name, by_file


def seed_map_sink_hypotheses(
    gaps: list[dict[str, Any]],
    context_map: dict[str, Any] | None,
) -> int:
    """Attach hint-tier hypotheses derived from context-map sink
    records to their gaps (``injected_hypotheses``, the shared
    render/dispatch surface). Returns the number seeded.

    A record seeds up to three gap classes:

    * the record's own ``(file, function)`` item;
    * the gap whose span contains the record's ``(file, line)`` —
      covers records attributed to module-level code;
    * every function the ``reaches_from`` prose names — the map's
      reachability claim is exactly what that function's review must
      test (dead code excluded: a hypothesis cannot resurrect a gap
      the reachability gates retired).

    Dedup: one hypothesis per (gap, mechanism) — re-runs and
    overlapping match classes never double-seed — and per-gap /
    per-run caps bound the prompt surface.
    """
    if not gaps or not isinstance(context_map, dict):
        return 0
    records = _sink_records(context_map)
    if not records:
        return 0
    by_key, by_name, by_file = _gap_index(gaps)

    seeded = 0
    for record in records:
        if seeded >= MAX_SEEDS_PER_RUN:
            logger.info(
                "map-sink seeding: run cap (%d) reached — remaining "
                "sink records not seeded", MAX_SEEDS_PER_RUN,
            )
            break
        mechanism = _mechanism(record)
        if not mechanism:
            continue
        file_val = str(record.get("file") or "")
        func_val = str(record.get("function") or "")
        line_val = record.get("line") or 0

        candidates: list[dict[str, Any]] = []
        candidates.extend(by_key.get((file_val, func_val), []))
        if isinstance(line_val, int) and line_val > 0:
            for gap in by_file.get(file_val, []):
                lo = gap.get("line_start") or 0
                hi = gap.get("line_end") or 0
                if lo and hi and lo <= line_val <= hi:
                    candidates.append(gap)
        for fn in dict.fromkeys(
                _REACHES_FN.findall(str(record.get("reaches_from") or ""))):
            candidates.extend(by_name.get(fn, []))

        seen_ids: set[int] = set()
        for gap in candidates:
            if id(gap) in seen_ids:
                continue
            seen_ids.add(id(gap))
            if gap.get("dead"):
                # Reachability-retired gaps stay retired — a map note
                # is a hint, never reachability evidence.
                continue
            existing = gap.setdefault("injected_hypotheses", [])
            if any(
                h.get("mechanism") == mechanism
                and h.get("source") == SEED_SOURCE
                for h in existing if isinstance(h, dict)
            ):
                continue
            own = sum(
                1 for h in existing
                if isinstance(h, dict) and h.get("source") == SEED_SOURCE
            )
            if own >= MAX_SEEDS_PER_GAP:
                continue
            if seeded >= MAX_SEEDS_PER_RUN:
                break
            existing.append({
                "mechanism": mechanism,
                "confidence": "low",
                "source": SEED_SOURCE,
            })
            seeded += 1
    return seeded

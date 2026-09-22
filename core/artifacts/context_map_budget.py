"""Producer-side size budget for context-map.json.

Consumers bound their reads of the map (``load_json(...,
max_bytes=CONTEXT_MAP_CONSUMER_MAX_BYTES)``); an artifact past that cap
is not partially read — the reader loses the WHOLE map, and several
readers treat that as best-effort (the audit orchestrator swallows the
failure, so the run silently proceeds mapless). Producers must therefore
keep the serialized artifact under ``CONTEXT_MAP_PRODUCER_BUDGET_BYTES``
— deliberately below the consumer cap so post-write growth (another
enricher pass, provenance stamping, re-serialisation differences between
encoders) cannot push a budget-conformant map over the read cap.

Mechanically synthesized inventory entries are the dominant growth term
on large targets: library-surface backfill emits one entry point per
exported function, and the ast-view / forward-reachable enrichers then
attach per-entry payloads to each. Degradation therefore sheds the
machine-recoverable synthesized payloads first and never touches
LLM-authored (narrative) entries — those cannot be regenerated from the
inventory.

Compact serialization is the FIRST budget lever, and it is lossless:
indented serialization of a large map can exceed both the producer
budget and the consumer read cap while the compact encoding of the
same data fits. Consumers cap on FILE bytes, so budget enforcement
measures the compact encoding and :func:`save_context_map` writes
exactly that encoding — measurement and on-disk artifact can never
disagree. The artifact is machine-consumed (every reader parses it;
diagram and review surfaces re-render from the parsed data), so
nothing needs the indented form and the map is always written compact.
Lossy degradation runs only when even the compact form is over budget.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from core.atomic_fs import write_text_atomically
from core.json import dumps_artifact

logger = logging.getLogger(__name__)

# Consumer read cap. Referenced by every bounded context-map reader so
# the read bound and the producer budget can never drift apart silently.
CONTEXT_MAP_CONSUMER_MAX_BYTES = 64 * 1024 * 1024

# Producer target — must stay below the consumer cap with headroom
# (see module docstring for why the gap exists).
CONTEXT_MAP_PRODUCER_BUDGET_BYTES = 48 * 1024 * 1024

# ``origin`` values stamped on mechanically synthesized entries
# (library-surface entry-point backfill). Everything else is treated as
# LLM-authored and is never degraded.
_SYNTHESIZED_ORIGINS = frozenset({"inventory-entry"})

# ``source`` values stamped on machine-generated sink entries (the sink
# enricher's call-graph discovery and heuristic project sinks). Fully
# regenerable by re-running the enricher; LLM-authored sinks carry no
# such stamp and are never degraded.
_MACHINE_SINK_SOURCES = frozenset({"mechanical", "heuristic"})

# Sink-carrying arrays the machine-sink cap may shrink.
_SINK_KEYS = ("sinks", "sink_details")


def _is_synthesized(entry: Any) -> bool:
    return isinstance(entry, dict) and entry.get("origin") in _SYNTHESIZED_ORIGINS


def _is_machine_sink(entry: Any) -> bool:
    return (isinstance(entry, dict)
            and entry.get("source") in _MACHINE_SINK_SOURCES)


def _serialized_size(data: Any) -> int:
    """Size of *data* in the compact artifact encoding.

    Must match what :func:`save_context_map` writes: measuring a
    prettier encoding overstates the artifact and triggers lossy
    drops a lossless compact re-encoding would have avoided (the
    pre-fix failure mode — indented measurement degraded maps whose
    compact form fit both caps). Key order does not change compact
    length, so the measurement is exact regardless of ``sort_keys``.
    """
    return len(dumps_artifact(data, indent=None).encode("utf-8"))


def _entries(context_map: dict[str, Any], key: str) -> list[Any]:
    v = context_map.get(key)
    return v if isinstance(v, list) else []


def _drop_synth_ast_views(context_map: dict[str, Any]) -> int:
    dropped = 0
    for entry in _entries(context_map, "entry_points"):
        if _is_synthesized(entry) and "ast_view" in entry:
            del entry["ast_view"]
            dropped += 1
    return dropped


def _drop_synth_reachable_names(context_map: dict[str, Any]) -> int:
    dropped = 0
    for entry in _entries(context_map, "entry_points"):
        if not _is_synthesized(entry):
            continue
        fr = entry.get("forward_reachable")
        if not isinstance(fr, dict):
            continue
        if not (fr.get("internal_names") or fr.get("external_names")):
            continue
        fr["internal_names"] = []
        fr["external_names"] = []
        # Counts stay authoritative; the flag records that the name
        # lists are no longer the full closure.
        fr["truncated"] = True
        dropped += 1
    return dropped


def _cap_list_entries(
    entries: list[Any],
    candidate_indices: list[int],
    overshoot: int,
) -> int:
    """Drop candidates from the tail until ``overshoot`` bytes are shed.

    Tail-first keeps the earliest entries (stable ids from the
    producers' emission order). Returns the number removed.
    """
    if not candidate_indices or overshoot <= 0:
        return 0
    removed: list[int] = []
    shed = 0
    for i in reversed(candidate_indices):
        if shed >= overshoot:
            break
        # Per-entry serialized size understates the true saving (list
        # separators) — acceptable: the caller re-checks the real size
        # and the budget already carries headroom.
        shed += _serialized_size(entries[i])
        removed.append(i)
    for i in removed:  # already in descending index order
        del entries[i]
    return len(removed)


def _cap_machine_sinks(context_map: dict[str, Any],
                       budget_bytes: int) -> int:
    """Drop machine-generated sink entries until the map fits.

    Applies to every sink-carrying array; LLM-authored sinks (no
    machine ``source`` stamp) are never candidates. Returns the total
    number of entries removed.
    """
    removed = 0
    for key in _SINK_KEYS:
        entries = _entries(context_map, key)
        candidates = [i for i, e in enumerate(entries)
                      if _is_machine_sink(e)]
        # Candidates first: serializing the whole map costs hundreds
        # of ms on budget-sized artifacts — never pay it for a key
        # with nothing to shed.
        if not candidates:
            continue
        overshoot = _serialized_size(context_map) - budget_bytes
        if overshoot <= 0:
            break
        removed += _cap_list_entries(entries, candidates, overshoot)
    return removed


def _cap_synth_entries(context_map: dict[str, Any],
                       budget_bytes: int) -> int:
    """Drop synthesized entry points from the tail until the map fits.

    Non-synthesized entries are never candidates. Returns the number
    of entries removed.
    """
    eps = _entries(context_map, "entry_points")
    synth_indices = [i for i, e in enumerate(eps) if _is_synthesized(e)]
    if not synth_indices:
        return 0
    overshoot = _serialized_size(context_map) - budget_bytes
    return _cap_list_entries(eps, synth_indices, overshoot)


def enforce_context_map_budget(
    context_map: dict[str, Any],
    *,
    budget_bytes: int = CONTEXT_MAP_PRODUCER_BUDGET_BYTES,
) -> list[str]:
    """Degrade ``context_map`` in place until it serializes within budget.

    Sizes are of the COMPACT artifact encoding — the form
    :func:`save_context_map` puts on disk. A map whose indented
    serialization is over budget but whose compact form fits is
    therefore NOT degraded: compact re-encoding is the first, lossless
    lever, and these lossy steps apply only past it.

    Progressive, cheapest-loss first — each step only runs when the map
    is still over budget after the previous one:

    1. Drop ``ast_view`` payloads on synthesized entry points (fully
       recoverable by re-running the ast-view enricher).
    2. Drop ``forward_reachable`` name lists on synthesized entry points
       (counts survive; ``truncated`` flags the loss).
    3. Cap machine-generated sink entries (``source`` mechanical /
       heuristic — regenerable by re-running the sink enricher).
    4. Cap the number of synthesized entry points themselves.

    LLM-authored entries are untouched at every step. Returns the list
    of applied degradation descriptions (empty when the map already
    fits); the summary is also logged once, loudly, at INFO.
    """
    if not isinstance(context_map, dict):
        return []
    size = _serialized_size(context_map)
    if size <= budget_bytes:
        return []
    original_size = size
    applied: list[str] = []

    n = _drop_synth_ast_views(context_map)
    if n:
        applied.append(f"dropped ast_view on {n} synthesized entry point(s)")
        size = _serialized_size(context_map)

    if size > budget_bytes:
        n = _drop_synth_reachable_names(context_map)
        if n:
            applied.append(
                f"dropped forward_reachable name lists on {n} synthesized "
                "entry point(s) (counts kept, truncated flagged)")
            size = _serialized_size(context_map)

    if size > budget_bytes:
        n = _cap_machine_sinks(context_map, budget_bytes)
        if n:
            applied.append(
                f"capped machine-generated sink entries ({n} dropped)")
            size = _serialized_size(context_map)

    if size > budget_bytes:
        n = _cap_synth_entries(context_map, budget_bytes)
        if n:
            applied.append(f"capped synthesized entry points ({n} dropped)")
            size = _serialized_size(context_map)

    if applied:
        logger.info(
            "context-map size budget: %d compact-encoded bytes exceeded "
            "the %d-byte producer budget (consumer read cap %d) — %s; "
            "now %d bytes",
            original_size, budget_bytes, CONTEXT_MAP_CONSUMER_MAX_BYTES,
            "; ".join(applied), size,
        )
    if size > budget_bytes:
        # Every degradable class (synthesized entry-point payloads and
        # entries, machine-stamped sinks) has been exhausted; whatever
        # remains carries no machine provenance stamp and is never
        # dropped here. Consumers bounded at the read cap may refuse
        # the artifact; say so rather than silently shipping it.
        logger.warning(
            "context-map size budget: still %d compact-encoded bytes "
            "after degradation (budget %d) — remaining content carries "
            "no machine provenance stamp (treated as LLM-authored) and "
            "is never dropped here", size, budget_bytes,
        )
    return applied


def save_context_map(
    path: str | Path,
    context_map: dict[str, Any],
    *,
    sort_keys: bool = False,
    budget_bytes: int = CONTEXT_MAP_PRODUCER_BUDGET_BYTES,
    mode: int | None = None,
) -> list[str]:
    """Write ``context_map`` to ``path`` in the compact producer
    encoding, budget-enforcing (in place) first.

    THE write chokepoint for ``context-map.json`` (and its
    binary-analysis twin): producers must not route the map through a
    pretty-printing writer, because consumers cap on FILE bytes and
    indented serialization can exceed budgets a compact encoding of
    the same data fits — the enforcement measurement and the artifact
    must use the same encoding. Always compact: the artifact is
    machine-consumed (readers parse it; diagram / review surfaces
    re-render from the parsed data), so no consumer needs indentation,
    and a single encoding keeps measurement equal to disk bytes by
    construction.

    Atomic write (tempfile + rename) like ``save_json``. Returns the
    list of lossy degradation descriptions applied — empty when the
    compact encoding alone fit the budget.
    """
    applied = enforce_context_map_budget(
        context_map, budget_bytes=budget_bytes,
    )
    write_text_atomically(
        path,
        dumps_artifact(context_map, indent=None, sort_keys=sort_keys) + "\n",
        tmp_prefix=".~savejson-",
        mode=mode,
    )
    return applied


__all__ = [
    "CONTEXT_MAP_CONSUMER_MAX_BYTES",
    "CONTEXT_MAP_PRODUCER_BUDGET_BYTES",
    "enforce_context_map_budget",
    "save_context_map",
]

"""Uniformly-weak family reporting: the all-members-weak case.

The deviance comparators are majority machines — a family of ten
validators ALL missing the auth check produces zero deviants and,
until now, zero report (``find_asymmetries`` skips uniform families
by design). This module emits the missing record for exactly that
case, deliberately minimal and bounded:

* **Mechanically-certain families only** — interface-slot (L7) and
  route (L10) groups, the layers whose membership is a mechanical
  fact. A verb-prefix or similarity family with a uniformly-absent
  property proves nothing (the grouping itself is heuristic).
* **Auth-class and bounds-class properties only** — the two property
  classes where "all N lack it" is a review-worthy fact on its own.
  The property detectors are the in-tree syntactic regexes the parity
  comparator already votes with (imported, never twinned).
* **Hint tier, never a verdict** — the record says "property absent
  in all N members; unexamined ≠ safe". It is review structure: the
  detectors are syntactic, absence of a regex hit is not absence of
  protection, and a uniform family has no majority to lean on. No
  finding, no status, no priority movement — a hostile repo could
  otherwise mint uniform families to steer attention budgets.

This also blunts the manufactured-consistent-majority attack: a
planted family whose consistent majority is itself weak now surfaces
for review instead of hiding behind an innocent decoy deviant. The
residual — manufactured majorities in property classes this module
does not cover — stays a documented limit, not a silent one.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Group types whose membership is mechanically certain. Literal
# strings by the consistency-dimension convention; pinned against the
# owning layers' constants by test.
_CERTAIN_GROUP_TYPES = frozenset({"interface_slot", "route_family"})

# Property classes reported when uniformly absent. The scan reuses
# the parity comparator's own body detectors so "absent" means the
# same thing in the majority vote and in this record.
_ABSENCE_PROPERTIES = ("auth_check", "bounds_guard")

#: Records emitted per run. Both directions: more lets a generated
#: tree of certain-membership families (an ops struct per file) turn
#: the review stream into uniform-absence noise; fewer hides real
#: all-weak surfaces on large targets. 20 — the record is a whole-
#: family review obligation, an order heavier than a per-function
#: lead, so it gets half the 40-lead budget class.
MAX_UNIFORM_ABSENCE_RECORDS = 20

#: Member exhibits carried per record (the PeerEvidence MAX_EXHIBITS
#: class): enough to start review, bounded so one wide family cannot
#: dominate the prompt.
_MAX_MEMBER_EXHIBITS = 5


def uniform_absence_records(
    source_texts: dict[str, str],
    peer_groups: list[Any] | None,
    *,
    min_group: int = 3,
) -> list[dict[str, Any]]:
    """Uniform-absence records over the mechanically-certain families.

    For each eligible group with at least *min_group* resolved member
    bodies: when EVERY resolved member lacks a scanned property, emit
    one record for that (group, property). Members without resolvable
    bodies do not vote — and a family with any unresolved member is
    skipped for that run (an absence claim over a partially-read
    family would overstate what was examined).

    Returns plain dicts (hint-tier records — the prepass carries them
    beside, never inside, the deviance leads).
    """
    if not peer_groups:
        return []
    from .consistency_dimensions import (
        function_spans,
        interface_properties,
    )

    spans = function_spans(source_texts)
    by_key: dict[tuple[str, str], tuple[int, str]] = {}
    by_name: dict[str, tuple[str, int, str]] = {}
    ambiguous_names: set[str] = set()
    for file_path, name, start, lines in spans:
        body = "\n".join(lines)
        by_key.setdefault((file_path, name), (start, body))
        # Bare-name fallback uses the resolver's ambiguity-excluding
        # rule: a name defined in several files binds NOTHING (an
        # arbitrary first-seen body could vote absence for the wrong
        # function); the member then counts as unresolved, which
        # poisons the family's claim — under-reports, never lies.
        if name in by_name and by_name[name][0] != file_path:
            ambiguous_names.add(name)
        by_name.setdefault(name, (file_path, start, body))
    for name in ambiguous_names:
        del by_name[name]

    records: list[dict[str, Any]] = []
    capped = False
    for group in peer_groups:
        gtype = getattr(group, "sibling_type", "")
        gtype = getattr(gtype, "value", gtype)
        if gtype not in _CERTAIN_GROUP_TYPES:
            continue
        siblings = list(getattr(group, "siblings", []) or [])
        if len(siblings) < min_group:
            continue
        # Family-size ceiling: unlike the majority comparators (which
        # vote over an unchoosable SAMPLE of an oversized family —
        # consistency_dimensions.MAX_FAMILY_MEMBERS), an absence
        # claim quantifies over the WHOLE family, so sampling would
        # lie. The certain-membership layers cap at formation; a
        # larger group here means an unbounded producer — refuse it.
        from .consistency_dimensions import MAX_FAMILY_MEMBERS
        if len(siblings) > MAX_FAMILY_MEMBERS:
            continue

        resolved: list[tuple[Any, int, str]] = []
        unresolved = 0
        for s in siblings:
            hit = by_key.get((s.file, s.function))
            if hit is not None:
                resolved.append((s, hit[0], hit[1]))
                continue
            named = by_name.get(s.function)
            if named is not None:
                resolved.append((s, named[1], named[2]))
            else:
                unresolved += 1
        # An absence claim quantifies over the WHOLE family; a member
        # the run could not read must poison the claim, not shrink it.
        if unresolved or len(resolved) < min_group:
            continue

        props = [
            interface_properties(body) for _s, _line, body in resolved
        ]
        for prop in _ABSENCE_PROPERTIES:
            if any(p.get(prop) for p in props):
                continue
            if len(records) >= MAX_UNIFORM_ABSENCE_RECORDS:
                capped = True
                break
            members = [
                {
                    "file": s.file,
                    "function": s.function,
                    "line": line,
                }
                for s, line, _body in resolved
            ]
            records.append({
                "kind": "uniform_absence",
                "group_id": getattr(group, "group_id", ""),
                "group_type": gtype,
                "property": prop,
                "n": len(resolved),
                "members": members[:_MAX_MEMBER_EXHIBITS],
                "members_total": len(members),
                # Hint tier by construction: syntactic detectors, no
                # majority, no verdict. Consumers must never promote
                # or classify on this record alone.
                "tier": "hint",
                "description": (
                    f"{prop} absent in all {len(resolved)} members of "
                    f"{getattr(group, 'group_id', '')} — a uniform "
                    f"family produces no deviant; unexamined is not "
                    f"safe"
                ),
            })
        if capped:
            break

    if capped:
        logger.info(
            "uniform-absence reporting capped at %d records",
            MAX_UNIFORM_ABSENCE_RECORDS,
        )
    if records:
        logger.info(
            "uniform-absence: %d record(s) over certain-membership "
            "families", len(records),
        )
    return records


def seed_uniform_absence(
    gaps: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> int:
    """Attach each record to its member gaps (gap-extra-key pattern,
    the ``consistency_leads`` precedent). Hint tier: no priority
    movement — the record informs review, it never steers the queue.
    """
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for rec in records:
        for m in rec.get("members") or []:
            by_key.setdefault(
                (m.get("file", ""), m.get("function", "")), [],
            ).append(rec)
    seeded = 0
    for gap in gaps:
        key = (gap.get("file", ""), gap.get("name", ""))
        for rec in by_key.get(key, []):
            gap.setdefault("uniform_absence", []).append(rec)
            seeded += 1
    return seeded

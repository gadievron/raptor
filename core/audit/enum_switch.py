"""Enum×switch completeness census (C/C++ first).

"Five switches over ``enum pkt_kind`` handle ``PKT_RESET``; the sixth
doesn't." The string-dispatch cross-ref (``dispatch_completeness``)
cannot see this — its keys are string literals. This census joins the
enum-DEFINITION extractor to the enum-labelled-switch extractor (both
in ``ts_extract``) and votes member presence across the peer switches
of one enum.

Verdict discipline (unchanged from every other dimension): the census
is a majority statistic — deviations are detection-grade leads under
the single consistency namespace (``consistency:enum-switch-majority``)
and NEVER classify code on their own. Non-exhaustive idioms and
degraded inputs are enumerated inconclusive reasons, never guesses:

* ``non_exhaustive_idiom_default`` — the deviant switch carries a
  ``default:`` arm; the member is handled by construction, so no lead.
* ``uniformly_missing_member`` — no peer handles the member; there is
  no majority to lean on (the all-weak case is P8 territory, and the
  produced-but-never-dispatched claim stays with the string
  cross-ref).
* ``definition_ambiguous`` — two same-named enum definitions disagree
  on members (version skew or a hostile tree); the census refuses the
  enum rather than picking a side.
* ``enum_ambiguous`` — a switch's labels fit several enums; joining
  it anywhere would be a guess.
* ``census_degraded`` — the enum's member collection hit the
  extractor cap; an absence claim over a partial member set lies, so
  the enum is excluded loudly (the field-census tier-degradation
  contract).

Hostile-repo bounds: both matrix axes are macro-generatable (X-macro
floods), so the census caps enums, switches per enum, and total
presence-matrix work, each with an in-band ``caps_hit`` marker —
degradation is said, never silent. The per-enum switch cap keeps
SEEDED-RANDOM survivors, never a deterministic prefix: switches
arrive in sorted-file order, and a first-N cut would let a flood of
conforming decoys in early-sorting file names evict the real deviant.

Named residual (definition-scope suppression): definitions merge
GLOBALLY by enum name. One planted header redefining a real enum
with a different member set drives ``definition_ambiguous`` and
silences every lead for that enum; legitimately distinct same-name
file-local enums lose coverage the same way. The honest fix is
translation-unit-scoped definition resolution, which needs include
graphs the census deliberately does not build — until then the
``definition_ambiguous`` counter in the run telemetry is the
operator's signal that an enum was refused rather than censused.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from .peer_evidence import PeerEvidence, PeerExhibit

logger = logging.getLogger(__name__)

DIMENSION_ENUM_SWITCH = "enum-switch"

# Peer-switch floor and majority ratio for a missing-member lead.
# Inline per the threshold-residence convention (both-direction
# rationale; registry-enumerated in consistency_stats, overridable via
# the audit run-config only). 3/0.75 are the engine-wide group floors:
# below three peers a "majority" is one switch outvoting another; a
# lower ratio flags legitimate subset-switches (handlers that only see
# a phase's members), a higher one hides real drift in small families.
ENUM_SWITCH_MIN_GROUP = 3
ENUM_SWITCH_RATIO = 0.75

#: Switches joined per enum. Both directions: more lets a generated
#: tree make one enum's presence matrix the run's dominant cost;
#: fewer under-counts genuinely hot protocol enums. 200 — with the
#: member cap this bounds one family's matrix at 256×200 checks.
MAX_SWITCHES_PER_ENUM = 200

#: Enum families censused per run. Both directions: more admits an
#: enum-per-file flood; fewer drops real enums on large C trees.
#: 500 mirrors the interface-slot census cap class.
MAX_ENUM_FAMILIES = 500

#: Total presence-matrix work per run (member×switch membership
#: checks). Both axes are attacker-generatable, and the per-family
#: caps still admit 500×256×200 in the worst shape — the run-level
#: budget keeps the census inside the prepass's wall-clock class.
#: Both directions: higher re-opens the DoS; lower truncates the
#: census on legitimately enum-heavy trees (truncation is marked
#: in-band and excludes the untouched enums, never partial-silent).
MAX_PRESENCE_OPS = 1_000_000


@dataclass
class EnumSwitchDeviation:
    """One switch missing a member its peer switches handle."""

    enum_name: str
    missing_member: str
    file: str
    line: int
    enclosing_function: str
    n: int
    conforming: int
    cwe: str = "CWE-478"
    peer_evidence: PeerEvidence | None = None

    @property
    def ratio(self) -> float:
        return self.conforming / self.n if self.n else 0.0

    @property
    def description(self) -> str:
        return (
            f"{self.conforming}/{self.n} switches over "
            f"{self.enum_name} handle {self.missing_member}; the "
            f"switch in {self.enclosing_function} does not (and has "
            f"no default arm)"
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "enum": self.enum_name,
            "missing_member": self.missing_member,
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "n": self.n,
            "conforming": self.conforming,
            "ratio": round(self.ratio, 3),
            "cwe": self.cwe,
        }
        if self.peer_evidence is not None:
            d["peer_evidence"] = self.peer_evidence.to_dict()
        return d


# Per-file extraction memo shared by the census and the L8 cohort
# producer (they run in different prep phases over the same texts;
# without the memo each file's switch walk ran twice). Keyed on
# (path, content hash) like ts_extract's parse cache; bounded LRU.
_EXTRACT_CACHE: OrderedDict[tuple[str, str], tuple[Any, Any]] = (
    OrderedDict()
)
_EXTRACT_CACHE_MAX = 256
_EXTRACT_CACHE_LOCK = threading.Lock()


def _extract_file(path: str, text: str) -> tuple[Any, Any]:
    """(definitions, switches) for one file, memoised on content."""
    from .ts_extract import (
        extract_enum_definitions,
        extract_enum_switches,
    )

    key = (path, hashlib.sha256(
        text.encode("utf-8", "replace"),
    ).hexdigest())
    with _EXTRACT_CACHE_LOCK:
        cached = _EXTRACT_CACHE.get(key)
        if cached is not None:
            _EXTRACT_CACHE.move_to_end(key)
            return cached
    result = (
        extract_enum_definitions(path, text),
        extract_enum_switches(path, text),
    )
    with _EXTRACT_CACHE_LOCK:
        _EXTRACT_CACHE[key] = result
        _EXTRACT_CACHE.move_to_end(key)
        while len(_EXTRACT_CACHE) > _EXTRACT_CACHE_MAX:
            _EXTRACT_CACHE.popitem(last=False)
    return result


def _extract_enum_data(
    source_texts: dict[str, str],
    reasons: dict[str, int],
) -> tuple[dict[str, Any], list[Any]]:
    """Merged enum definitions + all enum-labelled switches."""
    merged: dict[str, Any] = {}
    ambiguous: set[str] = set()
    switches: list[Any] = []
    for path in sorted(source_texts):
        defs, sws = _extract_file(path, source_texts[path] or "")
        if sws:
            switches.extend(sws)
        for d in defs or []:
            if d.name in ambiguous:
                continue
            prior = merged.get(d.name)
            if prior is None:
                merged[d.name] = d
            elif prior.members != d.members:
                ambiguous.add(d.name)
                del merged[d.name]
                reasons["definition_ambiguous"] = (
                    reasons.get("definition_ambiguous", 0) + 1
                )
    return merged, switches


def _owning_enum(
    labels: list[str],
    member_owners: dict[str, set[str]],
) -> tuple[str | None, bool]:
    """Resolve a switch's labels to exactly one enum.

    Returns ``(enum_name, ambiguous)``: ``(name, False)`` on a unique
    join, ``(None, True)`` when the labels fit several enums (joining
    any is a guess), ``(None, False)`` when they fit none (plain
    integers/macros — the census has nothing to say)."""
    owners: set[str] | None = None
    for label in labels:
        got = member_owners.get(label)
        if got is None:
            return None, False
        owners = set(got) if owners is None else owners & got
    if not owners:
        return None, False
    if len(owners) > 1:
        return None, True
    return next(iter(owners)), False


def detect_enum_switch_deviations(
    source_texts: dict[str, str],
    *,
    min_group: int = ENUM_SWITCH_MIN_GROUP,
    ratio: float = ENUM_SWITCH_RATIO,
    seed: bytes | None = None,
) -> tuple[list[EnumSwitchDeviation], dict[str, Any]]:
    """Run the census. Returns ``(deviations, stats)``.

    ``stats``: ``inconclusive_reasons`` (enumerated, see the module
    docstring), ``families`` (enums with a votable peer group),
    ``presence_ops`` (matrix work performed — the cost-rail pin reads
    it), ``caps_hit`` (any bound truncated the census).

    *seed* keys the over-cap survivor sampling; callers leave it
    ``None`` (fresh entropy per run) outside tests.
    """
    reasons: dict[str, int] = {}
    stats: dict[str, Any] = {
        "families": 0, "presence_ops": 0, "caps_hit": False,
        "inconclusive_reasons": reasons,
    }
    definitions, switches = _extract_enum_data(source_texts, reasons)
    if not definitions or not switches:
        return [], stats

    # Member -> owning enums index for the switch join (linear in
    # total members; never pairwise over switches).
    member_owners: dict[str, set[str]] = {}
    for name, d in definitions.items():
        for m in d.members:
            member_owners.setdefault(m, set()).add(name)

    by_enum: dict[str, list[Any]] = {}
    for sw in switches:
        enum_name, ambiguous = _owning_enum(sw.labels, member_owners)
        if enum_name is None:
            if ambiguous:
                reasons["enum_ambiguous"] = (
                    reasons.get("enum_ambiguous", 0) + 1
                )
            continue
        by_enum.setdefault(enum_name, []).append(sw)

    # Per-enum switch cap: SEEDED-RANDOM survivors, never a
    # deterministic prefix — switches arrive in sorted-file order,
    # so a first-N cut would let a hostile repo evict the real
    # deviant with a flood of conforming decoys in early-sorting
    # file names (the same argument as every other cap here). The
    # full switch list is already materialised by extraction, so
    # sampling adds no memory.
    rnd = random.Random(seed if seed is not None else os.urandom(16))
    for enum_name in sorted(by_enum):
        bucket = by_enum[enum_name]
        if len(bucket) > MAX_SWITCHES_PER_ENUM:
            stats["caps_hit"] = True
            by_enum[enum_name] = rnd.sample(
                bucket, MAX_SWITCHES_PER_ENUM,
            )

    deviations: list[EnumSwitchDeviation] = []
    ops = 0
    n_families = 0
    for enum_name in sorted(by_enum):
        peers = by_enum[enum_name]
        if len(peers) < min_group:
            continue
        d = definitions[enum_name]
        if d.caps_hit:
            # A capped member set must never mint absence claims.
            reasons["census_degraded"] = (
                reasons.get("census_degraded", 0) + 1
            )
            continue
        if n_families >= MAX_ENUM_FAMILIES:
            stats["caps_hit"] = True
            break
        n_families += 1

        label_sets = [frozenset(sw.labels) for sw in peers]
        n = len(peers)
        # Member-major presence walk with the run-level ops budget:
        # an enum whose walk does not fit the REMAINING budget is
        # EXCLUDED whole (loud, one census_degraded tick each), not
        # half-censused (an absence claim from a truncated walk
        # lies). Per-enum, not a hard stop: later, smaller enums may
        # still census inside the leftover budget.
        if ops + len(d.members) * n > MAX_PRESENCE_OPS:
            stats["caps_hit"] = True
            reasons["census_degraded"] = (
                reasons.get("census_degraded", 0) + 1
            )
            continue
        for member in d.members:
            handled = [
                i for i, labels in enumerate(label_sets)
                if member in labels
            ]
            ops += n
            conforming = len(handled)
            if conforming == 0:
                reasons["uniformly_missing_member"] = (
                    reasons.get("uniformly_missing_member", 0) + 1
                )
                continue
            if conforming == n or conforming / n < ratio:
                continue
            handled_set = set(handled)
            exhibits = [
                PeerExhibit(
                    peers[i].file, peers[i].line,
                    f"switch in {peers[i].function} handles "
                    f"{member}",
                )
                for i in handled[:3]
            ]
            for i, sw in enumerate(peers):
                if i in handled_set:
                    continue
                if sw.has_default:
                    reasons["non_exhaustive_idiom_default"] = (
                        reasons.get(
                            "non_exhaustive_idiom_default", 0,
                        ) + 1
                    )
                    continue
                deviations.append(EnumSwitchDeviation(
                    enum_name=enum_name,
                    missing_member=member,
                    file=sw.file,
                    line=sw.line,
                    enclosing_function=sw.function,
                    n=n,
                    conforming=conforming,
                    peer_evidence=PeerEvidence(
                        dimension=DIMENSION_ENUM_SWITCH,
                        formation="enum_switch",
                        group_key=enum_name,
                        n=n,
                        conforming=conforming,
                        ratio=conforming / n,
                        deviant=PeerExhibit(
                            sw.file, sw.line,
                            f"switch in {sw.function} has no "
                            f"{member} arm and no default",
                        ),
                        exhibits=exhibits,
                        contract_source="majority",
                        provenance=f"enum_switch:{enum_name}",
                    ),
                ))

    stats["families"] = n_families
    stats["presence_ops"] = ops
    deviations.sort(
        key=lambda dv: (dv.file, dv.line, dv.missing_member),
    )
    logger.info(
        "enum-switch census: %d families, %d deviation(s), %d "
        "presence ops%s",
        n_families, len(deviations), ops,
        " (caps hit)" if stats["caps_hit"] else "",
    )
    return deviations, stats


def enum_switch_cohorts(
    source_texts: dict[str, str],
    *,
    seed: bytes | None = None,
) -> list[tuple[str, list[str]]] | None:
    """L8 producer: (enum name, [switching functions]) cohorts.

    Functions whose switches join the same enum are review peers —
    NON-exclusive (switch co-location is review structure, not
    identity: the same functions legitimately belong to co-callee or
    dispatch families too). Returns ``None`` when nothing joins, so
    the resolver layer stays empty (equivalence pin). Ambiguity rules
    match the census (one extraction, memoised — see
    :func:`_extract_file`): unjoinable or multi-enum switches
    contribute nothing. Over-cap cohorts keep SEEDED-RANDOM
    survivors, the same anti-eviction rule as the census's switch
    cap; *seed* is test injection only.
    """
    reasons: dict[str, int] = {}
    definitions, switches = _extract_enum_data(source_texts, reasons)
    if not definitions or not switches:
        return None

    member_owners: dict[str, set[str]] = {}
    for name, d in definitions.items():
        for m in d.members:
            member_owners.setdefault(m, set()).add(name)

    cohorts: dict[str, dict[str, None]] = {}
    for sw in switches:
        enum_name, _ambiguous = _owning_enum(sw.labels, member_owners)
        if enum_name is None:
            continue
        if sw.function and sw.function != "<module>":
            cohorts.setdefault(enum_name, {}).setdefault(sw.function)
    rnd = random.Random(seed if seed is not None else os.urandom(16))
    result: list[tuple[str, list[str]]] = []
    for name in sorted(cohorts):
        members = list(cohorts[name])
        if len(members) < 2:
            continue
        if len(members) > MAX_SWITCHES_PER_ENUM:
            members = sorted(
                rnd.sample(members, MAX_SWITCHES_PER_ENUM),
            )
        result.append((name, members))
    return result or None

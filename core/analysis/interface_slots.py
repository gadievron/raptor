"""Interface-slot census: peer families whose membership is a
mechanical fact of an interface, not a naming heuristic.

Two family classes, both extracted from data the audit prep already
holds (no new parsing passes, no LLM):

* **ops-slot families** (C/C++): functions installed into the SAME
  designated-initializer slot across different ops-struct tables —
  ``.output = esp_output_head`` in five ``struct xfrm_ops``
  initialisers makes the five ``output`` implementations peers.
  Extraction reuses :func:`core.audit.ops_struct.
  extract_ops_registrations` (one extractor, two consumers — the
  reachability exemption and this census must agree on what a slot
  registration is).
* **override-set families** (Python): methods of the same name whose
  enclosing classes share a declared base — subclass overrides of one
  method. The inventory's Python extractor records ``class_name`` and
  the base-class names (``metadata.class_attributes``), so membership
  is an AST fact.

Membership certainty is the point: these are the strongest peer
classes the source side has, so the resolver claims them exclusively
ahead of the co-callee layers (a mechanically-certain interface
family must not lose members to functions that merely share a
caller), and the interface parity comparator admits the group type
as a voting family.

Everything here is derived from the scanned target (struct, field,
class and function names are attacker-chosen text): family keys and
quoted names are escaped at emission in the peer-group layer, counts
are capped with in-band degradation markers, and nothing in this
module renders a verdict — families are review structure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Group-type string for the resolver layer and the interface
# dimension's admission frozenset (consistency_dimensions.
# _INTERFACE_GROUP_TYPES). Literal in both places by convention;
# pinned against each other by test so a silent frozenset miss —
# exactly the drift failure mode the family is meant to catch in
# target code — dies loudly here too.
GROUP_TYPE_INTERFACE_SLOT = "interface_slot"

#: Slot families emitted per run. Both directions: more lets a
#: generated tree (one ops struct per file, thousands of slots) flood
#: the exclusive chain and the downstream comparator with
#: single-purpose families; fewer hides real breadth on
#: dispatch-heavy targets (kernel-shaped trees legitimately carry
#: hundreds of ops slots). 500 mirrors the enum-family cap class —
#: linear census, no pairwise work, so the cap bounds review volume,
#: not compute.
MAX_SLOT_FAMILIES = 500

#: Distinct implementations a slot needs before it is a family.
#: Two is the smallest peer notion; the resolver layer separately
#: applies its claim floor (an exclusive layer must not claim
#: members the comparator cannot vote on).
MIN_SLOT_IMPLEMENTATIONS = 2


@dataclass
class SlotMember:
    """One implementation of a slot.

    ``file``/``line`` are filled where the census knows them
    (override sets, from checklist records); ops-slot members carry
    the function NAME only — the registration site is not the
    definition site, so the peer-group layer resolves file/line
    through its name index (ambiguous names excluded there, never
    mis-bound).
    """

    function: str
    file: str = ""
    line: int = 0


@dataclass
class SlotFamily:
    """One interface-slot peer family."""

    kind: str                # "ops_slot" | "override_set"
    key: str                 # "xfrm_ops.output" / "BaseHandler.process"
    members: list[SlotMember] = field(default_factory=list)
    #: True when the census-wide family cap dropped candidates —
    #: consumers must surface degradation, never read a capped census
    #: as the whole census.
    caps_hit: bool = False


def _ops_slot_families(
    source_texts: dict[str, str],
) -> list[SlotFamily]:
    """C/C++ designated-initializer slot census over the run's texts."""
    try:
        from core.audit.ops_struct import extract_ops_registrations
    except ImportError:  # pragma: no cover - trimmed deployment
        return []

    # (struct_type, field) -> {function, ...}
    slots: dict[tuple[str, str], set[str]] = {}
    for path in sorted(source_texts):
        if not path.endswith((".c", ".h", ".cc", ".cpp", ".hpp",
                              ".cxx", ".hh")):
            continue
        text = source_texts.get(path) or ""
        if not text:
            continue
        for reg in extract_ops_registrations(text, path):
            struct_type = reg.get("struct_type") or ""
            slot = reg.get("field") or ""
            fn = reg.get("function") or ""
            if struct_type and slot and fn:
                slots.setdefault((struct_type, slot), set()).add(fn)

    families: list[SlotFamily] = []
    for (struct_type, slot) in sorted(slots):
        names = sorted(slots[(struct_type, slot)])
        if len(names) < MIN_SLOT_IMPLEMENTATIONS:
            continue
        families.append(SlotFamily(
            kind="ops_slot",
            key=f"{struct_type}.{slot}",
            members=[SlotMember(function=n) for n in names],
        ))
    return families


def _override_families(
    checklist: dict[str, Any] | None,
) -> list[SlotFamily]:
    """Python subclass-override census from checklist metadata.

    A family is (base class, method name): methods named M in two or
    more DISTINCT classes that each declare base B.
    ``class_attributes`` carries the declared base-class names for
    Python inventory records (Java records carry stereotype
    annotations in that slot instead — Java override sets are a named
    residual, never a silent claim, so only ``.py`` records join).

    Members are (file, method) records; two overriding classes in ONE
    file collapse to one member identity (function identity downstream
    is the (file, name) pair) — the family may then fall below the
    layer's claim floor, which under-claims and never mis-binds.

    Checklist content is producer-controlled (items are
    LLM-enrichable), so every level is type-validated as read.
    """
    if not isinstance(checklist, dict):
        return []
    files = checklist.get("files")
    if not isinstance(files, list):
        return []

    # (base, method) -> {class_name: SlotMember}
    by_slot: dict[tuple[str, str], dict[str, SlotMember]] = {}
    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        path = file_entry.get("path")
        if not isinstance(path, str) \
                or not path.endswith((".py", ".pyi")):
            continue
        items = file_entry.get("items", file_entry.get("functions"))
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("kind", "function") != "function":
                continue
            name = item.get("name")
            meta = item.get("metadata")
            if not isinstance(name, str) or not name \
                    or not isinstance(meta, dict):
                continue
            cls = meta.get("class_name")
            bases = meta.get("class_attributes")
            if not isinstance(cls, str) or not cls \
                    or not isinstance(bases, list):
                continue
            # Dunders are protocol plumbing, not interface slots —
            # __init__ overrides across every subclass tree would
            # family half the codebase.
            if name.startswith("__") and name.endswith("__"):
                continue
            line = item.get("line_start", item.get("line", 0))
            if isinstance(line, bool) or not isinstance(line, int):
                line = 0
            member = SlotMember(function=name, file=path, line=line)
            for base in bases:
                if isinstance(base, str) and base:
                    by_slot.setdefault((base, name), {}) \
                        .setdefault(cls, member)

    families: list[SlotFamily] = []
    for (base, method) in sorted(by_slot):
        by_class = by_slot[(base, method)]
        # Distinct member identities (file, name), not distinct
        # classes — see the docstring's collapse note.
        members = {
            (m.file, m.function): m for m in by_class.values()
        }
        if len(members) < MIN_SLOT_IMPLEMENTATIONS:
            continue
        families.append(SlotFamily(
            kind="override_set",
            key=f"{base}.{method}",
            members=[members[k] for k in sorted(members)],
        ))
    return families


def interface_slot_families(
    source_texts: dict[str, str] | None,
    checklist: dict[str, Any] | None = None,
) -> list[SlotFamily] | None:
    """L7 producer: the run's interface-slot families.

    Returns ``None`` when neither census yields a family, so the
    resolver layer stays empty and behaviour is unchanged
    (equivalence pin — the producer-absent contract every peer-group
    input follows).
    """
    families: list[SlotFamily] = []
    if source_texts:
        families.extend(_ops_slot_families(source_texts))
    families.extend(_override_families(checklist))
    if not families:
        return None
    if len(families) > MAX_SLOT_FAMILIES:
        # In-band, never partial-silent: keep (kind, key) order
        # (deterministic and, unlike arrival order, not
        # attacker-reorderable by file layout), mark the survivors'
        # census as capped.
        families = sorted(
            families, key=lambda f: (f.kind, f.key),
        )[:MAX_SLOT_FAMILIES]
        for fam in families:
            fam.caps_hit = True
        logger.info(
            "interface-slot census capped at %d families",
            MAX_SLOT_FAMILIES,
        )
    logger.info(
        "interface-slot census: %d families (%d ops-slot, %d "
        "override-set)",
        len(families),
        sum(1 for f in families if f.kind == "ops_slot"),
        sum(1 for f in families if f.kind == "override_set"),
    )
    return families

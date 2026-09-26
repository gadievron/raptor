"""Per-kind emissibility of pack entries as CodeQL models-as-data rows.

Not every pack kind has a models-as-data row shape, and not every
provenance tier may emit every row kind. This module is the decision
table — a pure function over (language, role, kind, provenance) —
plus a counting report so every non-emitted entry is a visible
:class:`~core.dataflow.extension_pack.RejectedRow`, never a silent
drop (the extension-pack provenance-gate idiom).

Enforced invariants (each pinned by tests):

* **Barrier and summary rows require operator-grade provenance.**
  A barrier row suppresses CodeQL findings and a summary row can
  narrow modelled flow — both are suppression-direction channels, so
  learned-tier provenance may emit source/sink rows only.
* **The python layout has no barrier predicate, and javascript is
  excluded from barriers identically.** The exclusion here is a rule
  layer ABOVE the emitter's layout tables: even if a future
  javascript layout in :mod:`core.dataflow.extension_pack` grew a
  barrier predicate, this matrix keeps the dynamic-language barrier
  channel closed until that decision is made deliberately.
* **Kinds without a faithful row shape are refused with a reason**:
  ``route_param`` has no API coordinate to emit; ``method_name`` is
  bare-name equality (a models-as-data row would apply the sink to
  every same-named method in the program); the reserved stored-taint
  kinds have no row shape yet.

Actual row EMISSION stays in :mod:`core.dataflow.extension_pack`;
this module only decides and counts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from collections.abc import Mapping

from core.dataflow.extension_pack import (
    ROLE_BARRIER,
    ROLE_SINK,
    ROLE_SOURCE,
    ROLE_SUMMARY,
    RejectedRow,
    # The emitter's layout and human-provenance tables are the single
    # source of truth this matrix must agree with (same convention as
    # route_models importing the callgraph's dotted-form helpers);
    # tests pin the agreement.
    _LANGUAGE_LAYOUTS,
    _MAD_PROVENANCE,
)
from core.taint.packs import (
    PROPAGATOR_KINDS,
    SANITIZER_KINDS,
    SINK_KINDS,
    SOURCE_KINDS,
    PackSet,
    PropagatorSpec,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
)

#: Provenance values whose rows CodeQL records as "manual" — the
#: human-attested set. Barrier/summary emission requires membership.
OPERATOR_GRADE_PROVENANCE = frozenset(_MAD_PROVENANCE)

#: Languages whose barrier channel stays closed in this matrix
#: regardless of emitter layout evolution (see the module docstring).
BARRIERLESS_MAD_LANGUAGES = frozenset({"python", "javascript"})

#: Pack role → models-as-data role.
_PACK_ROLE_TO_MAD = {
    "source": ROLE_SOURCE,
    "sink": ROLE_SINK,
    "sanitizer": ROLE_BARRIER,
    "propagator": ROLE_SUMMARY,
}

#: Pack kinds per role that have a faithful row shape (dotted API
#: coordinates). Everything else carries a per-kind refusal reason.
_EMISSIBLE_KINDS = {
    "source": frozenset({"module_attribute", "call_return"}),
    "sink": frozenset({"dotted_callee"}),
    "sanitizer": frozenset({"dotted_callee"}),
    "propagator": frozenset({"dotted_callee"}),
}

_KIND_REFUSAL_REASONS = {
    "route_param": (
        "route_param sources bind to route-model records; there is no "
        "API coordinate to emit as a models-as-data row"
    ),
    "stored_read": (
        "stored_read is a reserved stored-taint pairing kind with no "
        "models-as-data row shape yet"
    ),
    "stored_write": (
        "stored_write is a reserved stored-taint pairing kind with no "
        "models-as-data row shape yet"
    ),
    "method_name": (
        "method_name sinks are bare-name equality; a models-as-data row "
        "would apply the sink to every same-named method program-wide"
    ),
}

_VALID_KINDS = {
    "source": SOURCE_KINDS,
    "sink": SINK_KINDS,
    "sanitizer": SANITIZER_KINDS,
    "propagator": PROPAGATOR_KINDS,
}


@dataclass(frozen=True)
class Emissibility:
    """One matrix cell: may (language, role, kind, provenance) emit?"""

    emissible: bool
    predicate: str = ""
    reason: str = ""


def mad_emissibility(
    *, language: str, role: str, kind: str, provenance: str,
) -> Emissibility:
    """Decide one cell of the emissibility matrix.

    ``role`` is the PACK role (``source`` / ``sink`` / ``sanitizer`` /
    ``propagator``); ``kind`` the pack entry kind; ``provenance`` the
    entry's provenance value (learned entries carry ``iris_refined``).
    """
    mad_role = _PACK_ROLE_TO_MAD.get(role)
    if mad_role is None:
        return Emissibility(False, reason=f"unknown pack role {role!r}")
    if kind not in _VALID_KINDS[role]:
        return Emissibility(False, reason=f"unknown {role} kind {kind!r}")

    if role == "sanitizer" and language in BARRIERLESS_MAD_LANGUAGES:
        return Emissibility(
            False,
            reason=(
                f"barrier rows stay closed for {language}: python-all has "
                "no barrierModel extensible predicate (use QL barrier "
                "synthesis, core/dataflow/barrier_synth.py), and the "
                "javascript lane keeps the same exclusion so a learned or "
                "pack row can never suppress CodeQL findings there"
            ),
        )
    if mad_role in (ROLE_BARRIER, ROLE_SUMMARY) and (
        provenance not in OPERATOR_GRADE_PROVENANCE
    ):
        return Emissibility(
            False,
            reason=(
                f"{mad_role} rows require operator-grade provenance "
                f"({sorted(OPERATOR_GRADE_PROVENANCE)}); {provenance!r} may "
                "emit source/sink rows only — a non-operator barrier row "
                "would suppress findings and a summary row can narrow flow"
            ),
        )

    layout: Mapping[str, str] | None = _LANGUAGE_LAYOUTS.get(language)
    if layout is None:
        return Emissibility(
            False,
            reason=(
                f"no verified models-as-data layout for language "
                f"{language!r}; unverified row shapes are refused, never "
                "emitted speculatively"
            ),
        )
    if mad_role not in layout:
        return Emissibility(
            False,
            reason=f"language {language!r} layout has no {mad_role} predicate",
        )

    kind_reason = _KIND_REFUSAL_REASONS.get(kind)
    if kind_reason is not None or kind not in _EMISSIBLE_KINDS[role]:
        return Emissibility(
            False,
            reason=kind_reason or f"{role} kind {kind!r} has no row shape",
        )
    return Emissibility(True, predicate=layout[mad_role])


@dataclass(frozen=True)
class MatrixReport:
    """Counted outcome of one pack set against one language."""

    language: str
    counts: tuple[tuple[str, int], ...]        # predicate → emissible rows
    rejected: tuple[RejectedRow, ...]          # every non-emissible entry

    @property
    def emissible_rows(self) -> int:
        return sum(n for _, n in self.counts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "counts": dict(self.counts),
            "emissible_rows": self.emissible_rows,
            "rejected": [
                {"row": r.row, "reason": r.reason} for r in self.rejected
            ],
        }


def _label(role: str, entry: Any) -> str:
    coord = getattr(entry, "match", "") or getattr(entry, "kind", "")
    return f"{role}:{entry.kind}:{coord}"


def emissibility_report(pack_set: PackSet, *, language: str) -> MatrixReport:
    """Partition a loaded pack set into emissible-row counts and
    counted refusals for *language*. Pure decision pass — no rows are
    written here."""
    counts: dict[str, int] = {}
    rejected: list[RejectedRow] = []
    entries: list[tuple[str, SourceSpec | SinkSpec | SanitizerSpec | PropagatorSpec]] = [
        *(("source", s) for s in pack_set.sources),
        *(("sink", s) for s in pack_set.sinks),
        *(("sanitizer", s) for s in pack_set.sanitizers),
        *(("propagator", s) for s in pack_set.propagators),
    ]
    for role, entry in entries:
        cell = mad_emissibility(
            language=language, role=role, kind=entry.kind,
            provenance=entry.provenance,
        )
        if cell.emissible:
            counts[cell.predicate] = counts.get(cell.predicate, 0) + 1
        else:
            rejected.append(RejectedRow(row=_label(role, entry), reason=cell.reason))
    return MatrixReport(
        language=language,
        counts=tuple(sorted(counts.items())),
        rejected=tuple(rejected),
    )


__all__ = [
    "BARRIERLESS_MAD_LANGUAGES",
    "OPERATOR_GRADE_PROVENANCE",
    "Emissibility",
    "MatrixReport",
    "emissibility_report",
    "mad_emissibility",
]

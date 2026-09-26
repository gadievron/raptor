"""Pack vocabulary → CodeQL models-as-data rows, plus the per-run
augmentation record.

This is the emission half the matrix (:mod:`core.taint.mad_matrix`)
decides for: every pack entry the matrix calls emissible is converted
to a :class:`~core.dataflow.extension_pack.ModelRow` on verified
(type, path) coordinates, and every entry that is NOT converted —
matrix refusal, no kind mapping, no expressible coordinate — is a
counted :class:`~core.dataflow.extension_pack.RejectedRow`, never a
silent drop.

Two spec channels feed one pack per language:

* **Packs** (:func:`rows_from_pack_set`) — the in-tree seed packs
  plus operator config-dir packs; operator-grade provenance rides
  through to the emitter (``framework_catalog`` rows land as
  ``manual`` where the row family has a provenance column).
* **IRIS TaintSpecs** — converted by the existing
  :func:`core.dataflow.extension_pack.rows_from_taint_specs`, then
  passed through :func:`enforce_mad_provenance`, which applies the
  pinned invariant the emitter alone does not: summary (and barrier)
  rows require operator-grade provenance — a learned summary row can
  narrow modelled flow, a learned barrier row would suppress
  findings. Learned sources/sinks pass and carry their evidence tier
  into the record.

The **augmentation record** (:func:`write_augmentation_record`) is
the run-level contract consumers read to learn WHICH sink kinds /
classes / CWEs the augmented database was given rows for: a
refutation-grade gate consulting an augmented analysis may treat a
"no flow into <sink>" result as informative only for sink classes
this record names as augmented. Written as
``taint-mad-augmentation.json`` in the run output directory; the
shape is versioned (``schema_version`` 1) and additive — consumers
must tolerate extra keys.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Mapping, Sequence

from core.dataflow.extension_pack import (
    ROLE_BARRIER,
    ROLE_SINK,
    ROLE_SOURCE,
    ROLE_SUMMARY,
    ModelRow,
    RejectedRow,
    js_coordinate,
)
from core.security.log_sanitisation import escape_nonprintable
from core.taint.mad_matrix import (
    BARRIERLESS_MAD_LANGUAGES,
    OPERATOR_GRADE_PROVENANCE,
    mad_emissibility,
)
from core.taint.packs import (
    SOURCE_KIND_CALL_RETURN,
    PackSet,
)

RECORD_FILENAME = "taint-mad-augmentation.json"
RECORD_SCHEMA_VERSION = 1

#: pack sink class → models-as-data sink kind. Every kind on the
#: right is consumed by stock queries in BOTH verified (type, path)
#: stdlib packs — codeql/python-all 7.x and codeql/javascript-all
#: 2.10.x (grep: ``ModelOutput::sinkNode(this, "<kind>")``). Classes
#: with no consuming kind (template-injection, argument-injection)
#: are counted refusals, not guessed spellings — an unconsumed kind
#: row is a dead row.
PACK_SINK_KINDS: Mapping[str, str] = {
    "command-injection": "command-injection",
    "sql-injection": "sql-injection",
    "code-injection": "code-injection",
    "path-traversal": "path-injection",
    "xss": "html-injection",
    "url-redirection": "url-redirection",
    "unsafe-deserialization": "unsafe-deserialization",
    "log-injection": "log-injection",
}

#: pack source taint class → models-as-data source kind. Coarse in
#: the candidate direction on purpose: a source row can only WIDEN
#: what the stock queries track (more candidates downstream), never
#: suppress — so ``user-input`` maps to the general remote kind even
#: where a narrower threat-model kind exists. Unmapped classes are
#: counted refusals.
PACK_SOURCE_KINDS: Mapping[str, str] = {
    "user-input": "remote",
    "remote": "remote",
}

_SUMMARY_STAR = "Argument[*]"
#: javascript spelling for "any argument": the open range both the
#: js grammar here and upstream AccessPathSyntax parse.
_SUMMARY_STAR_JS = "Argument[0..]"
#: python spelling: a bounded index list — the emitter's python
#: access validator splits paths on every dot, so the range form is
#: unrepresentable there; eight leading positions cover real
#: variadic call sites (os.path.join and friends). Raising the bound
#: widens modelled flow for pathological arities; lowering it drops
#: real trailing-argument flows.
_SUMMARY_STAR_PY = "Argument[" + ",".join(str(i) for i in range(8)) + "]"


@dataclass(frozen=True)
class PackRowConversion:
    """Rows plus fully-accounted refusals for one (pack set, language)."""

    rows: tuple[ModelRow, ...]
    rejected: tuple[RejectedRow, ...] = field(default_factory=tuple)


def _python_coordinate(match: str) -> tuple[str, str] | None:
    """``pkg.mod.fn`` → (``pkg.mod``, ``Member[fn]``); bare names have
    no module-qualified type path and return ``None`` (mirrors the
    IRIS converter's python propagator rule)."""
    if "." not in match:
        return None
    mod, _, fn = match.rpartition(".")
    return mod, f"Member[{fn}]"


def _coordinate(match: str, language: str) -> tuple[str, str] | None:
    if language == "javascript":
        return js_coordinate(match)
    return _python_coordinate(match)


def _translate_flow_cell(cell: str, language: str) -> str:
    """Pack access-path grammar → models-as-data spelling.

    The pack format's ``Argument[*]`` (any argument) becomes the open
    range for javascript and the bounded index list for python (the
    two spellings the respective emitter grammars admit); everything
    else the shared pack grammar admits is already MaD-valid.
    """
    if cell == _SUMMARY_STAR:
        return (_SUMMARY_STAR_JS if language == "javascript"
                else _SUMMARY_STAR_PY)
    return cell


def _sink_label(sink) -> str:
    """Rejection label naming exactly one declared sink entry.

    ``(kind, match)`` alone is not unique: two packs may declare the
    same callee with different sink classes, and only one of the twins
    convert — so the class rides in the label. Without it a single
    refusal would be attributable to either twin (and an accounting
    join over the labels would wrongly exclude the converted one).
    """
    return f"sink:{sink.kind}:{sink.match or sink.kind}:{sink.sink_class}"


def rows_from_pack_set(
    pack_set: PackSet, *, language: str,
) -> PackRowConversion:
    """Convert every emissible pack entry into a model row.

    The matrix decides emissibility per (language, role, kind,
    provenance); this function adds the two conversion-level gates —
    a kind mapping must exist for the entry's class, and the match
    must have an expressible (type, path) coordinate — each refusal
    counted with a reason.
    """
    rows: list[ModelRow] = []
    rejected: list[RejectedRow] = []

    def _cell_or_reject(role: str, entry) -> bool:
        cell = mad_emissibility(
            language=language, role=role, kind=entry.kind,
            provenance=entry.provenance,
        )
        if not cell.emissible:
            if role == "sink":
                row = _sink_label(entry)
            else:
                label = getattr(entry, "match", "") or entry.kind
                row = f"{role}:{entry.kind}:{label}"
            rejected.append(RejectedRow(row=row, reason=cell.reason))
            return False
        return True

    for src in pack_set.sources:
        if not _cell_or_reject("source", src):
            continue
        kind = next(
            (PACK_SOURCE_KINDS[c] for c in src.taint_classes
             if c in PACK_SOURCE_KINDS), None)
        if kind is None:
            rejected.append(RejectedRow(
                row=f"source:{src.kind}:{src.match}",
                reason=(
                    f"no models-as-data source kind consumes classes "
                    f"{list(src.taint_classes)!r}"
                ),
            ))
            continue
        coord = _coordinate(src.match, language)
        if coord is None:
            rejected.append(RejectedRow(
                row=f"source:{src.kind}:{src.match}",
                reason="bare-name python coordinate has no "
                       "module-qualified type path",
            ))
            continue
        type_name, members = coord
        path = (f"{members}.ReturnValue"
                if src.kind == SOURCE_KIND_CALL_RETURN else members)
        rows.append(ModelRow(
            role=ROLE_SOURCE, type_name=type_name, path=path,
            model_kind=kind, provenance=src.provenance,
        ))

    for sink in pack_set.sinks:
        if not _cell_or_reject("sink", sink):
            continue
        kind = PACK_SINK_KINDS.get(sink.sink_class)
        if kind is None:
            rejected.append(RejectedRow(
                row=_sink_label(sink),
                reason=(
                    f"no models-as-data sink kind consumes class "
                    f"{sink.sink_class!r} in the verified stdlib packs"
                ),
            ))
            continue
        coord = _coordinate(sink.match, language)
        if coord is None:
            rejected.append(RejectedRow(
                row=_sink_label(sink),
                reason="bare-name python coordinate has no "
                       "module-qualified type path",
            ))
            continue
        type_name, members = coord
        if not sink.args:
            rejected.append(RejectedRow(
                row=_sink_label(sink),
                reason="sink declares no positional argument; "
                       "keyword-only positions have no emitted "
                       "models-as-data spelling",
            ))
            continue
        # One row per declared positional argument. Keyword-only
        # positions have no verified cross-language MaD spelling and
        # ride the positional rows they alias (subprocess.run's
        # args=/Argument[0]); conditional suppressions
        # (``unless_kwargs``) are inexpressible in a MaD row, so the
        # row over-approximates in the candidate direction only —
        # more findings to triage, never fewer.
        for i in sink.args:
            rows.append(ModelRow(
                role=ROLE_SINK, type_name=type_name,
                path=f"{members}.Argument[{i}]",
                model_kind=kind, provenance=sink.provenance,
            ))

    for z in pack_set.sanitizers:
        # Always a counted refusal on the dynamic-language lanes
        # (barrier channel closed) — the matrix carries the reason.
        _cell_or_reject("sanitizer", z)

    for prop in pack_set.propagators:
        if not _cell_or_reject("propagator", prop):
            continue
        coord = _coordinate(prop.match, language)
        if coord is None:
            rejected.append(RejectedRow(
                row=f"propagator:{prop.kind}:{prop.match}",
                reason="bare-name python coordinate has no "
                       "module-qualified type path",
            ))
            continue
        type_name, members = coord
        for edge in prop.flows:
            rows.append(ModelRow(
                role=ROLE_SUMMARY, type_name=type_name, path=members,
                access_input=_translate_flow_cell(edge.src, language),
                access_output=_translate_flow_cell(edge.dst, language),
                model_kind="taint", provenance=prop.provenance,
            ))

    return PackRowConversion(rows=tuple(rows), rejected=tuple(rejected))


def enforce_mad_provenance(
    rows: Sequence[ModelRow], *, language: str,
) -> PackRowConversion:
    """Apply the pinned suppression-channel invariant to a row batch.

    The emitter accepts any :data:`ACCEPTED_PROVENANCE` value for any
    role; this seam adds what the augmentation lane pins: summary and
    barrier rows require operator-grade provenance (a learned summary
    row can narrow modelled flow; a learned barrier row would
    suppress findings), and barrier rows on the barrierless languages
    are refused regardless of provenance. Source/sink rows pass
    unchanged — learned vocabulary may only widen detection.
    """
    kept: list[ModelRow] = []
    rejected: list[RejectedRow] = []
    for row in rows:
        if row.role == ROLE_BARRIER and language in BARRIERLESS_MAD_LANGUAGES:
            rejected.append(RejectedRow(
                row=row.summary(),
                reason=(
                    f"barrier rows stay closed for {language} "
                    "(suppression channel)"
                ),
            ))
            continue
        if (row.role in (ROLE_SUMMARY, ROLE_BARRIER)
                and row.provenance not in OPERATOR_GRADE_PROVENANCE):
            rejected.append(RejectedRow(
                row=row.summary(),
                reason=(
                    f"{row.role} rows require operator-grade provenance "
                    f"({sorted(OPERATOR_GRADE_PROVENANCE)}); "
                    f"{row.provenance!r} may emit source/sink rows only"
                ),
            ))
            continue
        kept.append(row)
    return PackRowConversion(rows=tuple(kept), rejected=tuple(rejected))


# ── the augmentation record ──────────────────────────────────────────


def _bound(text: str, cap: int = 200) -> str:
    """Record egress hygiene: IRIS row labels carry target-derived
    function names — escape non-printables and bound length before
    they land in the record file."""
    escaped = escape_nonprintable(str(text))
    if len(escaped) > cap:
        escaped = escaped[:cap] + f"...[+{len(escaped) - cap} chars]"
    return escaped


@dataclass(frozen=True)
class AugmentationCell:
    """Per-language record of what one augmented pack was given.

    ``augmented_sink_kinds`` / ``..._classes`` / ``..._cwes`` are the
    consumer-facing fields: they name exactly the sink surfaces the
    augmented database has model rows for. A gate consulting the
    augmented analysis in the refutation direction must treat sink
    surfaces OUTSIDE these sets as never-augmented (its result there
    carries no more weight than the baseline's).
    """

    language: str
    pack_name: str
    pack_dir: str
    model_file: str
    packs: tuple[str, ...]
    rows_written: int
    counts: tuple[tuple[str, int], ...]
    augmented_sink_kinds: tuple[str, ...]
    augmented_sink_classes: tuple[str, ...]
    augmented_cwes: tuple[str, ...]
    augmented_source_kinds: tuple[str, ...]
    summary_rows: int
    row_provenance: tuple[tuple[str, int], ...]
    iris_specs: int = 0
    iris_rows: int = 0
    iris_evidence_tiers: tuple[tuple[str, int], ...] = ()
    rejected: tuple[RejectedRow, ...] = ()

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "pack_name": self.pack_name,
            "pack_dir": self.pack_dir,
            "model_file": self.model_file,
            "packs": list(self.packs),
            "rows_written": self.rows_written,
            "counts": dict(self.counts),
            "augmented_sink_kinds": list(self.augmented_sink_kinds),
            "augmented_sink_classes": list(self.augmented_sink_classes),
            "augmented_cwes": list(self.augmented_cwes),
            "augmented_source_kinds": list(self.augmented_source_kinds),
            "summary_rows": self.summary_rows,
            "row_provenance": dict(self.row_provenance),
            "iris": {
                "specs": self.iris_specs,
                "rows": self.iris_rows,
                "evidence_tiers": dict(self.iris_evidence_tiers),
            },
            "rejected": [
                {"row": _bound(r.row), "reason": _bound(r.reason, 400)}
                for r in self.rejected
            ],
        }


def augmented_surfaces(
    pack_set: PackSet, rows: Sequence[ModelRow],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """(sink classes, CWEs, source kinds) actually staged, derived by
    joining the emitted sink rows back onto the pack sink table (the
    class/CWE spellings live on the pack side; the row carries the
    MaD kind)."""
    staged_kinds = {r.model_kind for r in rows if r.role == ROLE_SINK}
    classes = sorted({
        s.sink_class for s in pack_set.sinks
        if PACK_SINK_KINDS.get(s.sink_class) in staged_kinds
    })
    cwes = sorted({
        s.cwe for s in pack_set.sinks
        if PACK_SINK_KINDS.get(s.sink_class) in staged_kinds
    })
    source_kinds = sorted({
        r.model_kind for r in rows if r.role == ROLE_SOURCE
    })
    return tuple(classes), tuple(cwes), tuple(source_kinds)


def write_augmentation_record(
    out_dir: Path, cells: Sequence[AugmentationCell],
) -> Path:
    """Write ``taint-mad-augmentation.json`` under *out_dir*."""
    record = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "generated_by": "core.taint.mad_rows",
        "flag_family": "--taint-crossfile",
        "languages": {c.language: c.to_dict() for c in cells},
    }
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / RECORD_FILENAME
    path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


__all__ = [
    "PACK_SINK_KINDS",
    "PACK_SOURCE_KINDS",
    "RECORD_FILENAME",
    "RECORD_SCHEMA_VERSION",
    "AugmentationCell",
    "PackRowConversion",
    "augmented_surfaces",
    "enforce_mad_provenance",
    "rows_from_pack_set",
    "write_augmentation_record",
]

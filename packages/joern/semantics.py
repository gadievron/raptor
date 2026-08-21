"""Project-learned flow semantics for the Joern dataflow engine.

The engine ships with DefaultSemantics (stdlib operators and external
models) but knows nothing about a target's own sanitizers and taint
wrappers. This module turns study-learned vocabulary into
``FlowSemantic`` rows: a *kill* row marks a method as flow-terminating
(a validator the engine would otherwise propagate through), a
*propagate* row declares explicit param→param/return taint mappings
for a wrapper whose body analysis would miss or over-approximate the
flow.

Resolution is done inside the CPG, not by pattern: the rendered Scala
resolves each validated NAME to concrete method fullNames via
``cpg.method.nameExact`` and installs exact-key rows. Two reasons:

* ``FullNameSemantics.forMethod`` performs exact-map lookup — regex
  rows are not consulted on that path (verified empirically on the
  supported joern line), so pattern rows would silently not apply.
* Frontends decorate fullNames differently (pythonsrc:
  ``file.py:<module>.name``, c2cpg: bare ``name``); in-CPG resolution
  is frontend-agnostic and introduces no regex injection surface.

Every name is validated with the same qualified-identifier rule as all
other template substitutions (semantics rows are rendered into a Scala
REPL — validation is load-bearing). Rows whose provenance is
``llm_prior`` (training memory, no on-disk evidence) are refused at the
vocabulary boundary, mirroring the DomainVocabulary receipts gate.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .runner import _escape_scala_string, _validate_substitution_value

logger = logging.getLogger(__name__)

# Return-value position in FlowSemantic mappings (joern convention).
RETURN = -1

# A propagate row with more mappings than this is malformed vocabulary,
# not a plausible wrapper signature.
_MAX_MAPPINGS = 8
_MAX_ARG_INDEX = 64

_KINDS = ("kill", "propagate")

# Study-vocabulary provenance tier that must never drive a mechanical
# effect (see core.audit.condition_smt._entry_actionable).
_REFUSED_PROVENANCE = "llm_prior"


@dataclass(frozen=True)
class SemanticRow:
    """One learned flow-semantics row.

    ``method`` is a bare or dot-qualified identifier (validated).
    ``kind`` is ``"kill"`` (no mappings) or ``"propagate"`` with
    explicit ``(src, dst)`` argument-index mappings, ``-1`` = return.
    """

    method: str
    kind: str = "kill"
    mappings: tuple[tuple[int, int], ...] = field(default_factory=tuple)
    provenance: str = ""


def validate_row(row: SemanticRow) -> str | None:
    """Return an error string for an unusable row, or None when valid."""
    if not _validate_substitution_value(row.method):
        return f"invalid method name {row.method!r}"
    if row.kind not in _KINDS:
        return f"unknown kind {row.kind!r}"
    if row.provenance == _REFUSED_PROVENANCE:
        return f"refused provenance {row.provenance!r}"
    if row.kind == "kill":
        if row.mappings:
            return "kill rows must not carry mappings"
        return None
    if not row.mappings:
        return "propagate rows need at least one mapping"
    if len(row.mappings) > _MAX_MAPPINGS:
        return f"too many mappings ({len(row.mappings)} > {_MAX_MAPPINGS})"
    for pair in row.mappings:
        if len(pair) != 2:
            return f"mapping {pair!r} is not a (src, dst) pair"
        for idx in pair:
            if not isinstance(idx, int) or isinstance(idx, bool):
                return f"mapping index {idx!r} is not an int"
            if idx < RETURN or idx > _MAX_ARG_INDEX:
                return f"mapping index {idx} out of range"
    return None


def filter_valid_rows(
    rows: Iterable[SemanticRow],
) -> tuple[list[SemanticRow], list[str]]:
    """Split rows into (valid, rejection reasons). Rejections are loud."""
    valid: list[SemanticRow] = []
    rejected: list[str] = []
    for row in rows:
        err = validate_row(row)
        if err is None:
            valid.append(row)
        else:
            rejected.append(f"{row.method!r}: {err}")
    if rejected:
        logger.warning(
            "flow semantics: rejected %d row(s): %s",
            len(rejected), "; ".join(rejected[:10]),
        )
    return valid, rejected


def rows_from_vocab(entries: Iterable[Any]) -> list[SemanticRow]:
    """Build rows from vocabulary-shaped entries.

    Accepts plain strings (treated as sanitizer kill rows) and dicts
    with ``name`` plus optional ``kind``, ``mappings`` and
    ``provenance`` keys — the shape the study loop emits. Entries that
    fail validation (including ``llm_prior`` provenance) are dropped
    with a logged reason; vocabulary quality must never break a sweep.
    """
    candidates: list[SemanticRow] = []
    for entry in entries:
        if isinstance(entry, str):
            candidates.append(SemanticRow(method=entry))
            continue
        if isinstance(entry, dict):
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                continue
            raw_maps = entry.get("mappings") or ()
            try:
                mappings = tuple(
                    (int(a), int(b)) for a, b in raw_maps
                )
            except (TypeError, ValueError):
                logger.warning(
                    "flow semantics: unparseable mappings for %r", name,
                )
                continue
            candidates.append(SemanticRow(
                method=name,
                kind=str(entry.get("kind", "kill")),
                mappings=mappings,
                provenance=str(entry.get("provenance", "")),
            ))
    valid, _rejected = filter_valid_rows(candidates)
    return valid


_SEMANTICS_VAL = "raptorSemantics"


def render_semantics_decl(rows: Sequence[SemanticRow]) -> str:
    """Render the Scala declaration installing the learned semantics.

    Empty input renders the empty string — callers substitute the
    result into a template slot, and the no-semantics rendering must
    leave the script byte-identical to the pre-slot template.

    The declaration resolves each name against the loaded CPG
    (``nameExact`` on the last identifier segment; dot-qualified names
    additionally require the fullName to contain the qualified form)
    and installs exact-fullName rows after DefaultSemantics, so
    learned rows win for the methods they name.
    """
    if not rows:
        return ""
    tuples: list[str] = []
    for row in rows:
        name = row.method
        last = name.rsplit(".", 1)[-1]
        safe_last = _escape_scala_string(last)
        safe_full = _escape_scala_string(name)
        maps = ", ".join(f"({a}, {b})" for a, b in row.mappings)
        qualified = "true" if "." in name else "false"
        tuples.append(
            f'("{safe_last}", "{safe_full}", {qualified}, '
            f"List[(Int, Int)]({maps}))"
        )
    rows_literal = ",\n  ".join(tuples)
    return (
        "val raptorSemRows: List[(String, String, Boolean, List[(Int, Int)])] = List(\n"
        f"  {rows_literal})\n"
        "val raptorResolvedSem = raptorSemRows.flatMap { case (n, q, isQ, maps) =>\n"
        "  cpg.method.nameExact(n).fullName.dedup.l\n"
        "    .filter(fn => !isQ || fn.contains(q))\n"
        "    .map(fn => io.joern.dataflowengineoss.semanticsloader"
        ".FlowSemantic.from(fn, maps))\n"
        "}\n"
        f"val {_SEMANTICS_VAL} = io.joern.dataflowengineoss.DefaultSemantics()"
        ".after(\n"
        "  io.joern.dataflowengineoss.semanticsloader.FullNameSemantics"
        ".fromList(raptorResolvedSem))\n"
        'println(s"JOERN_SEMANTICS:installed=${raptorResolvedSem.size}:'
        'declared=${raptorSemRows.size}")\n'
    )


def render_context_arg(rows: Sequence[SemanticRow]) -> str:
    """EngineContext argument fragment: empty, or ``semantics = ..., ``."""
    if not rows:
        return ""
    return f"semantics = {_SEMANTICS_VAL}, "

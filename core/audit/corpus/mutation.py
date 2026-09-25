"""Synthetic-mutant spec validation and application for the corpus.

A synthetic mutant is a corpus label produced by applying ONE
mechanical mutation to ONE member of a peer family the consistency
census scores consistent at a pinned clean upstream ref.  The label's
``SourcePin`` is the PARENT REF: it points at the UNMUTATED upstream,
so pin verification (lint ``--mode pins``, the runner's spend gate)
keeps working against the real tree — span_sha verification would
fail on mutated code by construction.  The mutation spec recorded on
the label (``FunctionLabel.mutation``) is what the corpus runner
applies to its per-run fixture copy after fetch, and the spec's
``mutated_span_sha`` content-addresses the applied result so a
mis-applied or drifted mutation fails loudly before any review cost
instead of silently measuring the wrong code.

Spec shape (JSON object on the label)::

    {
      "operator": "drop-guard",          # one of MUTATION_OPERATORS
      "site_line": 142,                  # mutated line in the CLEAN file
      "edits": [                         # drop-in line-range rewrites,
        {"line_start": 142,              #   the _fix_mutant_control
         "line_end": 142,                #   mechanics (mechanical apply,
         "replacement": []}              #   content-verified result)
      ],
      "mutated_line_end": 279,           # label span end AFTER applying
      "mutated_span_sha": "0123456789ab" # span hash of the applied span
    }

Honesty contract (binding; mirrored in the corpus README): mutant
labels are mutation-operator regression floors conditioned on
family-found —
an end-to-end plumbing/regression harness (family formation → census
→ thresholds → lead), NOT a real-bug recall estimate.  Dimension
gates on mutants alone certify self-consistency only.  Mutant labels
carry the explicit ``synthetic_mutant`` provenance kind — never
laundered as public provenance — and never enter surfaces whose
provenance doctrine is public-only (``core.recall``'s manifest
hard-rejects non-benchmark|cve provenance kinds; that surface is
deliberately not a consumer of these labels).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .label import FunctionLabel

logger = logging.getLogger(__name__)

# The label provenance kind every synthetic mutant carries.  Real
# labels leave ``provenance_kind`` empty and anchor public provenance
# via cve/fix_commit; ``label_kind`` maps both to the two-value kind
# the runner and history store partition on.
PROVENANCE_SYNTHETIC_MUTANT = "synthetic_mutant"
KIND_REAL = "real"

# Mechanical mutation operators, each mapped to a census dimension
# name.  Per-operator baseline floors are pinned by the floors
# harness (core/audit/corpus/tests/test_mutation_floors.py); an
# operator's expected value there updates when a consuming dimension
# lands.
MUTATION_OPERATORS = (
    "drop-guard",
    "swap-order",
    "flip-bound",
    "remove-pair-release",
    "drop-return-check",
    "drop-slot-guard",
    "drop-case-arm",
)

# operator -> (consistency dimension exercised, default CWE).  The
# CWEs are the honest defect families the mutation introduces:
# a dropped null guard dereferences NULL (CWE-476), a swapped call
# order is an incorrect behavior order (CWE-696), a flipped bound is
# an off-by-one (CWE-193), a removed release leaks the resource
# (CWE-401), a dropped return check is an unchecked return (CWE-252),
# a guard dropped from one interface-slot implementation is the same
# NULL dereference exercised through the interface parity dimension
# (CWE-476), and a removed case arm is a missing enum case (CWE-478).
OPERATOR_INFO: dict[str, tuple[str, str]] = {
    "drop-guard": ("guard-presence", "CWE-476"),
    "swap-order": ("ordering", "CWE-696"),
    "flip-bound": ("guard-predicate", "CWE-193"),
    "remove-pair-release": ("cleanup", "CWE-401"),
    "drop-return-check": ("return-check", "CWE-252"),
    "drop-slot-guard": ("interface", "CWE-476"),
    "drop-case-arm": ("enum-switch", "CWE-478"),
}

# Spec size caps: a mutation is ONE small mechanical edit; anything
# larger is not a mutant, it is a rewrite (and fixture repos are
# third-party trees — the spec must never become a byte smuggling
# channel into label files).
MAX_MUTATION_EDITS = 4
MAX_REPLACEMENT_LINES = 40
MAX_REPLACEMENT_LINE_CHARS = 400
MAX_MUTATION_SPEC_BYTES = 16 * 1024

_HEX_DIGITS = frozenset("0123456789abcdef")


class MutationError(ValueError):
    """A mutation spec failed validation or application."""


def label_kind(label: Any) -> str:
    """Two-value label kind: ``synthetic_mutant`` or ``real``.

    The partition key the runner and the history store use — mutant
    runs and real-label runs must never mix in one result set or one
    trend/stability/compare view.
    """
    kind = getattr(label, "provenance_kind", "") or ""
    if kind == PROVENANCE_SYNTHETIC_MUTANT:
        return PROVENANCE_SYNTHETIC_MUTANT
    return KIND_REAL


def _int_field(value: Any) -> int | None:
    # bool is an int subclass; a True line number is a spec bug.
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def validate_mutation_spec(
    spec: Any,
    *,
    span: tuple[int, int] | None = None,
) -> list[str]:
    """Shape-validate one mutation spec.  Returns error strings.

    With *span* (the parent pin's ``(line_start, line_end)``) the
    positional invariants are checked too: every edit inside the
    pinned span, edits strictly ordered and non-overlapping, and
    ``mutated_line_end`` consistent with the edits' net line delta —
    a spec whose recorded post-mutation span disagrees with its own
    edits could never verify at application time, so it fails here.
    """
    errors: list[str] = []
    if not isinstance(spec, dict) or not spec:
        return ["mutation spec must be a non-empty object"]

    try:
        size = len(json.dumps(spec, sort_keys=True).encode("utf-8"))
    except (TypeError, ValueError):
        return ["mutation spec is not JSON-serialisable"]
    if size > MAX_MUTATION_SPEC_BYTES:
        errors.append(
            f"mutation spec is {size} bytes "
            f"(cap {MAX_MUTATION_SPEC_BYTES}) — a mutation is one "
            f"small mechanical edit, not a rewrite"
        )

    operator = spec.get("operator")
    if operator not in MUTATION_OPERATORS:
        errors.append(
            f"mutation operator {operator!r} must be one of "
            f"{sorted(MUTATION_OPERATORS)}"
        )

    site_line = _int_field(spec.get("site_line"))
    if site_line is None or site_line < 1:
        errors.append("mutation site_line must be a positive int")

    mutated_end = _int_field(spec.get("mutated_line_end"))
    if mutated_end is None or mutated_end < 1:
        errors.append("mutation mutated_line_end must be a positive int")

    sha = spec.get("mutated_span_sha")
    if (
        not isinstance(sha, str)
        or len(sha) != 12
        or not set(sha) <= _HEX_DIGITS
    ):
        errors.append(
            "mutation mutated_span_sha must be 12 lowercase hex chars "
            "(core.staleness span-hash convention)"
        )

    edits = spec.get("edits")
    if not isinstance(edits, list) or not edits:
        errors.append("mutation edits must be a non-empty list")
        return errors
    if len(edits) > MAX_MUTATION_EDITS:
        errors.append(
            f"mutation has {len(edits)} edits "
            f"(cap {MAX_MUTATION_EDITS})"
        )

    total_replacement = 0
    parsed: list[tuple[int, int, list[str]]] = []
    for i, edit in enumerate(edits):
        where = f"mutation edits[{i}]"
        if not isinstance(edit, dict):
            errors.append(f"{where}: must be an object")
            continue
        ls = _int_field(edit.get("line_start"))
        le = _int_field(edit.get("line_end"))
        if ls is None or ls < 1 or le is None or le < ls:
            errors.append(
                f"{where}: needs 1 <= line_start <= line_end "
                f"(got {edit.get('line_start')!r}.."
                f"{edit.get('line_end')!r})"
            )
            continue
        replacement = edit.get("replacement")
        if not isinstance(replacement, list) or not all(
            isinstance(ln, str) for ln in replacement
        ):
            errors.append(
                f"{where}: replacement must be a list of strings "
                f"(empty list = delete the range)"
            )
            continue
        if any("\n" in ln for ln in replacement):
            errors.append(
                f"{where}: replacement lines must not embed newlines"
            )
            continue
        if any(
            len(ln) > MAX_REPLACEMENT_LINE_CHARS for ln in replacement
        ):
            errors.append(
                f"{where}: replacement line exceeds "
                f"{MAX_REPLACEMENT_LINE_CHARS} chars"
            )
        total_replacement += len(replacement)
        parsed.append((ls, le, replacement))

    if total_replacement > MAX_REPLACEMENT_LINES:
        errors.append(
            f"mutation replaces {total_replacement} lines "
            f"(cap {MAX_REPLACEMENT_LINES})"
        )

    prev_end = 0
    for ls, le, _replacement in parsed:
        if ls <= prev_end:
            errors.append(
                "mutation edits must be strictly ordered and "
                "non-overlapping (ascending line_start)"
            )
            break
        prev_end = le

    if span is not None and not errors:
        span_start, span_end = span
        delta = sum(
            len(replacement) - (le - ls + 1)
            for ls, le, replacement in parsed
        )
        for ls, le, _replacement in parsed:
            if ls < span_start or le > span_end:
                errors.append(
                    f"mutation edit {ls}..{le} outside the pinned "
                    f"span {span_start}..{span_end}"
                )
        if site_line is not None and not (
            span_start <= site_line <= span_end
        ):
            errors.append(
                f"mutation site_line {site_line} outside the pinned "
                f"span {span_start}..{span_end}"
            )
        expected_end = span_end + delta
        if mutated_end is not None and mutated_end != expected_end:
            errors.append(
                f"mutation mutated_line_end {mutated_end} inconsistent "
                f"with the edits (pinned end {span_end} + "
                f"delta {delta} = {expected_end})"
            )
    return errors


def build_mutation_spec(
    text: str,
    *,
    line_start: int,
    line_end: int,
    operator: str,
    site_line: int,
    edits: list[tuple[int, int, list[str]]],
) -> dict[str, Any]:
    """Build a verified mutation spec from the CLEAN file *text*.

    Applies *edits* (absolute 1-indexed ``(line_start, line_end,
    replacement)`` triples inside the pinned span
    ``line_start..line_end``) to compute ``mutated_line_end`` and
    ``mutated_span_sha``, then round-trips the result through
    :func:`validate_mutation_spec`.  Raises :class:`MutationError`
    when the resulting spec would not validate — a generator must
    never emit a label the runner will refuse.
    """
    from .label import compute_span_sha

    lines = text.split("\n")  # line-model: exact inverse of the "\n".join below — the split→edit→join round-trip must keep every untouched byte so mutated_span_sha is faithful; split_lines trims \r and drops the trailing empty element, breaking invertibility
    delta = 0
    for els, ele, replacement in sorted(edits, reverse=True):
        if ele > len(lines):
            raise MutationError(
                f"edit {els}..{ele} beyond end of file "
                f"({len(lines)} lines)"
            )
        lines[els - 1:ele] = replacement
        delta += len(replacement) - (ele - els + 1)
    mutated_end = line_end + delta
    sha = compute_span_sha("\n".join(lines), line_start, mutated_end)
    if not sha:
        raise MutationError(
            f"mutated span {line_start}..{mutated_end} is not "
            f"hashable (empty or out of range after the edits)"
        )
    if mutated_end == line_end \
            and sha == compute_span_sha(text, line_start, line_end):
        # Laundering tripwire: edits are span-contained, so an equal
        # span hash over the unchanged range means the "mutation"
        # changed nothing — a no-op spec could declare pristine
        # upstream code that carries a REAL bug as synthetic.
        raise MutationError(
            "no-op mutation: the edits leave the pinned span "
            "byte-identical — a synthetic label must introduce its "
            "own defect, never re-declare upstream code"
        )
    spec: dict[str, Any] = {
        "operator": operator,
        "site_line": site_line,
        "edits": [
            {
                "line_start": els,
                "line_end": ele,
                "replacement": list(replacement),
            }
            for els, ele, replacement in sorted(edits)
        ],
        "mutated_line_end": mutated_end,
        "mutated_span_sha": sha,
    }
    errors = validate_mutation_spec(spec, span=(line_start, line_end))
    if errors:
        raise MutationError("; ".join(errors))
    return spec


def mutated_span(label: FunctionLabel) -> tuple[int, int]:
    """The label's expected-finding span in the MUTATED tree.

    Real labels keep their pinned span.  Synthetic mutants keep
    ``line_start`` (edits live inside the span, so its first line
    never moves) and end at the spec's ``mutated_line_end``.
    """
    if label_kind(label) != PROVENANCE_SYNTHETIC_MUTANT:
        return (label.source.line_start, label.source.line_end)
    end = _int_field(label.mutation.get("mutated_line_end"))
    return (
        label.source.line_start,
        end if end is not None else label.source.line_end,
    )


def apply_mutation_to_text(text: str, label: FunctionLabel) -> str:
    """Apply one synthetic label's mutation to *text*.  Fail-closed.

    Verifies the PARENT span first (the pinned range of the clean
    file must hash to the label's ``source.span_sha`` — applying a
    mutation over drifted code measures nothing), applies the edits
    bottom-up, then verifies the spec's ``mutated_span_sha`` over the
    applied result.  Raises :class:`MutationError` on any mismatch.
    """
    from .label import compute_span_sha

    pin = label.source
    spec = label.mutation
    errors = validate_mutation_spec(
        spec, span=(pin.line_start, pin.line_end),
    )
    if errors:
        raise MutationError(
            f"{label.function_id}: invalid mutation spec: "
            + "; ".join(errors)
        )
    if not pin.span_sha:
        raise MutationError(
            f"{label.function_id}: synthetic mutant requires a "
            f"content-addressed parent pin (source.span_sha)"
        )
    parent_sha = compute_span_sha(text, pin.line_start, pin.line_end)
    if parent_sha != pin.span_sha:
        raise MutationError(
            f"{label.function_id}: parent span verification failed "
            f"(pinned {pin.span_sha}, file has {parent_sha or 'none'}) "
            f"— the clean upstream span drifted; regenerate the mutant"
        )
    if spec["mutated_span_sha"] == pin.span_sha \
            and spec["mutated_line_end"] == pin.line_end:
        # Belt-and-braces twin of the label-schema no-op refusal
        # (edits are span-contained, so equal hashes over the same
        # range = the spec changed nothing): a no-op "mutation" would
        # declare pristine upstream code as synthetic.
        raise MutationError(
            f"{label.function_id}: no-op mutation spec (mutated span "
            f"hash equals the parent pin) — refusing to declare "
            f"unchanged upstream code as synthetic"
        )

    lines = text.split("\n")  # line-model: read-modify-write — the joined result is written back to the run tree, so the split must be the byte-exact inverse of the "\n".join (split_lines trims \r / drops the trailing element and would rewrite untouched lines); span-sha checks bracket both ends
    edits = sorted(
        (
            (int(e["line_start"]), int(e["line_end"]),
             list(e["replacement"]))
            for e in spec["edits"]
        ),
        key=lambda e: e[0],
        reverse=True,
    )
    for ls, le, replacement in edits:
        if le > len(lines):
            raise MutationError(
                f"{label.function_id}: mutation edit {ls}..{le} "
                f"beyond end of file ({len(lines)} lines)"
            )
        lines[ls - 1:le] = replacement
    mutated = "\n".join(lines)

    start, end = mutated_span(label)
    got = compute_span_sha(mutated, start, end)
    if got != spec["mutated_span_sha"]:
        raise MutationError(
            f"{label.function_id}: mutated span verification failed "
            f"(spec {spec['mutated_span_sha']}, applied result hashes "
            f"{got or 'none'})"
        )
    return mutated


def apply_labels_to_tree(
    labels: list[Any],
    tree_dirs: dict[str, Path],
) -> list[str]:
    """Apply every synthetic label's mutation to its per-run tree copy.

    *tree_dirs* maps repo_key -> the run's private tree (the excerpt
    copy — never the shared fixture clone).  Real labels are ignored.
    Returns error strings; any error means the run must refuse before
    review cost is spent (a half-mutated tree measures nothing).
    Writes are atomic (tempfile + rename) so a crash never leaves a
    torn file for a resumed run to review.
    """
    errors: list[str] = []
    for label in labels:
        if label_kind(label) != PROVENANCE_SYNTHETIC_MUTANT:
            continue
        tree = tree_dirs.get(label.source.repo)
        if tree is None or not Path(tree).is_dir():
            errors.append(
                f"{label.function_id}: no tree for repo "
                f"{label.source.repo!r}"
            )
            continue
        target = Path(tree) / label.source.file
        if not target.is_file():
            errors.append(
                f"{label.function_id}: {label.source.file} missing "
                f"from the run tree"
            )
            continue
        try:
            text = target.read_text(encoding="utf-8", errors="replace")  # raw-open: run-private copy of the pinned corpus tree (eval lane); read-modify-write must see the full text — a capped read would rewrite a truncated file
            mutated = apply_mutation_to_text(text, label)
        except MutationError as exc:
            errors.append(str(exc))
            continue
        except OSError as exc:
            errors.append(f"{label.function_id}: unreadable: {exc}")
            continue
        try:
            fd, tmp_name = tempfile.mkstemp(
                dir=str(target.parent), prefix=".mutant-",
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(mutated)
                os.replace(tmp_name, target)
            except BaseException:
                Path(tmp_name).unlink(missing_ok=True)
                raise
        except OSError as exc:
            errors.append(f"{label.function_id}: write failed: {exc}")
            continue
        logger.info(
            "mutation applied: %s (%s @ line %s)",
            label.function_id,
            label.mutation.get("operator"),
            label.mutation.get("site_line"),
        )
    return errors

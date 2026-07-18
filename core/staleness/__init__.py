"""Shared span-level staleness detection for RAPTOR.

Single chokepoint for "has this source span changed since I last
analysed it?"  Consumers: annotations, /audit constraints, /validate
checklist, study concepts, flow traces.

Key efficiency primitive: **batched hashing**.  ``hash_spans`` reads a
file once and returns hashes for N spans.  ``check_batch`` groups items
by file path so each file is read at most once, regardless of how many
spans reference it.

Hash format: first 12 hex chars of SHA-256 over the span's lines
(1-indexed, inclusive on both ends).  48 bits is collision-resistant
for the use case (a few thousand spans per project) while keeping
metadata lines short.  This is a *staleness detector*, not an
integrity guarantee — do not use these hashes to verify that code
has not been tampered with.

Comment stripping delegates to ``core.source.strip.strip_comments``
which uses per-language character-by-character state machines that
track string literal boundaries — ``//`` inside ``"https://..."``
and ``#`` inside triple-quoted Python strings are preserved correctly.
"""

from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from core.source.lines import slice_lines as _slice_lines
from core.source.strip import strip_comments as _strip_comments

__all__ = [
    "CheckItem",
    "Span",
    "SpanResult",
    "check_batch",
    "check_spans",
    "hash_span",
    "hash_spans",
    "norm_hash",
    "normalize_source",
]

_HASH_PREFIX_LEN = 12


# -------------------------------------------------------------------
# Data types
# -------------------------------------------------------------------

@dataclass(frozen=True)
class Span:
    """A source span to check for staleness.

    ``start_line`` and ``end_line`` are 1-indexed, inclusive.
    ``stored_hash`` is the SHA-256[:12] from when the span was last
    analysed.  ``stored_norm_hash`` is the normalised hash (optional;
    needed for cosmetic detection).  ``label`` is an opaque tag the
    caller can use to correlate results back to its own data structures.
    """
    start_line: int
    end_line: int
    stored_hash: str
    label: str = ""
    stored_norm_hash: str = ""


@dataclass(frozen=True)
class SpanResult:
    """Result of checking one span against current source.

    Status values:
    - ``"current"`` — hash matches, no change
    - ``"modified"`` — hash differs (real code change, or cosmetic
      detection not requested / not conclusive)
    - ``"cosmetic"`` — hash differs but normalised hash matches stored
      norm hash (comment/whitespace only change)
    - ``"deleted"`` — file no longer exists
    - ``"unknown"`` — cannot determine (invalid range, no stored hash,
      unreadable file)
    """
    status: str
    current_hash: str
    current_norm_hash: str
    span: Span


@dataclass
class CheckItem:
    """A cross-file span check request."""
    file: Path
    start_line: int
    end_line: int
    stored_hash: str
    label: str = ""
    stored_norm_hash: str = ""


# -------------------------------------------------------------------
# Normalisation (cosmetic-change detection)
# -------------------------------------------------------------------

def normalize_source(text: str, filename: str) -> str:
    """Strip comments and normalise whitespace for cosmetic comparison.

    Comment stripping is string-literal-aware via
    ``core.source.strip.strip_comments`` — ``//`` inside C strings and
    ``#`` inside Python triple-quoted strings are preserved.

    After stripping, whitespace is collapsed and blank lines removed
    so formatting-only changes hash identically.
    """
    text = _strip_comments(text, filename)

    out: list[str] = []
    for line in text.splitlines():
        collapsed = " ".join(line.split())
        if collapsed:
            out.append(collapsed)
    return "\n".join(out)


def norm_hash(text: str, filename: str) -> str:
    """Normalise source then SHA-256[:12]."""
    norm = normalize_source(text, filename)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:_HASH_PREFIX_LEN]


# -------------------------------------------------------------------
# Single-span hash (backward-compatible signature)
# -------------------------------------------------------------------

def hash_span(file_path: Path, start_line: int, end_line: int) -> str:
    """Hash a single source span.  Returns SHA-256[:12] or ``""``."""
    if start_line <= 0 or end_line < start_line:
        return ""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return _hash_from_lines(text.splitlines(), start_line, end_line)


# -------------------------------------------------------------------
# Batched hashing — read file once, hash N spans
# -------------------------------------------------------------------

def hash_spans(
    file_path: Path,
    spans: Sequence[tuple[int, int]],
) -> list[str]:
    """Read *file_path* once and return SHA-256[:12] for each
    ``(start_line, end_line)`` pair.

    Invalid ranges or unreadable files produce ``""`` for that span.
    """
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [""] * len(spans)
    lines = text.splitlines()
    return [_hash_from_lines(lines, s, e) for s, e in spans]


# -------------------------------------------------------------------
# Batched staleness check — cross-file, one read per file
# -------------------------------------------------------------------

def check_batch(
    items: Sequence[CheckItem],
    *,
    cosmetic: bool = False,
    root: Path | None = None,
) -> list[SpanResult]:
    """Check spans across multiple files, batching reads per file.

    When *cosmetic* is True and the item has a ``stored_norm_hash``,
    spans whose raw hash changed but whose normalised hash matches
    the stored norm hash get status ``"cosmetic"`` instead of
    ``"modified"``.

    When *root* is set, any ``CheckItem.file`` that resolves outside
    *root* is rejected with status ``"unknown"`` (path traversal
    defence).

    Returns one ``SpanResult`` per input item, in the same order.
    """
    root_prefix = ""
    if root is not None:
        root_prefix = str(root.resolve()) + os.sep

    by_file: dict[Path, list[tuple[int, CheckItem]]] = defaultdict(list)
    results: list[SpanResult | None] = [None] * len(items)

    for idx, item in enumerate(items):
        if root_prefix:
            try:
                resolved = str(item.file.resolve())
            except OSError:
                resolved = ""
            if not resolved.startswith(root_prefix):
                results[idx] = SpanResult(
                    status="unknown",
                    current_hash="",
                    current_norm_hash="",
                    span=Span(item.start_line, item.end_line,
                              item.stored_hash, item.label,
                              item.stored_norm_hash),
                )
                continue
        by_file[item.file].append((idx, item))

    for file_path, entries in by_file.items():
        _check_file_batch(file_path, entries, results, cosmetic=cosmetic)

    assert all(r is not None for r in results), "check_batch: result slot unfilled"
    return results  # type: ignore[return-value]


def check_spans(
    file_path: Path,
    spans: Sequence[Span],
    *,
    cosmetic: bool = False,
    root: Path | None = None,
) -> list[SpanResult]:
    """Check multiple spans in a single file."""
    items = [
        CheckItem(
            file=file_path,
            start_line=s.start_line,
            end_line=s.end_line,
            stored_hash=s.stored_hash,
            label=s.label,
            stored_norm_hash=s.stored_norm_hash,
        )
        for s in spans
    ]
    return check_batch(items, cosmetic=cosmetic, root=root)


# -------------------------------------------------------------------
# Internals
# -------------------------------------------------------------------

def _hash_from_lines(
    lines: list[str], start_line: int, end_line: int,
) -> str:
    """Hash lines[start_line..end_line] (1-indexed, inclusive).

    Delegates slicing to ``core.source.lines.slice_lines`` and operates
    on a pre-split line list to avoid repeated splitlines() in the
    batched path.
    """
    sliced = _slice_lines(lines, start_line, end_line)
    if not sliced:
        return ""
    snippet = "\n".join(sliced)
    return hashlib.sha256(snippet.encode("utf-8")).hexdigest()[:_HASH_PREFIX_LEN]


def _norm_hash_from_lines(
    lines: list[str], start_line: int, end_line: int, filename: str,
) -> str:
    """Extract span from pre-split lines, normalise, hash."""
    sliced = _slice_lines(lines, start_line, end_line)
    if not sliced:
        return ""
    snippet = "\n".join(sliced)
    return norm_hash(snippet, filename)


def _check_file_batch(
    file_path: Path,
    entries: list[tuple[int, CheckItem]],
    results: list[SpanResult | None],
    *,
    cosmetic: bool,
) -> None:
    """Check all spans for a single file in one read."""
    if not file_path.exists():
        for idx, item in entries:
            results[idx] = SpanResult(
                status="deleted",
                current_hash="",
                current_norm_hash="",
                span=Span(item.start_line, item.end_line,
                          item.stored_hash, item.label,
                          item.stored_norm_hash),
            )
        return

    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        for idx, item in entries:
            results[idx] = SpanResult(
                status="unknown",
                current_hash="",
                current_norm_hash="",
                span=Span(item.start_line, item.end_line,
                          item.stored_hash, item.label,
                          item.stored_norm_hash),
            )
        return

    lines = text.splitlines()
    filename = file_path.name

    for idx, item in entries:
        span = Span(item.start_line, item.end_line,
                    item.stored_hash, item.label,
                    item.stored_norm_hash)

        if item.start_line <= 0 or item.end_line < item.start_line:
            results[idx] = SpanResult(
                status="unknown",
                current_hash="",
                current_norm_hash="",
                span=span,
            )
            continue

        current_hash = _hash_from_lines(lines, item.start_line, item.end_line)

        if not current_hash:
            results[idx] = SpanResult(
                status="unknown",
                current_hash="",
                current_norm_hash="",
                span=span,
            )
            continue

        if not item.stored_hash:
            results[idx] = SpanResult(
                status="unknown",
                current_hash=current_hash,
                current_norm_hash="",
                span=span,
            )
            continue

        if current_hash == item.stored_hash:
            results[idx] = SpanResult(
                status="current",
                current_hash=current_hash,
                current_norm_hash="",
                span=span,
            )
            continue

        current_norm = ""
        status = "modified"
        if cosmetic:
            current_norm = _norm_hash_from_lines(
                lines, item.start_line, item.end_line, filename,
            )
            if item.stored_norm_hash and current_norm == item.stored_norm_hash:
                status = "cosmetic"

        results[idx] = SpanResult(
            status=status,
            current_hash=current_hash,
            current_norm_hash=current_norm,
            span=span,
        )

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

from core.source.contained import (
    DEFAULT_MAX_SOURCE_CHARS,
    read_text_capped,
)
from core.source.lines import slice_lines as _slice_lines
from core.source.lines import split_lines as _split_source_lines
from core.source.strip import strip_comments as _strip_comments
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from collections.abc import Sequence

__all__ = [
    "CheckItem",
    "Span",
    "SpanResult",
    "check_batch",
    "check_spans",
    "hash_span",
    "hash_spans",
    "hash_spans_text",
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
      detection not requested / not conclusive), or the stored span
      now lies wholly past EOF on a readable file (rewritten
      shorter/stubbed — the span provably no longer exists, which is
      positive drift evidence, never "cannot determine")
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

def _split_lines(text: str) -> list[str]:
    r"""Split source text into lines by ``\n`` ONLY.

    ``str.splitlines`` also breaks on ``\f``, ``\v``, ``\x85``,
    ``\u2028``... — but every line-number consumer around staleness
    (editors, annotations' ``--lines``, inventory ranges) counts
    ``\n``. A file rewritten with a ``\f`` where a ``\n`` used to be
    changed line content invisibly: splitlines still saw the same
    line list shape, the modified span hashed "current", and every
    downstream line number silently desynced. Delegates to the
    ``core.source.lines.split_lines`` chokepoint, which carries the
    full contract; its ``\r``/``\r\n`` normalisation is a no-op here
    because ``read_text``'s universal newlines already delivered
    ``\n``, so hashes of previously-stamped spans are unchanged. A
    single trailing empty element is still dropped, so line counts
    match editor numbering.
    """
    return _split_source_lines(text)


def _reliable_line_count(text: str, truncated: bool, lines: list[str]) -> int:
    """Number of lines of a (possibly capped) read that are COMPLETE.

    A truncated read that does not end at a ``\\n`` boundary cut its
    final line mid-content — hashing that partial tail against a
    stored span hash reported a false "modified" (a single-line file
    past the cap has NO span past ``len(lines)``, so the
    spans-past-the-cap guard alone never fired).  Spans touching the
    partial line must degrade to unknown/"" like spans past the cap:
    a read-bound artifact must never demote annotation authority.
    """
    if not truncated or text.endswith("\n"):
        return len(lines)
    return max(len(lines) - 1, 0)


def hash_span(file_path: Path, start_line: int, end_line: int) -> str:
    """Hash a single source span.  Returns SHA-256[:12] or ``""``.

    Reads via :func:`core.source.contained.read_text_capped` — staleness
    consumers run against untrusted target trees, and a bare
    ``read_text`` blocks forever on a repo-planted reader-less FIFO
    (``exists()`` is True for FIFOs) and loads planted multi-GB files
    whole. A span past the cap of a truncated read returns ``""``
    (cannot verify) rather than hashing a partial slice.
    """
    if start_line <= 0 or end_line < start_line:
        return ""
    got = read_text_capped(file_path, DEFAULT_MAX_SOURCE_CHARS)
    if got is None:
        return ""
    text, truncated = got
    lines = _split_lines(text)
    if truncated and end_line > _reliable_line_count(text, truncated, lines):
        return ""
    return _hash_from_lines(lines, start_line, end_line)


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
    Same guarded read as :func:`hash_span` (FIFO-proof, size-capped);
    spans past the cap of a truncated read produce ``""``.
    """
    got = read_text_capped(file_path, DEFAULT_MAX_SOURCE_CHARS)
    if got is None:
        return [""] * len(spans)
    text, truncated = got
    lines = _split_lines(text)
    reliable = _reliable_line_count(text, truncated, lines)
    return [
        "" if (truncated and e > reliable)
        else _hash_from_lines(lines, s, e)
        for s, e in spans
    ]


def hash_spans_text(
    text: str,
    spans: Sequence[tuple[int, int]],
) -> list[str]:
    """Hash spans of an in-memory *text* — same format as
    :func:`hash_spans` (SHA-256[:12] over the raw span lines), for
    producers that already hold the file content (e.g. the inventory
    builder stamping per-item span hashes at parse time).

    Invalid ranges produce ``""`` for that span.
    """
    lines = _split_lines(text)
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
            except (OSError, RuntimeError, ValueError):
                # Same tolerance set as core.paths.confine: ValueError
                # covers embedded-NUL paths (hostile CheckItems),
                # RuntimeError covers symlink loops on older Pythons.
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

    # Guarded read: ``exists()`` above is True for a repo-planted FIFO,
    # and a bare ``read_text`` then blocks the whole batch forever
    # (open() on a reader-less FIFO never returns); a planted multi-GB
    # file would load whole. ``read_text_capped`` opens O_NOFOLLOW |
    # O_NONBLOCK and fstat-checks S_ISREG on the fd — non-regular /
    # unreadable files degrade to "unknown" like any other read error.
    got = read_text_capped(file_path, DEFAULT_MAX_SOURCE_CHARS)
    if got is None:
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
    text, truncated = got

    lines = _split_lines(text)
    reliable = _reliable_line_count(text, truncated, lines)
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

        if truncated and item.end_line > reliable:
            # The span reaches past the capped read (or touches its
            # cut-mid-content final line): the file is larger than
            # the cap, so an empty/partial slice is a read-bound
            # artifact, not evidence the span vanished or changed —
            # "unknown", never a false "modified".
            results[idx] = SpanResult(
                status="unknown",
                current_hash="",
                current_norm_hash="",
                span=span,
            )
            continue

        current_hash = _hash_from_lines(lines, item.start_line, item.end_line)

        if not current_hash:
            # Empty slice on a READABLE file: the span lies wholly
            # past EOF (file rewritten shorter, replaced with a
            # stub). With a stored hash that is POSITIVE evidence the
            # quoted span no longer exists — report modified so the
            # lenient quarantine (which keeps "unknown" fresh) demotes
            # the entry's [verbatim]/receipt authority. Only a span
            # with nothing stored to compare against stays unknown.
            results[idx] = SpanResult(
                status="modified" if item.stored_hash else "unknown",
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

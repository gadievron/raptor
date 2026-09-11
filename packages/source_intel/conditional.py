"""Preprocessor-conditional context capture for cocci matches.

For each cocci match at (file, line), determine whether the line sits
inside an ``#if`` / ``#ifdef`` / ``#ifndef`` block. If so, record the
condition text — Stage D LLM consumer downweights matches behind
unknown conditions because they may not apply to the binary actually
built.

Scope (Phase 3c v1):
  * Tracks ``#if``, ``#ifdef``, ``#ifndef``, ``#elif`` openers + their
    matching ``#endif`` closers. Treats ``#else`` as continuation.
  * Returns the IMMEDIATELY enclosing condition — innermost when
    nested. Outer conditions aren't tracked in v1.
  * Pure-text scan; no preprocessor expansion. Doesn't resolve the
    condition's logical value — just records what was written.
  * File-level cache so repeated lookups within the same file amortise
    the line scan.

Limitations (documented; tightened in later axes):
  * ``#elif`` is treated as a continuation of the most recent ``#if``-
    family opener for nesting purposes. The Stage D LLM sees the
    OUTER condition; if the actual match was in a ``#elif`` branch,
    we don't capture that. Real fix needs full preprocessor-state
    tracking (out of v1 scope).
  * Comments / strings containing literal ``#if`` text would confuse
    the scanner. Practical impact is low for kernel/curl-style code
    where preprocessor directives appear column-1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


# Match preprocessor directives. Group 1 is the directive name; group 2
# is the rest of the line (the condition for #if-family openers).
_DIRECTIVE_RE = re.compile(
    r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b\s*(.*)$",
)


@dataclass(frozen=True)
class ConditionalBlock:
    """One ``#if*`` … ``#endif`` block in the source file."""

    start_line: int  # 1-based line of the opening directive
    end_line: int    # 1-based line of the matching #endif
    condition: str   # raw text of the condition (e.g. "CONFIG_HARDENING")
    directive: str   # "if" | "ifdef" | "ifndef"


def _index_file(path_str: str) -> tuple[ConditionalBlock, ...]:
    """Parse a file and cache the list of conditional blocks.

    Returns an empty tuple when the file can't be read or contains
    no preprocessor conditionals. The cache key includes the file's
    (mtime_ns, size) alongside the path, so an edited file re-parses
    automatically — a path-only key would keep serving pre-edit
    blocks to fresh analyze() runs in long-lived processes, attaching
    wrong #if conditions to new match lines.
    """
    try:
        st = Path(path_str).stat()
    except OSError:
        return ()
    return _index_file_stat(path_str, st.st_mtime_ns, st.st_size)


@lru_cache(maxsize=512)
def _index_file_stat(
    path_str: str, mtime_ns: int, size: int,
) -> tuple[ConditionalBlock, ...]:
    """Cached parse behind :func:`_index_file` — keyed on the stat
    identity captured by the caller (the extra params exist purely
    to participate in the lru_cache key)."""
    path = Path(path_str)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()

    blocks: list[ConditionalBlock] = []
    open_stack: list[tuple[int, str, str]] = []  # (line, directive, condition)
    for n, line in enumerate(text.split("\n"), start=1):
        m = _DIRECTIVE_RE.match(line)
        if not m:
            continue
        directive = m.group(1).lower()
        rest = m.group(2).strip()

        if directive in ("if", "ifdef", "ifndef"):
            open_stack.append((n, directive, rest))
        elif directive == "endif" and open_stack:
            start_line, dir_open, cond = open_stack.pop()
            blocks.append(ConditionalBlock(
                start_line=start_line,
                end_line=n,
                condition=cond,
                directive=dir_open,
            ))
        # `elif` and `else` are continuations of the current block —
        # we don't change the stack. v1 limitation documented in the
        # module docstring.

    # Unclosed openers (malformed source) — ignore. We could produce
    # synthetic blocks running to EOF but that's risky on real code.
    return tuple(blocks)


def enclosing_condition(file_path: str, line: int) -> str | None:
    """Return the condition text of the innermost ``#if*`` block that
    contains ``line`` in ``file_path``, or ``None`` if the line is not
    inside any conditional.

    For nested blocks, the INNERMOST is returned — that's the
    condition closest to the match site and most directly relevant.
    """
    if not file_path or line <= 0:
        return None
    blocks = _index_file(file_path)
    # Find blocks containing the line; pick the one with the largest
    # start_line (innermost — opens last, before the matched line).
    enclosing: ConditionalBlock | None = None
    for block in blocks:
        if block.start_line <= line <= block.end_line:
            if enclosing is None or block.start_line > enclosing.start_line:
                enclosing = block
    if enclosing is None:
        return None
    # Empty condition (e.g. ``#if`` with no expression — malformed) →
    # report the directive for context.
    if not enclosing.condition:
        return enclosing.directive
    return enclosing.condition


def clear_cache() -> None:
    """Drop the file-index cache. Stat-keyed invalidation already
    covers file edits; this is the explicit whole-cache reset."""
    _index_file_stat.cache_clear()

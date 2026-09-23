"""Module-level reachability for Go module deps.

Walks ``*.go`` files outside ``vendor/`` trees — ``*_test.go`` files
included, each hit tagged ``is_test`` — extracts ``import
"<module-path>"`` statements (single + parenthesised block forms), and
matches each module path against the dep's name. ``resolve_dep``
discounts test-only hits: a module imported only from ``*_test.go``
files resolves ``not_reachable``.

Match semantics: a dep ``github.com/foo/bar`` is "imported" when any
import path is exactly that, OR is a sub-package of it
(``github.com/foo/bar/sub`` counts).
"""

from __future__ import annotations

import logging
import re

from ..models import Confidence, Reachability
from ._shared import format_evidence as _format_evidence
from ._shared import iter_matches_with_lines as _iter_matches_with_lines
from ..parsers import _safe_read
from typing import TYPE_CHECKING
from core.source.lines import split_lines

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)


_DEFAULT_MAX_DEPTH = 12

# Single-line: ``import "foo"`` (with optional alias prefix).
# Leading indent is HORIZONTAL-only ([^\S\n]): under MULTILINE the
# ``^\s*`` spelling re-scans a run of blank lines from every line
# start inside it — quadratic on attacker-supplied source files.
_IMPORT_SINGLE_RE = re.compile(
    r'^[^\S\n]*import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"',
    re.MULTILINE,
)
# Block form: ``import (\n  "foo"\n  alias "bar"\n)``. Only the
# opener is matched by regex — the body is parsed line-wise, because
# a greedy-to-first-')' body match truncates the block at any ')'
# inside a trailing comment (``"fmt" // formatting (stdlib)``) and
# silently drops every subsequent import.
_IMPORT_BLOCK_OPEN_RE = re.compile(r"^\s*import\s*\(")
# Applied per-line via ``.match`` (no blank-run exposure), but the
# indent keeps the horizontal spelling anyway — identical match set
# on a single line, and no MULTILINE ^\s* member for the idiom
# census to chase.
_BLOCK_LINE_RE = re.compile(
    r'^[^\S\n]*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"]+)"',
    re.MULTILINE,
)


def scan_imports(
    target: Path, *, max_depth: int = _DEFAULT_MAX_DEPTH,
) -> dict[str, list[tuple[Path, int, bool]]]:
    """Return ``{import_path: [(file, line, is_test), ...]}``."""
    target = target.resolve()
    out: dict[str, list[tuple[Path, int, bool]]] = {}
    for go_file in _walk_go_sources(target, max_depth=max_depth):
        is_test = _is_test_file(go_file)
        text = _safe_read.read_bounded(go_file, follow_symlinks=False)
        if text is None:
            continue
        for path, line in _imports_in(text):
            out.setdefault(path, []).append((go_file, line, is_test))
    return out


def resolve_dep(
    dep_name: str,
    scan: dict[str, list[tuple[Path, int, bool]]],
    *,
    target: Path | None = None,
    advisory_symbols: list[str] | None = None,
) -> Reachability:
    """Look up ``dep_name`` (a Go module path) in the scan.

    When ``advisory_symbols`` is provided (from OSV ``ecosystem_specific
    .imports[].symbols``), a second pass checks whether any of those
    function/type names appear in the importing Go files. A match
    upgrades the verdict from ``imported`` to ``likely_called``.
    """
    matches: list[tuple[Path, int, bool]] = []
    prefix = dep_name.rstrip("/") + "/"
    for path, hits in scan.items():
        if path == dep_name or path.startswith(prefix):
            matches.extend(hits)

    if not matches:
        return Reachability(
            verdict="not_reachable",
            confidence=Confidence(
                "medium",
                reason=f"no `import \"{dep_name}\"` found",
            ),
            evidence=[],
        )
    non_test = [h for h in matches if not h[2]]
    if non_test:
        if advisory_symbols:
            symbol_hits = _grep_symbols(non_test, advisory_symbols)
            if symbol_hits:
                evidence = _format_evidence(non_test, target=target)
                evidence.extend(
                    f"[symbol] {sym}" for sym in symbol_hits[:5]
                )
                return Reachability(
                    verdict="likely_called",
                    confidence=Confidence(
                        "high",
                        reason=(
                            f"import + advisory symbol(s) "
                            f"({', '.join(symbol_hits[:3])}) found in source"
                        ),
                    ),
                    evidence=evidence,
                )
        return Reachability(
            verdict="imported",
            confidence=Confidence(
                "high",
                reason="import found in non-test Go source",
            ),
            evidence=_format_evidence(non_test, target=target),
        )
    return Reachability(
        verdict="not_reachable",
        confidence=Confidence(
            "medium",
            reason="module referenced only by *_test.go files",
        ),
        evidence=_format_evidence(matches, target=target),
    )


def _grep_symbols(
    hits: list[tuple[Path, int, bool]],
    symbols: list[str],
) -> list[str]:
    """Check whether any advisory-listed symbols appear in the source files.

    Returns the subset of ``symbols`` that were found (identifier-boundary
    match, not substring).
    """
    # Stream file-by-file: buffering every importing file's full
    # text simultaneously (then joining, doubling it) held multiple
    # bounded-at-50MB files in memory at once with no total budget.
    # One file is resident at a time; symbols already found are not
    # re-searched, and the sweep stops early once every symbol hit.
    patterns = {
        sym: re.compile(r"\b" + re.escape(sym) + r"\b")
        for sym in dict.fromkeys(symbols)
    }
    found: set[str] = set()
    files_checked: set = set()
    for f, _, _ in hits:
        if f in files_checked:
            continue
        files_checked.add(f)
        if len(found) == len(patterns):
            break
        text = _safe_read.read_bounded(f, follow_symlinks=False)
        if text is None:
            continue
        for sym, pat in patterns.items():
            if sym not in found and pat.search(text):
                found.add(sym)
    return [sym for sym in patterns if sym in found]


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _code_before_close(line: str) -> tuple[str, bool]:
    """Split a block-body line at the first unquoted ``)`` or ``//``.

    Returns ``(code, closed)`` where ``code`` is the prefix that can
    carry an import spec and ``closed`` says whether an unquoted
    ``)`` — the block terminator — appeared before any line comment.
    A ``)`` inside a quoted import path or a ``//`` comment must NOT
    close the block.
    """
    in_quote = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_quote = not in_quote
        elif not in_quote:
            if ch == ")":
                return line[:i], True
            if ch == "/" and line[i:i + 2] == "//":
                return line[:i], False
    return line, False


def _imports_in(text: str) -> Iterable[tuple[str, int]]:
    # Single-line. Rolling-cursor line numbers — the naive
    # full-prefix count is quadratic on dense-import files.
    for m, line in _iter_matches_with_lines(
            text, _IMPORT_SINGLE_RE.finditer(text)):
        yield m.group(1), line
    # Block form — parsed line-wise from ``import (`` to the line
    # carrying the unquoted closing ``)``.
    in_block = False
    for line_no, line in enumerate(split_lines(text), start=1):
        if not in_block:
            open_m = _IMPORT_BLOCK_OPEN_RE.match(line)
            if not open_m:
                continue
            # Same-line body (``import ( "fmt" )``) is legal Go.
            code, closed = _code_before_close(line[open_m.end():])
            line_m = _BLOCK_LINE_RE.match(code.lstrip())
            if line_m:
                yield line_m.group(1), line_no
            in_block = not closed
        else:
            code, closed = _code_before_close(line)
            line_m = _BLOCK_LINE_RE.match(code)
            if line_m:
                yield line_m.group(1), line_no
            in_block = not closed


def _walk_go_sources(
    target: Path, *, max_depth: int,
) -> Iterable[Path]:
    from ._walker import iter_source_files
    return iter_source_files(target, {".go"}, max_depth=max_depth)


def _is_test_file(path: Path) -> bool:
    return path.name.endswith("_test.go")


"""TranslationView — the parser's view of a source file.

The C/C++ inventory and call graph are built on *unpreprocessed* text:
tree-sitter doesn't run the C preprocessor, so `#if 0` arms, both sides of
every `#ifdef`, and unexpanded macros all reach the parser as if live. This
module introduces a seam: the extraction path reads a ``TranslationView``
(its ``parse_text``) rather than raw file content, so increasingly faithful
preprocessing can be slotted in *behind* the seam without rewiring any
consumer.

Fidelity ladder (the view's ``fidelity`` field):

  * 0 — raw text (today's behavior; what non-C/C++ always gets).
  * 1 — ``#if 0`` / literal-false arms blanked in-memory (layer 1).
  * 2 — plus function-like-macro masking flags recorded (layer 2).
  * 3 — real ``cpp`` with a build config; one variant; macros expanded;
        a non-identity ``line_map`` from ``#line`` markers (layer 3, later).

Two fields are first-class from the start specifically so layer 3 is a
provider swap rather than a rewrite:

  * ``line_map`` — maps a parse-text line back to an original source line.
    Identity at fidelity < 3 (blanking preserves line numbers); real once
    macro expansion / ``#include`` inlining renumber lines.
  * ``fidelity`` — lets the reachability resolver decide witness soundness
    (a C ``NOT_CALLED`` at fidelity < 3 is never sound — an unresolved arm
    or unexpanded macro could call the function).

The mode (``allow_unreachable``) reaches *this* layer, not just the
suppression policy: in isolation mode the provider returns the raw/union
view so disabled code is still present for the operator to review (a
suppression-layer override is useless if extraction already deleted it).

No on-disk mutation, ever: the view is a transient in-memory transform of
``content``; the real file is never touched (and ``sha256`` / line counts
are taken from the real content by the caller).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Languages whose extraction goes through the C-preprocessor-aware path.
_C_FAMILY = frozenset({"c", "cpp"})

_PP_DIRECTIVE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")


def _pp_cond(kind: str, rest: str) -> str:
    """Classify an #if/#elif controlling expression as
    'false' | 'true' | 'unknown'. Only literal 0/1 are decidable without a
    build config — `#ifdef X` / `#if SYMBOL` / `#if EXPR` are config- or
    value-dependent and MUST stay 'unknown' (firing on them would wrongly
    delete code that is live in some build → a false negative)."""
    if kind in ("ifdef", "ifndef"):
        return "unknown"
    r = re.sub(r"/\*.*?\*/", "", rest)
    r = re.sub(r"//.*$", "", r).strip()
    if r in ("0", "(0)", "00"):
        return "false"
    if r in ("1", "(1)"):
        return "true"
    return "unknown"


def detect_preprocessor_dead_ranges(content: str) -> List[Tuple[int, int]]:
    """Inclusive 1-indexed line ranges of statically-dead preprocessor arms
    (`#if 0` / `#elif 0`, and the `#else` of a `#if 1`). Config-INDEPENDENT
    only — dead under every build configuration. Nesting-aware: anything
    inside a dead arm is dead. Validated 0 over-fires across OpenSSL's ~17k
    `#ifdef` directives."""
    lines = content.split("\n")
    stack: list[dict] = []
    dead: set[int] = set()
    for i, line in enumerate(lines, 1):
        m = _PP_DIRECTIVE.match(line)
        if not m:
            if stack and stack[-1]["effective_dead"]:
                dead.add(i)
            continue
        kind, rest = m.group(1), m.group(2)
        parent_dead = stack[-1]["effective_dead"] if stack else False
        if kind in ("if", "ifdef", "ifndef"):
            lit = _pp_cond(kind, rest)
            f = {"parent_dead": parent_dead, "taken": lit == "true",
                 "arm_dead": lit == "false"}
            f["effective_dead"] = parent_dead or f["arm_dead"]
            stack.append(f)
        elif kind == "elif" and stack:
            f = stack[-1]
            lit = _pp_cond("elif", rest)
            if f["taken"] or lit == "false":
                f["arm_dead"] = True
            elif lit == "true":
                f["arm_dead"], f["taken"] = False, True
            else:
                f["arm_dead"] = False
            f["effective_dead"] = f["parent_dead"] or f["arm_dead"]
        elif kind == "else" and stack:
            f = stack[-1]
            f["arm_dead"] = bool(f["taken"])   # dead iff a true arm was taken
            f["effective_dead"] = f["parent_dead"] or f["arm_dead"]
        elif kind == "endif" and stack:
            stack.pop()
    ranges: List[Tuple[int, int]] = []
    run: Optional[list] = None
    for ln in sorted(dead):
        if run and ln == run[1] + 1:
            run[1] = ln
        else:
            if run:
                ranges.append((run[0], run[1]))
            run = [ln, ln]
    if run:
        ranges.append((run[0], run[1]))
    return ranges


def _blank_ranges(content: str, ranges: List[Tuple[int, int]]) -> str:
    """Replace the body of each dead range with same-length spaces, keeping
    newlines so byte/line offsets — and therefore the identity line_map —
    are preserved. The on-disk file is untouched."""
    if not ranges:
        return content
    lines = content.split("\n")
    dead = set()
    for lo, hi in ranges:
        dead.update(range(lo, hi + 1))
    out = []
    for i, line in enumerate(lines, 1):
        out.append(re.sub(r"[^\n]", " ", line) if i in dead else line)
    return "\n".join(out)


@dataclass(frozen=True)
class LineMap:
    """Maps a 1-indexed line in ``parse_text`` back to a 1-indexed line in
    the original source.

    ``entries`` empty ⇒ identity (parse line == source line), which is the
    case at fidelity < 3 because in-memory blanking replaces characters
    with spaces and never adds or removes newlines. Layer 3 populates a real
    mapping (parsed-line → source-line) from ``cpp``'s ``#line`` markers.
    """
    # Sorted tuple of (parse_line, source_line) breakpoints. Empty = identity.
    entries: Tuple[Tuple[int, int], ...] = ()

    def to_source(self, parse_line: int) -> int:
        if not self.entries:
            return parse_line
        # Find the last breakpoint at or before parse_line (layer 3 use).
        src = parse_line
        for p_line, s_line in self.entries:
            if p_line <= parse_line:
                src = s_line + (parse_line - p_line)
            else:
                break
        return src


IDENTITY_LINE_MAP = LineMap()


@dataclass(frozen=True)
class TranslationView:
    """What the parser sees, plus provenance for the reachability layer."""
    parse_text: str
    line_map: LineMap = IDENTITY_LINE_MAP
    fidelity: int = 0
    masking_flags: frozenset = field(default_factory=frozenset)
    config: Optional[object] = None     # BuildConfig placeholder (layer 3)


def preprocess_view(
    path: str,
    language: str,
    content: str,
    *,
    allow_unreachable: bool = False,
    config: Optional[object] = None,
) -> TranslationView:
    """Return the parser's view of ``content``.

    Non-C/C++ → identity view (fidelity 0): byte-identical to today, so the
    seam is free for every other language. C/C++ handling (``#if 0``
    blanking + macro flags) is layered on in subsequent units; for now this
    is the identity provider so introducing the seam changes no behavior.
    """
    # Non-C/C++ → identity (byte-identical to today).
    if language not in _C_FAMILY:
        return TranslationView(parse_text=content, line_map=IDENTITY_LINE_MAP,
                               fidelity=0, masking_flags=frozenset(),
                               config=config)

    # In-isolation mode: the operator wants to review everything, including
    # disabled code. Return the raw/union view (no blanking) so dead arms
    # are present for analysis. (The suppression-policy layer also disables
    # may_suppress under this flag — see U5/witness model.)
    if allow_unreachable:
        return TranslationView(parse_text=content, line_map=IDENTITY_LINE_MAP,
                               fidelity=0, masking_flags=frozenset(),
                               config=config)

    # Default C/C++ view (fidelity 1): blank statically-dead `#if 0` arms
    # in-memory before the parser sees them. tree-sitter doesn't run the
    # preprocessor, so without this, functions (and parser garbage) inside
    # `#if 0` enter the inventory + call graph as if live. Config-dependent
    # `#ifdef` arms are NOT touched — that needs real preprocessing (layer
    # 3). line_map stays identity (blanking preserves line numbers).
    dead = detect_preprocessor_dead_ranges(content)
    parse_text = _blank_ranges(content, dead)
    return TranslationView(parse_text=parse_text, line_map=IDENTITY_LINE_MAP,
                           fidelity=1, masking_flags=frozenset(), config=config)


__all__ = [
    "LineMap",
    "IDENTITY_LINE_MAP",
    "TranslationView",
    "preprocess_view",
    "detect_preprocessor_dead_ranges",
    "_C_FAMILY",
]

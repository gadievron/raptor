"""TranslationView — the parser's view of a source file.

The C/C++ inventory and call graph are built on *unpreprocessed* text:
tree-sitter doesn't run the C preprocessor, so `#if 0` arms, both sides of
every `#ifdef`, and unexpanded macros all reach the parser as if live. This
module introduces a seam: the extraction path reads a ``TranslationView``
(its ``parse_text``) rather than raw file content, so increasingly faithful
preprocessing can be slotted in *behind* the seam without rewiring any
consumer.

Fidelity ladder (the view's ``fidelity`` field):

  * 0 — raw text (what non-C/C++ and isolation mode always get).
  * 1 — literal-only dead arms blanked: ``#if 0`` / ``#elif 0`` and the
        ``#else`` of ``#if 1`` (config-INDEPENDENT, dead under every build).
  * 2 — config-aware dead arms: also ``#ifdef X`` / ``#ifndef X`` /
        ``#if defined(X)`` / ``#if X`` resolved against a build
        :class:`~core.build.macro_config.MacroConfig` (explicit
        ``-D``/``-U`` / ``.config``). Config-DEPENDENT → heuristic, not sound.
  * 3 — real ``cpp`` with full macro expansion + ``#line``-derived
        non-identity ``line_map`` (deferred; line-preserving config-aware
        blanking at layer 2 captures the dominant extraction win soundly,
        without a subprocess or ``#include`` inlining).

Function-like-macro call targets (``#define CALL_F() f()``) are handled
orthogonally by ``detect_macro_call_targets`` — consumed by the resolver to
keep a macro-only-reachable function UNCERTAIN rather than NOT_CALLED — not
via a fidelity level.

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

# Languages whose extraction goes through the C-preprocessor-aware path.
_C_FAMILY = frozenset({"c", "cpp"})

_PP_DIRECTIVE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")

# `#if`/`#elif` operand forms we resolve against a config. Single-term only —
# compound expressions (``&&`` / ``||`` / comparisons / arithmetic) stay
# 'unknown' rather than risk a wrong partial evaluation (a false negative).
_DEFINED_RE = re.compile(r"^(!\s*)?defined\s*\(\s*(\w+)\s*\)$")
_DEFINED_BARE_RE = re.compile(r"^(!\s*)?defined\s+(\w+)$")
_IDENT_RE = re.compile(r"^(\w+)$")


def _strip_pp_comments(rest: str) -> str:
    # bounded comment gap: an unbounded gap lets a hostile directive
    # line planting `/*` openers re-scan the tail per opener —
    # quadratic; real one-line comments sit far inside 500 chars.
    r = re.sub(r"/\*.{0,500}?\*/", "", rest)
    return re.sub(r"//.*$", "", r).strip()


def _eval_int_literal(s: str) -> int | None:
    """Parse a bare integer literal (decimal / 0x-hex, optional surrounding
    parens / L/U suffix). Returns ``None`` for anything non-trivial — we only
    evaluate values we can be certain about."""
    t = s.strip()
    while t.startswith("(") and t.endswith(")"):
        t = t[1:-1].strip()
    t = re.sub(r"[uUlL]+$", "", t)
    try:
        return int(t, 0) if t else None
    except ValueError:
        return None


def _pp_cond(kind: str, rest: str, macros: object | None = None) -> str:
    """Classify an #if/#ifdef/#ifndef/#elif controlling expression as
    'false' | 'true' | 'unknown'.

    Without a config only literal ``0``/``1`` are decidable; ``#ifdef X`` and
    value-dependent ``#if`` stay 'unknown'. With a :class:`MacroConfig`
    (``macros``) we additionally resolve forms whose every symbol is KNOWN
    (explicitly ``-D``/``-U`` or named in ``.config``):

      * ``#ifdef X`` / ``#ifndef X``
      * ``#if defined(X)`` / ``#if !defined(X)`` (and ``defined X``)
      * ``#if X`` where X is known-defined to an integer literal, or
        known-undefined (→ 0 in ``#if`` per C semantics).

    A symbol absent from the config stays UNKNOWN — it may be ``#define``d in
    an included header, so we must not treat absence as undefined (that would
    delete live code → false negative). Compound expressions stay 'unknown'.
    """
    if kind in ("ifdef", "ifndef"):
        m = _IDENT_RE.match(_strip_pp_comments(rest))
        if not (m and macros):
            return "unknown"
        d = macros.is_defined(m.group(1))
        if d is None:
            return "unknown"
        defined_true = d if kind == "ifdef" else (not d)
        return "true" if defined_true else "false"

    r = _strip_pp_comments(rest)
    if r in ("0", "(0)", "00"):
        return "false"
    if r in ("1", "(1)"):
        return "true"
    if not macros:
        return "unknown"

    # defined(X) / !defined(X) / defined X
    dm = _DEFINED_RE.match(r) or _DEFINED_BARE_RE.match(r)
    if dm:
        d = macros.is_defined(dm.group(2))
        if d is None:
            return "unknown"
        res = (not d) if dm.group(1) else d
        return "true" if res else "false"

    # bare single identifier: #if MACRO
    im = _IDENT_RE.match(r)
    if im:
        name = im.group(1)
        val = macros.value_of(name)
        if val is not None:
            iv = _eval_int_literal(val)
            return "unknown" if iv is None else ("true" if iv != 0 else "false")
        # known-undefined identifier evaluates to 0 in #if → false. Absent
        # (unknown) stays unknown — header might define it.
        if macros.is_defined(name) is False:
            return "false"
    return "unknown"


# C++ raw-string opener: optional encoding prefix, then R"delim( —
# the delimiter is at most 16 chars, none of space/parens/backslash.
_PP_RAW_STRING_OPEN = re.compile(r'(?:u8|[uUL])?R"([^ ()\\\t\v\f]{0,16})\(')


def _skip_line_literal(line: str, start: int) -> int:
    """Advance past a ``"…"`` / ``'…'`` literal opened at ``start``
    within one physical line, honouring backslash escapes. Returns the
    index just past the closing quote, or ``len(line)`` when the
    literal doesn't close on this line (a real compiler diagnoses
    that; treating the tail as literal text is the state-reset that
    matches it)."""
    quote = line[start]
    i = start + 1
    n = len(line)
    while i < n:
        c = line[i]
        if c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return n


def _is_digit_separator(line: str, i: int) -> bool:
    """True when the ``'`` at ``i`` is a C++14 digit separator
    (``1'000``, ``0xAB'CD``) rather than a character-literal opener:
    the identifier/number token ending just before it starts with a
    digit."""
    j = i - 1
    while j >= 0 and (line[j].isalnum() or line[j] == "_"):
        j -= 1
    return j + 1 < i and line[j + 1].isdigit()


# Translation phase 2: a backslash at end of line splices the next
# physical line onto it. GCC and Clang additionally splice when
# whitespace (space, tab, vertical tab, form feed — gcc-verified for
# every member — or a CR left behind by CRLF content split on "\n")
# separates the backslash from the newline — diagnostics only,
# semantics unchanged. Matching only a bare trailing "\\" made every
# backslash-space and backslash-CRLF splice a divergence the compiler
# resolves the other way (blanking compiled functions out of the
# parse view). A strict-standard compiler that refuses the
# whitespace-separated splice diverges only toward under-blanking
# (dead code stays visible — the cheap failure).
_PP_SPLICE_RE = re.compile(r"\\[ \t\v\f\r]*$")


def _ends_with_splice(line: str) -> bool:
    return _PP_SPLICE_RE.search(line) is not None


def _pp_directive_line_view(
    content: str, language: str = "c",
) -> list[str | None]:
    r"""Per physical line: the translation-phase-3 view the compiler's
    directive processor sees, or ``None`` when no directive starting
    on this line can be honoured.

    Comments are removed in translation phase 3, BEFORE phase-4
    directive processing — so a directive-shaped line inside a
    ``/* */`` block comment is comment text (honouring it lets a
    hostile repo blank live code out of the parse view:
    ``/*\n#if 0\n*/`` around a live function), while a directive
    AFTER a comment close on the same line (``*/ #endif``) IS
    honoured (the comment becomes whitespace, leaving ``#`` the
    line's first token). Emitting the per-line phase-3 text — comment
    content blanked to spaces, string/char literal text kept — gives
    the range detector both facts at once instead of a line-start
    boolean that could only represent the first.

    ``None`` marks the lines no directive can start on: a line
    spliced onto the previous logical line by a trailing backslash
    (see ``_PP_SPLICE_RE``; includes spliced ``//`` comments), and —
    in C++ — a line beginning inside a raw string. Raw strings are
    tracked for ``language == "cpp"`` ONLY: C has no raw strings
    (``R"(…`` is an identifier followed by a plain string there), and
    hallucinating a never-closing raw string inside a real ``#if 0``
    arm would mask the arm's real ``#endif`` and over-blank the live
    code after it. Divergence doctrine: outside that raw-string case,
    hallucinating an opener the compiler doesn't see only masks
    directives (under-blank — dead code stays visible, the cheap
    failure); the scanner must never MISS an opener the compiler
    sees, which is what the literal/raw-string tracking is for."""
    lines = content.split("\n")
    view: list[str | None] = [None] * len(lines)
    raw_strings = language == "cpp"
    in_comment = False
    raw_delim: str | None = None
    continued = False          # previous physical line ends in a splice
    in_line_comment = False    # …and that line was inside a // comment
    for idx, line in enumerate(lines):
        if in_line_comment:
            # Spliced continuation of a // comment: the whole line is
            # comment text.
            view[idx] = None
            in_line_comment = _ends_with_splice(line)
            continue
        capable = raw_delim is None and not continued
        continued = _ends_with_splice(line)
        p3: list[str] = []
        i = 0
        n = len(line)
        while i < n:
            if in_comment:
                e = line.find("*/", i)
                if e == -1:
                    p3.append(" " * (n - i))
                    i = n
                    continue
                p3.append(" " * (e + 2 - i))
                in_comment = False
                i = e + 2
                continue
            if raw_delim is not None:
                needle = ")" + raw_delim + '"'
                e = line.find(needle, i)
                if e == -1:
                    p3.append(line[i:])
                    i = n
                    continue
                p3.append(line[i:e + len(needle)])
                raw_delim = None
                i = e + len(needle)
                continue
            c = line[i]
            if c == "/" and i + 1 < n and line[i + 1] == "/":
                in_line_comment = continued
                p3.append(" " * (n - i))
                break
            if c == "/" and i + 1 < n and line[i + 1] == "*":
                in_comment = True
                p3.append("  ")
                i += 2
                continue
            if raw_strings and c in "uULR":
                # Raw-string opener only at a token boundary
                # (``xR"(…)"`` is an identifier then a plain string).
                at_boundary = i == 0 or not (
                    line[i - 1].isalnum() or line[i - 1] == "_")
                if at_boundary:
                    m = _PP_RAW_STRING_OPEN.match(line, i)
                    if m:
                        raw_delim = m.group(1)
                        p3.append(line[i:m.end()])
                        i = m.end()
                        continue
                p3.append(c)
                i += 1
                continue
            if c == "'" and _is_digit_separator(line, i):
                p3.append(c)
                i += 1
                continue
            if c in "\"'":
                j = _skip_line_literal(line, i)
                p3.append(line[i:j])
                i = j
                continue
            p3.append(c)
            i += 1
        view[idx] = "".join(p3) if capable else None
    return view


def detect_preprocessor_dead_ranges(
    content: str, macros: object | None = None,
    *, language: str = "c",
) -> list[tuple[int, int]]:
    """Inclusive 1-indexed line ranges of statically-dead preprocessor arms.

    Without ``macros``: literal-only — ``#if 0`` / ``#elif 0`` and the
    ``#else`` of a ``#if 1``. Config-INDEPENDENT (dead under every build),
    validated 0 over-fires across OpenSSL's ~17k ``#ifdef`` directives.

    With a :class:`~core.build.macro_config.MacroConfig` (``macros``): also
    resolves ``#ifdef`` / ``#ifndef`` / ``#if defined(X)`` / ``#if X`` arms
    whose symbols are explicitly KNOWN in the build config. Still cannot
    over-fire: symbols absent from the config stay 'unknown' (untouched).
    Config-DEPENDENT, so the resulting view is heuristic, not sound.

    Directive recognition is comment/splice-aware — and raw-string
    aware when ``language == "cpp"`` (see
    :func:`_pp_directive_line_view`) — a ``#if 0`` inside a ``/* */``
    comment is comment text to the compiler and must not blank the
    live code that follows, while a directive after a same-line
    comment close (``*/ #endif``) IS honoured (phase 3 turns the
    comment into whitespace before phase 4 processes the line).

    Nesting-aware: anything inside a dead arm is dead.
    """
    lines = content.split("\n")
    p3_lines = _pp_directive_line_view(content, language)
    stack: list[dict] = []
    dead: set[int] = set()
    for i, line in enumerate(lines, 1):
        p3 = p3_lines[i - 1]
        m = _PP_DIRECTIVE.match(p3) if p3 is not None else None
        if m is not None:
            # Condition text: prefer the RAW line's match when the raw
            # line is directive-shaped — its rest (comments included,
            # handled by _strip_pp_comments exactly as before) keeps
            # every previously-honoured directive's evaluation
            # byte-identical. The phase-3 rest only feeds the NEWLY
            # honoured comment-close shape, where the raw line can't
            # match at all.
            raw_m = _PP_DIRECTIVE.match(line)
            if raw_m is not None:
                m = raw_m
        if not m:
            if stack and stack[-1]["effective_dead"]:
                dead.add(i)
            continue
        kind, rest = m.group(1), m.group(2)
        parent_dead = stack[-1]["effective_dead"] if stack else False
        if kind in ("if", "ifdef", "ifndef"):
            lit = _pp_cond(kind, rest, macros)
            f = {"parent_dead": parent_dead, "taken": lit == "true",
                 "arm_dead": lit == "false"}
            f["effective_dead"] = parent_dead or f["arm_dead"]
            stack.append(f)
        elif kind == "elif" and stack:
            f = stack[-1]
            lit = _pp_cond("elif", rest, macros)
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
    ranges: list[tuple[int, int]] = []
    run: list | None = None
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


_FUNC_MACRO_DEF = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]*\(([^)]*)\)(.*)$", re.MULTILINE,
)
_CALL_IN_BODY = re.compile(r"\b([A-Za-z_]\w*)[ \t]*\(")
# Control-flow / operator keywords that look like calls but aren't.
_C_NON_CALL_KW = frozenset({
    "if", "while", "for", "switch", "return", "sizeof", "defined",
    "do", "else", "case", "alignof", "_Alignof", "static_assert",
    "_Static_assert", "catch",
})


def _strip_c_literals_comments(s: str) -> str:
    """Blank string / char literals and comments in a (logical) macro body
    so call-shaped text inside them isn't mistaken for a routed call. Walks
    char-by-char; `//` ends the logical line. Returns the body with those
    spans removed."""
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            j = s.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            break
        if c in {'"', "'"}:
            q = c
            i += 1
            while i < n:
                if s[i] == "\\":
                    i += 2
                    continue
                if s[i] == q:
                    i += 1
                    break
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def detect_macro_call_targets(content: str) -> set:
    """Function names invoked inside *function-like* macro bodies.

    tree-sitter sees a macro invocation as a call to the macro name, not to
    whatever the body expands to — so a function reachable *only* via a
    macro (``#define CALL_F() f()``) reads NOT_CALLED in the static graph.
    The resolver treats any name in this set as UNCERTAIN rather than
    NOT_CALLED, closing that false negative. C/C++ only.

    Targeted, not blanket: a file using ordinary ``UPPER()`` macros doesn't
    taint every NOT_CALLED — only the specific names a macro body calls.
    String literals and comments in the body are stripped first so
    call-shaped text inside them (``"foo()"``, ``/* bar() */``) isn't
    mistaken for a routed call.
    """
    if not content or "define" not in content:
        return set()
    # Fold line-continuations with the same splice grammar the
    # directive scanner honours (_PP_SPLICE_RE): a backslash-CRLF or
    # backslash-space splice is how every CRLF file spells multi-line
    # macros, and folding only "\\\n" made detection silently lose the
    # UNCERTAIN rescue for macro-only-reachable functions there (the
    # false NOT_CALLED direction).
    joined = re.sub(r"\\[ \t\v\f\r]*\n", " ", content)
    targets: set = set()
    for m in _FUNC_MACRO_DEF.finditer(joined):
        macro_name = m.group(1)
        body = _strip_c_literals_comments(m.group(3))
        for c in _CALL_IN_BODY.finditer(body):
            name = c.group(1)
            if name != macro_name and name not in _C_NON_CALL_KW:
                targets.add(name)
    return targets


def _blank_ranges(content: str, ranges: list[tuple[int, int]]) -> str:
    """Replace the body of each dead range with same-length spaces, keeping
    newlines so byte/line offsets — and therefore the identity line_map —
    are preserved. The on-disk file is untouched."""
    if not ranges:
        return content
    lines = content.split("\n")
    dead: set[int] = set()
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
    entries: tuple[tuple[int, int], ...] = ()

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
    config: object | None = None     # BuildConfig placeholder (layer 3)


def preprocess_view(
    _path: str,
    language: str,
    content: str,
    *,
    allow_unreachable: bool = False,
    config: object | None = None,
) -> TranslationView:
    """Return the parser's view of ``content``.

    Non-C/C++ → identity view (fidelity 0): byte-identical, so the seam is
    free for every other language. C/C++ → dead preprocessor arms blanked
    in-memory: literal-only (fidelity 1) by default, or config-aware
    (fidelity 2) when ``config`` is a non-empty
    :class:`~core.build.macro_config.MacroConfig`. Isolation mode
    (``allow_unreachable``) returns the raw view so disabled code stays
    visible for review. No on-disk mutation; ``line_map`` is identity at
    every fidelity < 3 (blanking preserves line numbers).
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

    # Blank statically-dead arms in-memory before the parser sees them.
    # tree-sitter doesn't run the preprocessor, so without this, functions
    # (and parser garbage) inside dead arms enter the inventory + call graph
    # as if live. With a build macro config (``config``), resolve `#ifdef` /
    # `#if defined(X)` / `#if X` arms whose symbols are explicitly known
    # (fidelity 2); without one, literal-only `#if 0` (fidelity 1). Either
    # way line_map stays identity — blanking replaces dead-arm characters
    # with spaces and never moves a line.
    macros = config or None
    dead = detect_preprocessor_dead_ranges(content, macros, language=language)
    parse_text = _blank_ranges(content, dead)
    return TranslationView(parse_text=parse_text, line_map=IDENTITY_LINE_MAP,
                           fidelity=2 if macros else 1,
                           masking_flags=frozenset(), config=config)


__all__ = [
    "IDENTITY_LINE_MAP",
    "_C_FAMILY",
    "LineMap",
    "TranslationView",
    "detect_macro_call_targets",
    "detect_preprocessor_dead_ranges",
    "preprocess_view",
]

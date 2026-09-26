"""Token-enforcement coverage map — mechanical projection.

Answers, per entry point, the question audits keep answering by hand:
does this entry enforce the application's anti-request-forgery token
before doing anything observable?

The CHECK IDIOM is learned, never hardcoded: the study pass elicits
``token_checks`` vocabulary entries (which function(s) implement the
target's own enforcement idiom — see ``core.concepts.study``), and
this module only PROJECTS those learned names onto the entry points
via static call reachability inside each entry's pre-output prefix.
The generic name shapes in :data:`TOKEN_SEED_RE` are candidate
DISCOVERY seeds for the study pass; they never decide enforcement.

Statuses (``token-map.json``, one record per entry):

- ``enforced``      — a learned check function is called directly in
                      the entry's pre-output prefix.
- ``indirect``      — the check is reachable from a pre-output call
                      through ≥1 statically resolved intermediate
                      function.
- ``not_enforced``  — no path from the pre-output prefix to any check
                      function AND every reachability search ran to
                      natural exhaustion; the record carries the
                      absence census (which calls WERE seen).
- ``unknown``       — the prefix could not be decided: parse failure,
                      dynamic dispatch, unresolvable include, a
                      truncated search (call-depth or include-splice
                      budget), a config-dependent short open tag, or
                      no check function was learned at all. Unknown
                      never degrades to enforced OR not_enforced.

HONESTY CONTRACT (consumers): every status is hint-tier. ``enforced``
is a call-presence witness, NOT a bypass-freedom proof — a check call
behind a conditional (``conditional: true`` on the record) or inside a
callee's skip path still projects as enforced/indirect. No consumer
may suppress or down-rank a finding because an entry maps as
enforced.

Scope: PHP. The projection parses PHP with a deliberately small
lexer (comment/string stripping + brace tracking); anything it cannot
resolve statically becomes ``unknown``, never a guess.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TOKEN_MAP_VERSION = "1"
TOKEN_MAP_FILENAME = "token-map.json"

#: Candidate DISCOVERY seed shapes for the study pass (function names
#: worth showing to the LLM as possible token-idiom candidates). Seeds
#: propose; the study's evidence-verified classification disposes. A
#: name matching this regex earns NO enforcement authority, and a
#: learned check function does not need to match it.
TOKEN_SEED_RE = re.compile(r"(?i)(token|csrf|xsrf|nonce)")

#: Reachability search depth for the ``indirect`` status. Two-way
#: bound: deep enough for wrapper-of-wrapper idioms (entry → helper →
#: helper → check), shallow enough that a whole-app utility tangle
#: cannot launder an accidental path into "indirect". A search the cap
#: TRUNCATES (unvisited resolvable callees remained) poisons the
#: entry's absence claim to ``unknown`` — a deeper-than-cap real
#: enforcement chain must never read as ``not_enforced`` (a false
#: absence would feed the class-sweep seed generator).
MAX_CALL_DEPTH = 6

#: Include-splice recursion bound (also the cycle guard's backstop).
MAX_INCLUDE_DEPTH = 8

#: Total include-splice budget per entry. Depth and cycle guards alone
#: leave K sibling requires of the same target × depth = K^depth
#: re-splices (exponential time/memory on hostile trees). Both
#: directions of the bound: real entry files reach their guard include
#: within a handful of requires — 64 covers deep legitimate chains and
#: moderate diamond-include fan-outs; an over-budget entry degrades to
#: ``unknown`` ("include graph too large"), never to a partial splice
#: (a truncated splice could hide the check → false absence) and never
#: to unbounded work.
MAX_TOTAL_SPLICES = 64

_PHP_KEYWORDS = frozenset({
    "if", "else", "elseif", "while", "for", "foreach", "switch",
    "match", "isset", "empty", "unset", "list", "array", "function",
    "return", "echo", "print", "die", "exit", "new", "clone", "and",
    "or", "xor", "not", "declare", "catch",
    "require", "require_once", "include", "include_once",
})

_OUTPUT_CALLS = frozenset({
    "echo", "print", "printf", "vprintf", "print_r", "var_dump",
    "readfile", "passthru",
})

# Every repeat is bounded (identifier length, gap-to-paren window,
# include-argument window): the lexer runs over hostile repo text, and
# an unbounded repeat behind an unanchored scan is a quadratic pump
# (.github/tests/test_redos_idiom_census.py). Both directions of the
# bounds: 128-char identifiers / 32-char name-to-paren gaps / 512-char
# include arguments comfortably cover real code, while an
# attack-shaped over-limit construct simply produces no event (the
# projection degrades toward fewer claims, never toward unbounded
# scan cost).
_FUNC_DEF_RE = re.compile(
    r"\bfunction[^\S\n]{1,32}([A-Za-z_]\w{0,127})[^\S\n]{0,32}\(",
)
_CALL_RE = re.compile(
    r"(?<![\w$>])([A-Za-z_]\w{0,127})[^\S\n]{0,32}\(",
)
_DYNAMIC_RE = re.compile(
    r"\$[A-Za-z_]\w{0,127}[^\S\n]{0,32}\("     # $handler(...)
    r"|\bcall_user_func(?:_array)?\b"          # call_user_func*(...)
    r"|->[^\S\n]{0,32}[A-Za-z_]\w{0,127}[^\S\n]{0,32}\("  # $o->m(...)
    r"|::[^\S\n]{0,32}\$",                     # Cls::$var(...)
)
# Bounded to one statement line and a 512-char argument window; the
# argument text is re-trimmed in Python (parens/whitespace), keeping
# the regex free of overlapping trim quantifiers.
_INCLUDE_RE = re.compile(
    r"\b(?:require|include)(?:_once)?\b([^;\n]{0,512});",
)
_INCLUDE_LITERAL_RE = re.compile(
    r"^(?:__DIR__\s*\.\s*)?(['\"])([^'\"]+)\1$",
)
# Position-anchored (used via ``.match(text, pos)`` — never on a
# ``text[pos:]`` slice, which copies O(n) per tag and turns the tag
# walk quadratic on tag-dense hostile input).
_OPEN_TAG_RE = re.compile(r"<\?(?:php\b|=)?")
_HEREDOC_OPEN_RE = re.compile(
    r"<<<[^\S\r\n]{0,8}(['\"]?)([A-Za-z_]\w{0,127})\1\r?\n",
)


# ------------------------------------------------------------------
# PHP-lite lexing
# ------------------------------------------------------------------

def _strip_php(text: str) -> str:
    """Blank out comments, string literals, and heredocs, preserving
    offsets and line structure.

    Replaced characters become spaces (newlines are kept) so every
    downstream regex offset and line count refers to the original
    source. Include-path literals are re-read from the ORIGINAL text
    at the match offset, so blanking strings here is safe.
    """
    out = list(text)
    i, n = 0, len(text)

    def _blank(a: int, b: int) -> None:
        for j in range(a, min(b, n)):
            if out[j] != "\n":
                out[j] = " "

    while i < n:
        ch = text[i]
        two = text[i:i + 2]
        if two == "//" or ch == "#":
            end = text.find("\n", i)
            end = n if end == -1 else end
            _blank(i, end)
            i = end
        elif two == "/*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            _blank(i, end)
            i = end
        elif ch in ("'", '"'):
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch:
                    break
                j += 1
            _blank(i + 1, j)
            i = min(j + 1, n)
        elif two == "<<":
            # Position-anchored match — ``re.match(pat, text[i:])``
            # would copy the whole tail per ``<<`` token (quadratic on
            # shift-operator-dense hostile input).
            m = _HEREDOC_OPEN_RE.match(text, i)
            if m:
                # Horizontal-only anchor whitespace ([^\S\n]) — a
                # newline-capable run after a MULTILINE ^ re-anchors
                # across a hostile blank-line run quadratically.
                terminator = re.compile(
                    r"^[^\S\n]*" + re.escape(m.group(2)) + r"\b",
                    re.MULTILINE,
                )
                t = terminator.search(text, m.end())
                end = n if t is None else t.end()
                _blank(i, end)
                i = end
            else:
                i += 2
        else:
            i += 1
    return "".join(out)


def _php_code_spans(text: str) -> list[tuple[int, int, str]]:
    """(code_start, end, tag) spans of PHP open-tag regions.

    ``tag`` is ``"php"`` (``<?php``), ``"echo"`` (``<?=``), or
    ``"short"`` (bare ``<?``). All three region kinds are returned;
    the parser decides per tag which count as scannable code.
    """
    spans: list[tuple[int, int, str]] = []
    pos = 0
    n = len(text)
    while pos < n:
        start = text.find("<?", pos)
        if start == -1:
            break
        # Position-anchored match — ``re.match(pat, text[start:])``
        # would copy the whole tail per tag (quadratic on tag-dense
        # hostile input).
        m = _OPEN_TAG_RE.match(text, start)
        opener = m.group(0) if m else "<?"
        if opener == "<?php":
            tag = "php"
        elif opener == "<?=":
            tag = "echo"
        else:
            tag = "short"
        code_start = start + len(opener)
        close = text.find("?>", code_start)
        if close == -1:
            spans.append((code_start, n, tag))
            break
        spans.append((code_start, close, tag))
        pos = close + 2
    return spans


def _inline_html_offsets(
    text: str, spans: list[tuple[int, int, str]],
) -> list[int]:
    """Offsets where non-whitespace INLINE HTML begins (output events).

    Every open-tag region (php, echo, short) is covered — a short-tag
    region is neither code nor HTML output here (its interpretation
    depends on ``short_open_tag``), so it never mints an output event
    by itself.
    """
    offsets: list[int] = []
    covered: list[tuple[int, int]] = []
    pos = 0
    for start, end, _tag in spans:
        open_at = text.rfind("<?", 0, start)
        covered.append((open_at if open_at != -1 else start, end))
    covered.sort()
    for start, end in covered:
        gap = text[pos:start]
        stripped = gap.strip()
        if stripped:
            offsets.append(pos + gap.index(stripped[0]))
        close = text.find("?>", end)
        pos = end if close == -1 else close + 2
    tail = text[pos:]
    if tail.strip():
        offsets.append(pos + tail.index(tail.strip()[0]))
    return offsets


@dataclass
class _PhpUnit:
    """One parsed PHP file: function bodies + top-level statement code."""

    path: Path
    rel: str
    text: str = ""
    stripped: str = ""
    parse_ok: bool = True
    parse_error: str = ""
    #: function name → (body_start, body_end) in file offsets.
    functions: dict[str, tuple[int, int]] = field(default_factory=dict)
    #: top-level (start, end) code spans, function bodies excised.
    top_spans: list[tuple[int, int]] = field(default_factory=list)
    #: offsets of output events: inline HTML plus ``<?=`` short-echo
    #: tags (a short-echo tag always emits — output-before-check must
    #: see it).
    html_offsets: list[int] = field(default_factory=list)
    #: offsets of bare ``<?`` short-open tags. Whether these regions
    #: are code depends on the target's ``short_open_tag`` INI setting,
    #: which this projection cannot observe — they poison the entry to
    #: ``unknown`` instead of being guessed either way.
    short_tag_offsets: list[int] = field(default_factory=list)


def _match_brace_span(stripped: str, open_idx: int) -> tuple[int, int] | None:
    depth = 0
    for j in range(open_idx, len(stripped)):
        c = stripped[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return (open_idx, j + 1)
    return None


def _parse_php_unit(path: Path, source_root: Path) -> _PhpUnit:
    try:
        rel = str(path.resolve().relative_to(source_root.resolve()))
    except ValueError:
        rel = str(path)
    unit = _PhpUnit(path=path, rel=rel)
    try:
        unit.text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        unit.parse_ok = False
        unit.parse_error = f"unreadable: {exc.__class__.__name__}"
        return unit
    unit.stripped = _strip_php(unit.text)
    tagged_spans = _php_code_spans(unit.text)
    unit.html_offsets = _inline_html_offsets(unit.text, tagged_spans)

    # Per-tag semantics: <?php and <?= regions are scannable code; a
    # <?= tag additionally IS an output event (short echo always
    # emits); a bare <? region is neither — it is recorded so the
    # projection can degrade the entry to unknown.
    code_spans: list[tuple[int, int]] = []
    for span_start, span_end, tag in tagged_spans:
        if tag == "short":
            unit.short_tag_offsets.append(max(0, span_start - 2))
            continue
        if tag == "echo":
            unit.html_offsets.append(max(0, span_start - 3))
        code_spans.append((span_start, span_end))
    unit.html_offsets.sort()

    body_spans: list[tuple[int, int]] = []
    for span_start, span_end in code_spans:
        segment = unit.stripped[span_start:span_end]
        for m in _FUNC_DEF_RE.finditer(segment):
            open_idx = segment.find("{", m.end())
            if open_idx == -1:
                unit.parse_ok = False
                unit.parse_error = (
                    f"function {m.group(1)} has no body brace"
                )
                return unit
            body = _match_brace_span(segment, open_idx)
            if body is None:
                unit.parse_ok = False
                unit.parse_error = (
                    f"unbalanced braces in function {m.group(1)}"
                )
                return unit
            unit.functions[m.group(1)] = (
                span_start + body[0], span_start + body[1],
            )
            body_spans.append(
                (span_start + m.start(), span_start + body[1]),
            )

    # Top-level = code spans minus function-definition spans.
    for span_start, span_end in code_spans:
        pos = span_start
        for b_start, b_end in sorted(body_spans):
            if b_end <= pos or b_start >= span_end:
                continue
            if b_start > pos:
                unit.top_spans.append((pos, b_start))
            pos = max(pos, b_end)
        if pos < span_end:
            unit.top_spans.append((pos, span_end))
    return unit


# ------------------------------------------------------------------
# Event extraction
# ------------------------------------------------------------------

@dataclass
class _Event:
    kind: str  # call | dynamic | include | output
    offset: int
    name: str = ""      # call: callee; include: resolved rel path or ""
    depth: int = 0      # brace depth relative to the span's baseline
    detail: str = ""


def _span_events(unit: _PhpUnit, spans: list[tuple[int, int]]) -> list[_Event]:
    events: list[_Event] = []
    for start, end in spans:
        segment = unit.stripped[start:end]
        depth_at: list[int] = []
        d = 0
        for c in segment:
            depth_at.append(d)
            if c == "{":
                d += 1
            elif c == "}":
                d = max(0, d - 1)

        for m in _INCLUDE_RE.finditer(segment):
            raw = unit.text[start + m.start(1):start + m.end(1)].strip()
            if raw.startswith("(") and raw.endswith(")"):
                raw = raw[1:-1].strip()
            lit = _INCLUDE_LITERAL_RE.match(raw)
            name = lit.group(2) if lit else ""
            if lit and raw.startswith("__DIR__") and name.startswith("/"):
                # ``__DIR__ . '/x.php'`` anchors at the file's own
                # directory — the leading slash is the concatenation
                # separator, not filesystem root.
                name = name[1:]
            events.append(_Event(
                kind="include",
                offset=start + m.start(),
                name=name,
                depth=depth_at[m.start()] if m.start() < len(depth_at) else 0,
                detail="" if lit else "dynamic include path",
            ))
        for m in _DYNAMIC_RE.finditer(segment):
            events.append(_Event(
                kind="dynamic",
                offset=start + m.start(),
                depth=depth_at[m.start()] if m.start() < len(depth_at) else 0,
                detail="dynamic dispatch",
            ))
        for m in _CALL_RE.finditer(segment):
            name = m.group(1)
            if name in _PHP_KEYWORDS:
                continue
            kind = "output" if name in _OUTPUT_CALLS else "call"
            events.append(_Event(
                kind=kind,
                offset=start + m.start(),
                name=name,
                depth=depth_at[m.start()] if m.start() < len(depth_at) else 0,
            ))
        # echo/print are language constructs — no parens required.
        for m in re.finditer(
            r"\b(echo|print)\b(?![^\S\n]{0,32}\()", segment,
        ):
            events.append(_Event(
                kind="output",
                offset=start + m.start(),
                name=m.group(1),
                depth=depth_at[m.start()] if m.start() < len(depth_at) else 0,
            ))
    events.sort(key=lambda e: e.offset)
    return events


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


# ------------------------------------------------------------------
# Project-wide index (definitions + per-function calls)
# ------------------------------------------------------------------

class _PhpIndex:
    """Lazy parse cache + call graph over the target's PHP files."""

    def __init__(self, source_root: Path) -> None:
        self.source_root = source_root
        self._units: dict[Path, _PhpUnit] = {}
        self._defs: dict[str, tuple[Path, str]] | None = None

    def unit(self, path: Path) -> _PhpUnit:
        key = path.resolve()
        if key not in self._units:
            self._units[key] = _parse_php_unit(key, self.source_root)
        return self._units[key]

    def _definitions(self) -> dict[str, tuple[Path, str]]:
        if self._defs is None:
            self._defs = {}
            for p in sorted(self.source_root.rglob("*.php")):
                if not p.is_file():
                    continue
                u = self.unit(p)
                for name in u.functions:
                    # First definition wins deterministically (sorted
                    # walk); duplicate definitions are rare and any
                    # ambiguity only ever widens reachability toward
                    # the positive statuses, never toward
                    # not_enforced.
                    self._defs.setdefault(name, (p.resolve(), u.rel))
        return self._defs

    def resolve_function(self, name: str) -> tuple[Path, str] | None:
        return self._definitions().get(name)

    def body_events(self, name: str) -> list[_Event] | None:
        loc = self.resolve_function(name)
        if loc is None:
            return None
        u = self.unit(loc[0])
        span = u.functions.get(name)
        if span is None or not u.parse_ok:
            return None
        return _span_events(u, [span])

    def resolve_include(self, from_file: Path, rel: str) -> Path | None:
        cand = (from_file.parent / rel).resolve()
        if cand.is_file():
            try:
                cand.relative_to(self.source_root.resolve())
            except ValueError:
                return None  # escapes the target tree — not spliced
            return cand
        return None


# ------------------------------------------------------------------
# Pre-output prefix
# ------------------------------------------------------------------

def _entry_prefix_events(
    index: _PhpIndex, entry_file: Path,
) -> tuple[list[_Event], str]:
    """Ordered events of the entry's pre-output prefix.

    Top-level events of the entry file with statically resolved
    includes spliced in at their include point (transitively, cycle-,
    depth-, and total-budget-guarded), truncated at the first output
    event. A splice the guards REFUSE becomes a dynamic-poison event
    (absence claims degrade to unknown), never a silent gap. Returns
    (events, error) — a non-empty error means the prefix could not be
    computed (parse failure) and the entry must project as unknown.
    """
    budget = [MAX_TOTAL_SPLICES]

    def _file_events(path: Path, seen: frozenset[Path], depth: int,
                     ) -> tuple[list[_Event], str]:
        unit = index.unit(path)
        if not unit.parse_ok:
            return [], f"{unit.rel}: {unit.parse_error}"
        events: list[_Event] = list(_span_events(unit, unit.top_spans))
        for off in unit.html_offsets:
            events.append(_Event(kind="output", offset=off, name="html"))
        for off in unit.short_tag_offsets:
            # Bare <? region: code under short_open_tag=On, literal
            # output under Off — statically undecidable, so it poisons
            # absence claims exactly like dynamic dispatch.
            events.append(_Event(
                kind="dynamic", offset=off,
                detail=(
                    f"{unit.rel}: short open tag <? "
                    "(interpretation depends on short_open_tag)"
                ),
            ))
        events.sort(key=lambda e: e.offset)

        out: list[_Event] = []
        for ev in events:
            if ev.kind != "include":
                if ev.kind in ("call", "output"):
                    ev.detail = ev.detail or unit.rel
                out.append(ev)
                continue
            if not ev.name:
                # Dynamic include path: statically undecidable.
                out.append(_Event(
                    kind="dynamic", offset=ev.offset, depth=ev.depth,
                    detail=f"{unit.rel}: dynamic include path",
                ))
                continue
            target = index.resolve_include(path, ev.name)
            if target is None:
                out.append(_Event(
                    kind="dynamic", offset=ev.offset, depth=ev.depth,
                    detail=f"{unit.rel}: unresolved include {ev.name!r}",
                ))
                continue
            if target in seen:
                continue  # cycle: already spliced on this path
            if depth >= MAX_INCLUDE_DEPTH or budget[0] <= 0:
                # Truncated splice — the unspliced file could contain
                # the check, so a silent skip would fabricate absence.
                out.append(_Event(
                    kind="dynamic", offset=ev.offset, depth=ev.depth,
                    detail=(
                        f"{unit.rel}: include of {ev.name!r} not "
                        "spliced ("
                        + ("include depth cap"
                           if depth >= MAX_INCLUDE_DEPTH
                           else "include graph too large — splice "
                                "budget exhausted")
                        + ")"
                    ),
                ))
                continue
            budget[0] -= 1
            sub, err = _file_events(
                target, seen | {target}, depth + 1,
            )
            if err:
                return [], err
            # Conditional includes taint the spliced events'
            # conditionality (they run only on the include's branch).
            for s in sub:
                s.depth += ev.depth
            out.extend(sub)
        return out, ""

    resolved = entry_file.resolve()
    events, err = _file_events(resolved, frozenset({resolved}), 0)
    if err:
        return [], err
    prefix: list[_Event] = []
    for ev in events:
        if ev.kind == "output":
            break
        prefix.append(ev)
    return prefix, ""


def _reach_check(
    index: _PhpIndex,
    start: str,
    checks: frozenset[str],
) -> tuple[list[str] | None, bool]:
    """BFS the static call graph from *start* to any check function.

    Returns ``(path, truncated)``: the call path (start .. check) or
    None, plus whether :data:`MAX_CALL_DEPTH` truncated the search
    while resolvable callees remained unvisited. A truncated no-path
    result is NOT an absence witness — the caller must degrade the
    entry to ``unknown``, never ``not_enforced``. Dynamic constructs
    inside intermediate bodies are NOT followed (they cannot witness a
    path) — they simply contribute no edge.
    """
    frontier: list[list[str]] = [[start]]
    visited = {start}
    for _ in range(MAX_CALL_DEPTH):
        next_frontier: list[list[str]] = []
        for path in frontier:
            body = index.body_events(path[-1])
            if body is None:
                continue
            for ev in body:
                if ev.kind != "call" or ev.name in visited:
                    continue
                if ev.name in checks:
                    return path + [ev.name], False
                visited.add(ev.name)
                if index.resolve_function(ev.name) is not None:
                    next_frontier.append(path + [ev.name])
        if not next_frontier:
            return None, False
        frontier = next_frontier
    return None, True


# ------------------------------------------------------------------
# Public projection
# ------------------------------------------------------------------

_MAX_CENSUS_CALLS = 12


def learned_check_functions(model: Any) -> list[dict[str, Any]]:
    """The study-learned token check functions, with provenance.

    Reads ``DomainModel.token_checks`` (duck-typed: any object with the
    attribute, or a plain dict). Entries missing a name are dropped;
    the ``seed_match`` flag records whether the learned name happens
    to match the generic discovery-seed shape (operator-visible
    honesty: a non-matching name is evidence the identification came
    from study evidence, not name-grepping).
    """
    raw = (
        model.get("token_checks") if isinstance(model, dict)
        else getattr(model, "token_checks", [])
    ) or []
    out: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        if not name or not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        out.append({
            "name": name,
            "kind": str(entry.get("kind") or "other"),
            "provenance": str(entry.get("provenance") or ""),
            "seed_match": bool(TOKEN_SEED_RE.search(name)),
            **({"when": str(entry["when"])} if entry.get("when") else {}),
        })
    return out


def entries_from_context_map(context_map: dict[str, Any]) -> list[dict[str, str]]:
    """Adapt ``context-map.json`` entry_points to projection entries.

    Keeps only entries carrying a usable ``file``; the projection
    itself re-checks existence and PHP-ness.
    """
    out: list[dict[str, str]] = []
    for ep in context_map.get("entry_points") or []:
        if not isinstance(ep, dict):
            continue
        file_ = str(ep.get("file") or ep.get("location") or "").strip()
        if not file_:
            continue
        file_ = file_.split(":", 1)[0]
        out.append({
            "entry": str(ep.get("name") or file_),
            "file": file_,
        })
    return out


def entries_from_checklist(checklist: dict[str, Any]) -> list[dict[str, str]]:
    """Adapt a ``checklist.json`` inventory to projection entries.

    PHP is a script-per-file language: the request handler is the
    file-scope code, stamped ``script_handler: true`` on interstitial
    items by ``core.inventory.script_handler``. Files carrying that
    stamp are entry candidates; pure library files (wiring-only
    interstitials) are not.
    """
    out: list[dict[str, str]] = []
    for f in checklist.get("files") or []:
        if not isinstance(f, dict):
            continue
        path = str(f.get("path") or "")
        if not path.lower().endswith(".php"):
            continue
        items = f.get("items") or []
        if any(
            isinstance(it, dict) and it.get("script_handler") is True
            for it in items
        ):
            out.append({"entry": path, "file": path})
    return out


def project_token_map_for_run(
    model: Any, output_dir: Path, source_root: Path | str,
) -> Path | None:
    """Best-effort projection hook for the study save chokepoint.

    Builds and writes ``token-map.json`` beside ``domain-model.json``
    when (a) the study learned at least one token check function and
    (b) an entry-point source is co-located in *output_dir*
    (``context-map.json`` entry_points and/or ``checklist.json``
    script-handler files). Returns the written path, or None when
    nothing was projected. Never raises past its boundary — the map
    is an enrichment, not a study gate.
    """
    from core.json import load_json

    try:
        if not learned_check_functions(model):
            return None
        root = Path(source_root)
        if not root.is_dir():
            return None
        output_dir = Path(output_dir)
        entries: list[dict[str, str]] = []
        cm = load_json(output_dir / "context-map.json")
        if isinstance(cm, dict):
            entries.extend(entries_from_context_map(cm))
        if (output_dir / "checklist.json").exists():
            from core.inventory import read_checklist
            cl = read_checklist(output_dir)
            if isinstance(cl, dict):
                entries.extend(entries_from_checklist(cl))
        if not entries:
            return None
        payload = build_token_map(model, entries, root)
        return save_token_map(payload, output_dir)
    except Exception:
        logger.debug("token-map projection skipped", exc_info=True)
        return None


def build_token_map(
    model: Any,
    entries: list[dict[str, str]],
    source_root: Path,
) -> dict[str, Any]:
    """Project the learned token checks onto *entries*.

    *entries*: ``[{"entry": <label>, "file": <path relative to
    source_root or absolute inside it>}, ...]`` — typically from
    :func:`entries_from_context_map`.

    Returns the ``token-map.json`` payload. Pure computation plus
    reads under *source_root*; never writes.
    """
    source_root = Path(source_root)
    checks = learned_check_functions(model)
    check_names = frozenset(c["name"] for c in checks)

    payload: dict[str, Any] = {
        "version": TOKEN_MAP_VERSION,
        "artifact": "token-enforcement-map",
        "source_root": str(source_root),
        "check_functions": checks,
        "honesty": (
            "hint-tier; enforced = call-presence witness, never "
            "bypass-freedom; no consumer may suppress on this map"
        ),
        "entries": [],
        "census": {},
    }
    if not checks:
        payload["note"] = (
            "no token check function learned by the study pass — "
            "entries not projected"
        )
        return payload

    index = _PhpIndex(source_root)
    seen_files: set[str] = set()
    records: list[dict[str, Any]] = []
    for entry in entries:
        file_ = str(entry.get("file") or "").strip()
        label = str(entry.get("entry") or file_)
        if not file_:
            continue
        path = Path(file_)
        if not path.is_absolute():
            path = source_root / file_
        try:
            rel = str(path.resolve().relative_to(source_root.resolve()))
        except ValueError:
            records.append(_record(
                label, file_, "unknown",
                reason="entry file outside source root",
            ))
            continue
        if rel in seen_files:
            continue
        seen_files.add(rel)
        if path.suffix.lower() != ".php":
            continue
        if not path.is_file():
            records.append(_record(
                label, rel, "unknown", reason="entry file not found",
            ))
            continue
        records.append(
            _project_entry(index, label, rel, path, check_names),
        )

    records.sort(key=lambda r: (r["file"], r["entry"]))
    payload["entries"] = records
    census: dict[str, int] = {}
    for r in records:
        census[r["status"]] = census.get(r["status"], 0) + 1
    payload["census"] = census
    return payload


def _record(label: str, rel: str, status: str, **extra: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {"entry": label, "file": rel, "status": status}
    rec.update({k: v for k, v in extra.items() if v not in (None, "", [])})
    return rec


def _project_entry(
    index: _PhpIndex,
    label: str,
    rel: str,
    path: Path,
    checks: frozenset[str],
) -> dict[str, Any]:
    unit = index.unit(path)
    # Content digest of the entry source at projection time. Lets a
    # later consumer detect drift (source edited since the map was
    # built) without a timestamp — the payload stays deterministic.
    digest = (
        hashlib.sha256(unit.text.encode("utf-8")).hexdigest()[:16]
        if unit.text else None
    )

    prefix, err = _entry_prefix_events(index, path)
    if err:
        return _record(
            label, rel, "unknown",
            reason=f"parse failure: {err}",
            source_sha256=digest,
        )

    # 1) Direct witness in the prefix.
    for ev in prefix:
        if ev.kind == "call" and ev.name in checks:
            return _record(
                label, rel, "enforced",
                via=ev.name,
                call_path=[rel, ev.name],
                line=_line_of(unit.text, ev.offset) if ev.detail == unit.rel
                else None,
                conditional=bool(ev.depth > 0) or None,
                evidence=(
                    f"direct call to {ev.name} in pre-output prefix"
                    + (" (conditional branch)" if ev.depth > 0 else "")
                ),
                source_sha256=digest,
            )

    # 2) Transitive witness through resolved callees. A search the
    #    depth cap truncated cannot witness absence — remembered and
    #    degraded to unknown below (never not_enforced).
    truncated_from: list[str] = []
    for ev in prefix:
        if ev.kind != "call":
            continue
        chain, truncated = _reach_check(index, ev.name, checks)
        if chain:
            return _record(
                label, rel, "indirect",
                via=chain[-1],
                call_path=[rel, *chain],
                conditional=bool(ev.depth > 0) or None,
                evidence=(
                    f"check {chain[-1]} reached via "
                    + " -> ".join(chain)
                    + (" (conditional branch)" if ev.depth > 0 else "")
                    + "; intermediate branch conditions not analysed"
                ),
                source_sha256=digest,
            )
        if truncated and ev.name not in truncated_from:
            truncated_from.append(ev.name)

    # 3) Dynamic constructs poison absence claims.
    dynamics = [ev for ev in prefix if ev.kind == "dynamic"]
    if dynamics:
        return _record(
            label, rel, "unknown",
            reason="dynamic dispatch in pre-output prefix",
            evidence="; ".join(
                sorted({d.detail or "dynamic dispatch" for d in dynamics}),
            )[:400],
            source_sha256=digest,
        )

    # 3b) Truncated reachability searches poison absence claims.
    if truncated_from:
        return _record(
            label, rel, "unknown",
            reason="call-depth cap truncated the reachability search",
            evidence=(
                "search from "
                + ", ".join(truncated_from[:8])
                + f" stopped at depth {MAX_CALL_DEPTH} with unvisited"
                " callees — absence unproven"
            ),
            source_sha256=digest,
        )

    # 4) Absence census.
    called = []
    for ev in prefix:
        if ev.kind == "call" and ev.name not in called:
            called.append(ev.name)
    post_output = _post_output_check(index, path, checks)
    return _record(
        label, rel, "not_enforced",
        census_calls=called[:_MAX_CENSUS_CALLS],
        evidence=(
            "no path from pre-output prefix to any learned check"
            + (
                f"; {post_output} called only after output begins"
                " — not credited"
                if post_output else ""
            )
        ),
        source_sha256=digest,
    )


def _post_output_check(
    index: _PhpIndex, path: Path, checks: frozenset[str],
) -> str:
    """Name of a check function called at top level AFTER first output."""
    unit = index.unit(path)
    if not unit.parse_ok:
        return ""
    events = list(_span_events(unit, unit.top_spans))
    for off in unit.html_offsets:
        events.append(_Event(kind="output", offset=off, name="html"))
    events.sort(key=lambda e: e.offset)
    seen_output = False
    for ev in events:
        if ev.kind == "output":
            seen_output = True
        elif seen_output and ev.kind == "call" and ev.name in checks:
            return ev.name
    return ""


# ------------------------------------------------------------------
# Persistence + drift
# ------------------------------------------------------------------

def save_token_map(payload: dict[str, Any], output_dir: Path) -> Path:
    from core.atomic_fs import write_text_atomically

    out_path = Path(output_dir) / TOKEN_MAP_FILENAME
    write_text_atomically(out_path, json.dumps(payload, indent=2) + "\n")
    return out_path


def load_token_map(output_dir: Path) -> dict[str, Any] | None:
    from core.json import load_json

    path = Path(output_dir) / TOKEN_MAP_FILENAME
    if not path.is_file():
        return None
    raw = load_json(path)
    if not isinstance(raw, dict) or raw.get("artifact") != "token-enforcement-map":
        return None
    return raw


_ENTRY_ANNOTATION_STATUSES = frozenset({
    "enforced", "indirect", "not_enforced", "unknown",
})


def annotate_entry_points(
    entry_points: list[Any], artifact_dir: Path,
) -> int:
    """Attach the per-entry token-enforcement fact to *entry_points*.

    Advisory attach for the validate bridge: each context-map entry
    point whose file appears in ``<artifact_dir>/token-map.json``
    gains a ``token_enforcement`` dict ``{status, via?, conditional?,
    evidence?}``. Text values are escaped/capped here (the map is a
    run-dir artifact — attacker-adjacent shapes must not flow
    verbatim into downstream prompts). NEVER writes any status/
    priority field — consumers treat the fact as a hint, and an
    "enforced" value licenses nothing. Returns the number of entries
    annotated; 0 when no map exists.
    """
    from core.security.log_sanitisation import escape_nonprintable

    payload = load_token_map(artifact_dir)
    if not payload:
        return 0
    by_file: dict[str, dict[str, Any]] = {}
    for r in payload.get("entries") or []:
        if isinstance(r, dict) and r.get("file"):
            by_file.setdefault(str(r["file"]), r)
    if not by_file:
        return 0

    def _defend(value: Any, cap: int = 300) -> str:
        text = escape_nonprintable(str(value or ""))
        return text[:cap]

    count = 0
    for ep in entry_points or []:
        if not isinstance(ep, dict):
            continue
        file_ = str(ep.get("file") or "").replace("\\", "/").lstrip("./")
        record = by_file.get(file_)
        if record is None:
            continue
        status = str(record.get("status") or "")
        if status not in _ENTRY_ANNOTATION_STATUSES:
            continue
        fact: dict[str, Any] = {"status": status}
        if record.get("via"):
            fact["via"] = _defend(record["via"], 120)
        if record.get("conditional"):
            fact["conditional"] = True
        evidence = record.get("evidence") or record.get("reason")
        if evidence:
            fact["evidence"] = _defend(evidence)
        ep["token_enforcement"] = fact
        count += 1
    return count


#: Statuses that count as "covered" for drift purposes. unknown is
#: NOT a loss partner in either direction: enforced→unknown is a
#: visibility regression (reported as such), not proof of a lost
#: guard.
_POSITIVE = frozenset({"enforced", "indirect"})


def token_map_drift(
    prior: dict[str, Any], current: dict[str, Any],
) -> list[dict[str, Any]]:
    """Per-entry status changes between two token maps.

    Returns records ``{entry, file, prior_status, current_status,
    change}`` where ``change`` is:

    - ``lost_enforcement``  — positive (enforced/indirect) →
      not_enforced. THE signal for gated-fragile Ruled Outs whose
      disproof named the token as sole guard.
    - ``lost_visibility``   — positive → unknown (the map can no
      longer see the guard; not proof it is gone).
    - ``gained_enforcement`` — not_enforced/unknown → positive.
    - ``changed``           — any other status change.

    Entries present on only one side are skipped (no basis for a
    per-entry claim); different learned check functions between the
    two maps are surfaced on the first record as ``check_set_changed``
    so a rename is never misread as mass drift.
    """
    def _by_file(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {
            r["file"]: r for r in payload.get("entries") or []
            if isinstance(r, dict) and r.get("file")
        }

    prior_entries = _by_file(prior)
    current_entries = _by_file(current)
    prior_checks = sorted(
        c.get("name", "") for c in prior.get("check_functions") or []
    )
    current_checks = sorted(
        c.get("name", "") for c in current.get("check_functions") or []
    )

    drift: list[dict[str, Any]] = []
    for file_, cur in sorted(current_entries.items()):
        old = prior_entries.get(file_)
        if old is None:
            continue
        p_status = str(old.get("status") or "")
        c_status = str(cur.get("status") or "")
        if p_status == c_status:
            continue
        if p_status in _POSITIVE and c_status == "not_enforced":
            change = "lost_enforcement"
        elif p_status in _POSITIVE and c_status == "unknown":
            change = "lost_visibility"
        elif p_status not in _POSITIVE and c_status in _POSITIVE:
            change = "gained_enforcement"
        else:
            change = "changed"
        drift.append({
            "entry": cur.get("entry") or file_,
            "file": file_,
            "prior_status": p_status,
            "current_status": c_status,
            "change": change,
        })
    if drift and prior_checks != current_checks:
        drift[0]["check_set_changed"] = {
            "prior": prior_checks, "current": current_checks,
        }
    return drift

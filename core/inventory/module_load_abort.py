"""Detect unconditional module-load aborts at file scope.

When a source file's top-level execution unconditionally raises /
throws / panics before any function binding completes, no function
defined in that file is reachable through normal import / link. The
substrate's call-graph analysis can't see this — it counts call
edges between in-file functions and reports CALLED for any function
referenced by another, even though the entire file is unloadable.

This module adds per-language detection: a single helper
:func:`detect_module_load_abort` returns either ``None`` (no abort
detected) or a structured record describing what was found.
Consumers (the inventory builder + the reachability prepass) treat
detected aborts as a file-level reachability gate — every function
in the file is marked dead regardless of in-file call edges.

Conservative bias: the detection only fires when the abort is
unambiguously unconditional. ``raise ImportError`` inside
``if sys.version_info < (3, 10):`` is NOT flagged — the file may
still import on the supported-version branch. ``func init() { if
config == nil { panic(...) } }`` is NOT flagged — the panic is
config-gated. False negatives are cheap (we miss a deferral
opportunity); false positives are expensive (we silence a real
finding on a file that's actually loadable).

Per-language detection currently handled:

  * Python: ``raise <AbortException>(...)`` at module scope, NOT
    inside any conditional. Recognised exceptions:
    ``ImportError``, ``ModuleNotFoundError``, ``SystemExit``,
    ``RuntimeError``, ``NotImplementedError``.
  * JavaScript / TypeScript: ``throw new <NameError>(...)`` at
    brace-depth zero (module scope), before any function binding.
  * Go: ``func init() { panic(...) }`` where the panic is at the
    init body's top scope (not inside a conditional / loop).
  * Rust: ``compile_error!(...)`` at module scope.

Other languages return ``None`` (no detection wired) — same
graceful-degradation pattern as the call-graph extractors. The
consumer treats absence as "no abort detected", never as "file is
guaranteed loadable".
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModuleLoadAbort:
    """Describes a detected unconditional module-load abort.

    ``line``: 1-indexed line number of the abort statement.
    ``summary``: short human-readable label for prompts / logs —
    e.g. ``"raise ImportError"`` or ``"func init() { panic(...) }"``.
    Consumers display this verbatim; keep it concise.
    """
    line: int
    summary: str


def detect_module_load_abort(
    language: str, content: str,
) -> Optional[ModuleLoadAbort]:
    """Per-language dispatch. Returns the first detected unconditional
    abort, or ``None`` when no abort is detected (or the language
    has no detector wired).

    Best-effort: any parse failure inside a per-language detector
    returns ``None``; the caller treats absence as "no signal".
    """
    if not content:
        return None
    try:
        if language == "python":
            return _detect_python(content)
        if language in ("javascript", "typescript", "tsx"):
            return _detect_javascript(content)
        if language == "go":
            return _detect_go(content)
        if language == "rust":
            return _detect_rust(content)
        if language == "php":
            return _detect_php(content)
        if language == "ruby":
            return _detect_ruby(content)
    except Exception:  # noqa: BLE001
        # Detection failures are non-fatal — the consumer treats
        # ``None`` as "no abort detected", which matches the
        # graceful-degradation pattern the call-graph extractors
        # use when their grammar dep is missing.
        return None
    return None


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


_PY_ABORT_EXCEPTIONS = frozenset({
    "ImportError",
    "ModuleNotFoundError",
    "SystemExit",
    "RuntimeError",
    "NotImplementedError",
})


def _detect_python(content: str) -> Optional[ModuleLoadAbort]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None
    # Walk module-scope statements in order. A ``raise`` at module
    # scope (i.e. directly in tree.body, not nested inside any
    # If / Try / With / For / While) runs unconditionally at import
    # time and aborts before any def below it binds.
    for node in tree.body:
        if isinstance(node, ast.Raise) and _py_is_abort_raise(node):
            return ModuleLoadAbort(
                line=node.lineno,
                summary=_py_summarise_raise(node),
            )
    return None


def _py_is_abort_raise(node: ast.Raise) -> bool:
    """Is this a ``raise SomeAbortError(...)`` (or bare class)
    matching the abort-exception allow-list?

    Bare ``raise`` with no exception (a re-raise inside an except
    handler) doesn't apply at module scope — module-scope ast.Raise
    nodes with exc=None can't actually execute meaningfully but the
    AST allows them; defensively treat as not-an-abort.
    """
    if node.exc is None:
        return False
    exc = node.exc
    name = None
    if isinstance(exc, ast.Call):
        if isinstance(exc.func, ast.Name):
            name = exc.func.id
        elif isinstance(exc.func, ast.Attribute):
            name = exc.func.attr
    elif isinstance(exc, ast.Name):
        name = exc.id
    elif isinstance(exc, ast.Attribute):
        name = exc.attr
    return name in _PY_ABORT_EXCEPTIONS


def _py_summarise_raise(node: ast.Raise) -> str:
    if node.exc is None:
        return "raise"
    exc = node.exc
    if isinstance(exc, ast.Call):
        if isinstance(exc.func, ast.Name):
            return f"raise {exc.func.id}"
        if isinstance(exc.func, ast.Attribute):
            return f"raise {exc.func.attr}"
    if isinstance(exc, ast.Name):
        return f"raise {exc.id}"
    if isinstance(exc, ast.Attribute):
        return f"raise {exc.attr}"
    return "raise"


# ---------------------------------------------------------------------------
# JavaScript / TypeScript — regex with brace-depth tracking. No AST
# in stdlib; pulling tree-sitter just for this detector is overkill
# (the call-graph extractor already does that work). False-negative
# bias on ambiguous cases is acceptable.
# ---------------------------------------------------------------------------


_JS_LINE_COMMENT = re.compile(r"//[^\n]*")
_JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
# Any ``throw new <Capitalized>`` at module scope aborts load — the
# class need not be named ``*Error`` (``throw new Disabled()`` counts).
# Capitalised initial keeps us off ``throw new lowerCaseFactory()``
# false-positives where a value (not an error) is being constructed.
_JS_THROW_NEW = re.compile(
    r"\bthrow\s+new\s+([A-Z][A-Za-z0-9_]*)\b"
)


def _detect_javascript(content: str) -> Optional[ModuleLoadAbort]:
    # Strip comments first so commented-out throw text doesn't trip
    # the regex. Replace with whitespace of equal length to preserve
    # line/offset arithmetic for the line-number report.
    def _spaces(m: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    stripped = _JS_BLOCK_COMMENT.sub(_spaces, content)
    stripped = _JS_LINE_COMMENT.sub(_spaces, stripped)
    # Walk character-by-character tracking brace and paren depth.
    # An unconditional module-level throw is one at depth zero
    # before any function body opens it. String / template / char
    # literals are skipped wholesale — without this a function body
    # containing a string with an unbalanced brace (``const s =
    # "}";``) corrupts the depth counter and a throw INSIDE the
    # function reads as depth-zero, a false-positive module-abort
    # that would silence every finding below it.
    depth = 0
    paren = 0
    i = 0
    n = len(stripped)
    while i < n:
        c = stripped[i]
        if c in "\"'`":
            j = _js_skip_string(stripped, i)
            if j is None:
                break
            i = j
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
        elif c == "(":
            paren += 1
        elif c == ")":
            paren = max(0, paren - 1)
        elif c == "t" and depth == 0 and paren == 0:
            m = _JS_THROW_NEW.match(stripped, i)
            if m:
                line_no = stripped.count("\n", 0, i) + 1
                err_name = m.group(1)
                return ModuleLoadAbort(
                    line=line_no,
                    summary=f"throw new {err_name}",
                )
        i += 1
    return None


def _js_skip_string(source: str, start: int) -> Optional[int]:
    """Advance past a JS string / template / char literal beginning at
    ``start``. Returns the index just past the closing quote, or
    ``None`` on an unterminated literal. Handles backslash escapes;
    treats template literals (`` ` ``) as opaque (``${…}`` interior is
    skipped wholesale — conservative for abort detection)."""
    quote = source[start]
    i = start + 1
    n = len(source)
    while i < n:
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return None


# ---------------------------------------------------------------------------
# Go — ``func init() { panic(...) }`` where the panic is at the init
# body's top scope (not gated by an enclosing conditional). Regex-based;
# tree-sitter-go usage would be heavier than warranted for this single
# detector.
# ---------------------------------------------------------------------------


_GO_INIT_HEADER = re.compile(r"\bfunc\s+init\s*\(\s*\)\s*\{")
_GO_PANIC_CALL = re.compile(r"\bpanic\s*\(")


def _detect_go(content: str) -> Optional[ModuleLoadAbort]:
    init_match = _GO_INIT_HEADER.search(content)
    if not init_match:
        return None
    body_start = init_match.end()
    body_end = _go_find_matching_brace(content, body_start - 1)
    if body_end is None:
        return None
    init_body = content[body_start:body_end]
    panic_match = _GO_PANIC_CALL.search(init_body)
    if not panic_match:
        return None
    # Panic must be at init body's top scope (not inside any
    # nested block — if / for / switch / select). If brace depth
    # at the panic's location relative to the body is > 0, it's
    # conditional.
    if not _go_panic_is_unconditional(init_body, panic_match.start()):
        return None
    # Convert body-relative offset to absolute line number.
    abs_offset = body_start + panic_match.start()
    line_no = content.count("\n", 0, abs_offset) + 1
    return ModuleLoadAbort(
        line=line_no,
        summary="func init() { panic(...) }",
    )


def _go_find_matching_brace(source: str, open_pos: int) -> Optional[int]:
    """Given index of an opening ``{``, return index of the
    matching closing ``}``. Returns None on malformed input."""
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != "{":
        return None
    depth = 1
    i = open_pos + 1
    n = len(source)
    while i < n and depth > 0:
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        elif c in '"`':
            j = _go_skip_string(source, i)
            if j is None:
                return None
            i = j
            continue
        i += 1
    return None


def _go_skip_string(source: str, start: int) -> Optional[int]:
    """Advance past a Go string literal starting at ``start``.
    Handles both interpreted (``"…"``) and raw (`` `…` ``) strings.
    """
    quote = source[start]
    i = start + 1
    n = len(source)
    while i < n:
        c = source[i]
        if c == "\\" and quote == '"':
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return None


def _go_panic_is_unconditional(body: str, panic_offset: int) -> bool:
    """The panic is unconditional iff brace depth at its location
    (relative to the init body) is zero — i.e. it's a statement
    directly in the function body, not nested inside any conditional
    block (if / for / switch / select)."""
    depth = 0
    i = 0
    while i < panic_offset:
        c = body[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
        elif c in '"`':
            j = _go_skip_string(body, i)
            if j is None:
                return False
            i = j
            continue
        i += 1
    return depth == 0


# ---------------------------------------------------------------------------
# Rust — ``compile_error!(...)`` at module scope. Triggers at
# compile time; module never compiles, hence never loads. Macro
# may also appear inside ``#[cfg(...)]`` gates — those are
# conditional on build features and we conservatively do NOT
# flag them (build configuration is out of scope for static
# analysis).
# ---------------------------------------------------------------------------


_RUST_COMPILE_ERROR = re.compile(
    r"^\s*compile_error\s*!\s*\(", re.MULTILINE,
)


def _detect_rust(content: str) -> Optional[ModuleLoadAbort]:
    # Naive but effective: compile_error! at line start (after any
    # leading whitespace) with no preceding ``#[cfg`` attribute on
    # the same logical statement. The substrate doesn't model cfg
    # gates; we conservatively flag any unconditional compile_error
    # and treat cfg-gated ones as out of scope (false-negative bias).
    m = _RUST_COMPILE_ERROR.search(content)
    if not m:
        return None
    # Check that the preceding non-whitespace token isn't ``]`` (end
    # of an attribute). A bare attribute-attached compile_error like
    # ``#[cfg(...)] compile_error!(...)`` is conditional; skip it.
    before = content[: m.start()].rstrip()
    if before.endswith("]"):
        return None
    line_no = content.count("\n", 0, m.start()) + 1
    return ModuleLoadAbort(
        line=line_no,
        summary="compile_error!(...)",
    )


# ---------------------------------------------------------------------------
# PHP — ``<?php`` files execute top-level code on include/require. An
# unconditional file-scope ``throw new <Class>``, ``die`` or ``exit``
# aborts the load before any declaration below it binds. Brace-depth
# tracking (mirrors the JS detector) + a statement-initial gate so a
# CONDITIONAL abort (``if (x) die();`` — the abort follows ``)``) is
# never flagged (a false positive would wrongly hard-suppress live code).
# ---------------------------------------------------------------------------


_PHP_LINE_COMMENT = re.compile(r"(//|#)[^\n]*")
_PHP_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_PHP_TAG = re.compile(r"<\?php|<\?=|<\?|\?>")
_PHP_ABORT = re.compile(r"throw\s+new\s+([A-Za-z_\\][\w\\]*)|die\b|exit\b")
# A statement-initial abort is preceded (ignoring whitespace) by one of
# these — i.e. it begins a statement, so it is not a branch/modifier body.
# (Open/close tags are stripped to whitespace first, so the first statement
# after ``<?php`` sees ``last_significant is None`` and counts as initial.)
_PHP_STMT_BOUNDARY = frozenset({";", "{", "}"})


def _detect_php(content: str) -> Optional[ModuleLoadAbort]:
    def _spaces(m: "re.Match[str]") -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    stripped = _PHP_BLOCK_COMMENT.sub(_spaces, content)
    stripped = _PHP_LINE_COMMENT.sub(_spaces, stripped)
    # Blank the PHP open/close tags so the first statement after ``<?php``
    # is statement-initial and ``->`` / ``?>`` ``>`` chars never read as a
    # boundary.
    stripped = _PHP_TAG.sub(_spaces, stripped)
    depth = 0
    last_significant = None  # last non-whitespace char seen
    i = 0
    n = len(stripped)
    while i < n:
        c = stripped[i]
        if c in "\"'":
            j = _js_skip_string(stripped, i)
            if j is None:
                break
            last_significant = stripped[j - 1] if j else c
            i = j
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
        elif depth == 0 and (c in "tde") and (
                last_significant is None or last_significant in _PHP_STMT_BOUNDARY):
            # Only attempt a match at a statement boundary at file scope.
            m = _PHP_ABORT.match(stripped, i)
            if m:
                tok = m.group(0).split()[0]
                summary = (f"throw new {m.group(1).split(chr(92))[-1]}"
                           if m.group(1) else tok)
                line_no = stripped.count("\n", 0, i) + 1
                return ModuleLoadAbort(line=line_no, summary=summary)
        if not c.isspace():
            last_significant = c
        i += 1
    return None


# ---------------------------------------------------------------------------
# Ruby — top-level code runs on require. An unconditional column-0
# ``raise`` / ``abort`` / ``exit`` / ``fail`` aborts the load. Ruby has no
# braces for blocks (def/class/module/if/… end), so nesting is tracked by
# COLUMN-0 block openers vs ``end`` — Ruby bodies are indented by universal
# convention, so a column-0 statement is top-level. We flag only an
# unconditional (no trailing ``if``/``unless``/… modifier) column-0 abort at
# nesting depth 0. Conservative by design: ambiguous cases under-detect
# (FN-safe) rather than risk a false positive (which would hard-suppress).
# ---------------------------------------------------------------------------


_RB_OPENER = re.compile(
    r"^(class|module|def|begin|if|unless|while|until|case|for)\b")
_RB_END = re.compile(r"^end\b")
# A one-liner (``def foo; end`` / ``class X; end``) opens AND closes on the
# same line — net zero nesting. Detected by a trailing ``end`` word so it
# doesn't leave depth stuck at 1 (which would hide a top-level abort below).
_RB_ONELINER = re.compile(r"\bend\s*$")
_RB_ABORT = re.compile(r"^(raise\s+\S|abort\b|exit\b|exit!|fail\s+\S|Kernel\.(abort|exit))")
_RB_MODIFIER = re.compile(r"\b(if|unless|while|until)\b")


def _detect_ruby(content: str) -> Optional[ModuleLoadAbort]:
    depth = 0
    for idx, raw in enumerate(content.splitlines()):
        # Strip trailing line comment (best-effort; a ``#`` inside a string
        # is rare at module scope and only risks under-detection).
        line = re.sub(r"#.*$", "", raw)
        stripped = line.strip()
        if not stripped:
            continue
        is_col0 = line[:1] not in (" ", "\t")
        if is_col0 and depth == 0:
            abort = _RB_ABORT.match(stripped)
            if abort and not _RB_MODIFIER.search(stripped[len(abort.group(0)):]):
                # Exclude conditional modifier forms (``raise X if cond``).
                return ModuleLoadAbort(
                    line=idx + 1,
                    summary=stripped.split()[0].split(".")[-1])
        # Track nesting via COLUMN-0 openers / ends only (indented inner
        # structure is irrelevant to whether a column-0 line is top-level).
        if is_col0:
            if _RB_END.match(stripped):
                depth = max(0, depth - 1)
            elif _RB_OPENER.match(stripped) and not _RB_ONELINER.search(stripped):
                # one-liner (``def f; end``) is net-zero — don't increment.
                depth += 1
    return None


__all__ = ["ModuleLoadAbort", "detect_module_load_abort"]

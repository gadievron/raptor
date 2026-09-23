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

Recovery / early-exit constructs make an abort non-terminating even
when the abort statement itself is unconditional, so each detector
also abstains when the language offers a way for the file to survive
(or never reach) the abort:

  * Go: a ``defer`` registered before the panic may ``recover()`` it,
    and a ``return`` before the panic ends init first — any ``defer``
    or ``return`` token in the init body before the panic → no
    witness.
  * JavaScript / PHP: a module-/file-scope ``return`` (CommonJS
    module wrapper, PHP include) ends top-level execution before the
    abort line is reached. Any ``return`` token not provably inside a
    ``function`` body (or arrow-function body for JS) before the
    abort → no witness. Braces whose opener can't be proven to be a
    function (class/method/object bodies, bare blocks) count as
    module-level — the cheap under-detect direction.
  * Ruby: a top-level ``return`` ends the file's execution; an
    INDENTED block opener at nesting depth zero breaks the column-0
    nesting model (the following column-0 lines may be inside it) —
    either → no witness.

Suppression is only ever earned when the abort provably terminates
loading; every ambiguity above degrades to "no signal".

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
  * PHP: file-scope ``throw new <Class>`` / ``die`` / ``exit`` at
    brace-depth zero, statement-initial (conditional forms skipped).
  * Ruby: unconditional column-0 ``raise`` / ``abort`` / ``exit`` /
    ``fail`` at nesting depth zero (modifier forms skipped).

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
) -> ModuleLoadAbort | None:
    """Per-language dispatch. Returns a detected unconditional abort,
    or ``None`` when no abort is detected (or the language has no
    detector wired). Detectors are best-effort and may examine only
    the first candidate site (see :func:`_detect_rust`), so ``None``
    never means "file is guaranteed loadable".

    Best-effort: any parse failure inside a per-language detector
    returns ``None``; the caller treats absence as "no signal".
    """
    if not content:
        return None
    try:
        if language == "python":
            return _detect_python(content)
        if language in ("javascript", "typescript", "tsx"):
            return _detect_javascript(language, content)
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


def _detect_python(content: str) -> ModuleLoadAbort | None:
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
# JavaScript / TypeScript — regex with brace-depth tracking over the
# tokenizer-grade blanked view (comments, strings, templates, regex
# literals, JSX text all spaced out by the shared substrate). No
# grammar / parse errors → bail on the whole file (no abort — toward
# no suppression).
# ---------------------------------------------------------------------------


# Any ``throw new <Capitalized>`` at module scope aborts load — the
# class need not be named ``*Error`` (``throw new Disabled()`` counts).
# Capitalised initial keeps us off ``throw new lowerCaseFactory()``
# false-positives where a value (not an error) is being constructed.
_JS_THROW_NEW = re.compile(
    r"\bthrow\s+new\s+([A-Z][A-Za-z0-9_]*)\b"
)

_JS_STMT_BOUNDARY = frozenset({";", "{", "}"})

_JS_RETURN = re.compile(r"return\b")
# A brace provably opening a FUNCTION body: an arrow (``=>``) or a
# ``function`` keyword header (optionally generator / named) whose
# parameter list carries no braces. ONLY these scopes may contain a
# ``return`` without ending module-level execution. Anything the
# pattern can't prove (class/object method shorthand, bare blocks,
# parameter defaults containing braces) counts as module-level, so a
# ``return`` inside it abstains — the cheap under-detect direction; a
# wrongly "function"-classified brace would instead let a module-level
# return keep a false whole-file abort witness.
_JS_FN_BRACE = re.compile(
    r"(?:=>|\bfunction\b(?:\s*\*)?(?:\s+[A-Za-z_$][\w$]*)?\s*\([^{}]*\))\s*$"
)


def _detect_javascript(
    language: str, content: str,
) -> ModuleLoadAbort | None:
    # Blank ALL non-code text (comments, strings, template literals,
    # regex literals, JSX text) via the tokenizer-grade substrate,
    # preserving newlines so the line-number report stays valid.
    # Comment-only or string-only stripping is not enough: braces
    # inside a REGEX literal (``var r = /}}/;``) corrupted the depth
    # counter, so a throw inside a never-called function read as
    # depth-zero — a false-positive whole-file abort gate that
    # silenced every finding below it. Same class for a string with
    # an unbalanced brace (``const s = "}";``).
    from core.inventory.lexical_view import LexicalRefusal, blank_noncode

    try:
        stripped = blank_noncode(language, content)
    except LexicalRefusal:
        # Parse errors: recovered token boundaries are guesses; a
        # partial view could fabricate a whole-file abort over live
        # code. Bail on the whole file — toward no suppression.
        return None
    if stripped is None:
        # Grammar unavailable — cannot vouch a code view; no witness.
        return None
    # Walk character-by-character tracking brace and paren depth.
    # An unconditional module-level throw is one at depth zero
    # before any function body opens it. Braces are additionally
    # classified function / non-function so a module-level ``return``
    # (a CommonJS wrapper can return; conditional blocks that return
    # end the module before a later throw runs) abstains, while a
    # ``return`` inside a proven function body doesn't.
    depth = 0
    paren = 0
    fn_depth = 0
    brace_is_fn: list[bool] = []
    last_significant = None
    i = 0
    n = len(stripped)
    while i < n:
        c = stripped[i]
        if c == "{":
            is_fn = bool(_JS_FN_BRACE.search(stripped, max(0, i - 400), i))
            brace_is_fn.append(is_fn)
            if is_fn:
                fn_depth += 1
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
            if brace_is_fn and brace_is_fn.pop():
                fn_depth -= 1
        elif c == "(":
            paren += 1
        elif c == ")":
            paren = max(0, paren - 1)
        elif c == "r" and fn_depth == 0 and (
                i == 0 or not (stripped[i - 1].isalnum()
                               or stripped[i - 1] in "_$")):
            if _JS_RETURN.match(stripped, i):
                # A return not provably inside a function body may end
                # module-level execution before any later abort line is
                # reached (CJS top-level return, return inside an
                # executed conditional block). Abstain — toward no
                # suppression.
                return None
        elif c == "t" and depth == 0 and paren == 0 and (
                last_significant is None
                or last_significant in _JS_STMT_BOUNDARY):
            m = _JS_THROW_NEW.match(stripped, i)
            if m:
                line_no = stripped.count("\n", 0, i) + 1
                err_name = m.group(1)
                return ModuleLoadAbort(
                    line=line_no,
                    summary=f"throw new {err_name}",
                )
        if not c.isspace():
            last_significant = c
        i += 1
    return None


def _js_skip_string(source: str, start: int) -> int | None:
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
# Recovery / early-exit tokens BEFORE the panic disqualify the abort:
# a ``defer`` registered first may ``recover()`` the panic (the file
# then loads normally), and a ``return`` ends init before the panic
# runs. Textual check on the comment/string-stripped body — a token
# inside a nested func literal also abstains (under-detect, cheap).
_GO_RECOVERY_TOKEN = re.compile(r"\b(?:defer|return)\b")


def _go_strip_comments_and_strings(content: str) -> str:
    """Blank Go comments and string/rune literal INTERIORS, preserving
    newlines (line-number arithmetic) and the quote characters
    themselves (so the downstream brace walkers still see terminated,
    now-empty literals). Without this a ``panic(``, ``func init() {``
    or brace inside a comment or string in the untrusted target file
    reads as real code and can fabricate the whole-file abort gate —
    the false-positive direction the module docstring forbids."""
    out = list(content)
    i = 0
    n = len(out)
    while i < n:
        c = out[i]
        if c == "/" and i + 1 < n and out[i + 1] == "/":
            while i < n and out[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and out[i + 1] == "*":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n:
                if out[i] == "*" and i + 1 < n and out[i + 1] == "/":
                    out[i] = " "
                    out[i + 1] = " "
                    i += 2
                    break
                if out[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        if c in "\"'`":
            quote = c
            i += 1
            while i < n:
                ch = out[i]
                if ch == "\\" and quote != "`" and i + 1 < n:
                    out[i] = " "
                    if out[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if ch == quote:
                    i += 1
                    break
                if ch != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _detect_go(content: str) -> ModuleLoadAbort | None:
    # Sanitize once up front: comments and string/rune interiors are
    # blanked so neither the init-header search, the panic search, nor
    # the depth walkers below can be steered by comment/string content.
    content = _go_strip_comments_and_strings(content)
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
    # A defer registered before the panic may recover() it; a return
    # before the panic ends init first. Either way the abort is not
    # proven to terminate loading — no witness.
    if _GO_RECOVERY_TOKEN.search(init_body, 0, panic_match.start()):
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


def _go_find_matching_brace(source: str, open_pos: int) -> int | None:
    """Given index of an opening ``{``, return index of the
    matching closing ``}``. Returns None on malformed input."""
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != "{":
        return None
    depth = 1
    i = open_pos + 1
    n = len(source)
    while i < n and depth > 0:
        c = source[i]
        if c == "/" and i + 1 < n:
            if source[i + 1] == "/":
                nl = source.find("\n", i + 2)
                i = nl + 1 if nl != -1 else n
                continue
            if source[i + 1] == "*":
                end = source.find("*/", i + 2)
                i = end + 2 if end != -1 else n
                continue
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


def _go_skip_string(source: str, start: int) -> int | None:
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
    block (if / for / switch / select). Comments and string literals
    are skipped exactly as in :func:`_go_find_matching_brace` — a
    ``}`` inside a comment before the panic would otherwise drop the
    depth and misread a conditional panic as unconditional."""
    depth = 0
    i = 0
    n = len(body)
    while i < panic_offset:
        c = body[i]
        if c == "/" and i + 1 < n:
            if body[i + 1] == "/":
                nl = body.find("\n", i + 2)
                i = nl + 1 if nl != -1 else n
                continue
            if body[i + 1] == "*":
                end = body.find("*/", i + 2)
                i = end + 2 if end != -1 else n
                continue
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
    # A skip that jumped PAST the panic means the "panic" itself sits
    # inside a comment / string literal — not a real abort.
    return i == panic_offset and depth == 0


# ---------------------------------------------------------------------------
# Rust — ``compile_error!(...)`` at module scope. Triggers at
# compile time; module never compiles, hence never loads. Macro
# may also appear inside ``#[cfg(...)]`` gates — those are
# conditional on build features and we conservatively do NOT
# flag them (build configuration is out of scope for static
# analysis). Matched over the tokenizer-grade blanked view so a
# ``compile_error!`` inside a comment or string literal (both
# idiomatic in macro documentation) can never fabricate the
# whole-file abort gate. No grammar / parse errors → bail.
# ---------------------------------------------------------------------------


_RUST_COMPILE_ERROR = re.compile(
    r"^[ \t]*compile_error\s*!\s*\(", re.MULTILINE,
)


def _detect_rust(content: str) -> ModuleLoadAbort | None:
    from core.inventory.lexical_view import LexicalRefusal, blank_noncode

    try:
        stripped = blank_noncode("rust", content)
    except LexicalRefusal:
        # Parse errors: recovered token boundaries are guesses; a
        # partial view could fabricate a whole-file abort. Bail —
        # toward no suppression.
        return None
    if stripped is None:
        # Grammar unavailable — cannot vouch a code view; no witness.
        return None
    # Naive but effective: examine only the FIRST compile_error! at
    # line start (after any leading whitespace). If that occurrence
    # is attribute-gated, report nothing — later occurrences are not
    # scanned, so an unconditional compile_error following a
    # cfg-gated one is missed. The substrate doesn't model cfg
    # gates; treating those sites as out of scope is the module-wide
    # false-negative bias (miss a deferral, never suppress live
    # code).
    m = _RUST_COMPILE_ERROR.search(stripped)
    if not m:
        return None
    # Module scope only: a ``compile_error!`` nested inside braces is
    # most commonly a ``macro_rules!`` arm (the ubiquitous "bad
    # invocation" guard, e.g. a fallback match arm) or function-body
    # code — sites that fire conditionally or never, where flagging
    # would hard-suppress a live file. A ``mod``-nested unconditional
    # compile_error is skipped too: a missed deferral, the module-wide
    # cheap (false-negative) direction. All three delimiter pairs
    # count: macro invocations take any token-tree delimiter, and a
    # ``compile_error!`` inside ``ignore_it!( ... )`` / ``ignore_it![
    # ... ]`` never expands (rustc-verified) but leaves the prefix
    # brace-balanced — only the dangling ``(`` / ``[`` betrays it.
    # Valid Rust code before a genuine module-scope statement nets
    # zero on every pair; delimiters inside strings/comments are
    # already blanked, so raw counts over the prefix are exact.
    prefix = stripped[: m.start()]
    if any(
        prefix.count(op) - prefix.count(cl) != 0
        for op, cl in (("{", "}"), ("(", ")"), ("[", "]"))
    ):
        return None
    # Check that the preceding non-whitespace token isn't ``]`` (end
    # of an attribute). A bare attribute-attached compile_error like
    # ``#[cfg(...)] compile_error!(...)`` is conditional; skip it.
    before = prefix.rstrip()
    if before.endswith("]"):
        return None
    line_no = stripped.count("\n", 0, m.start()) + 1
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
#
# Scanned over the tokenizer-grade blanked view: comments, strings,
# heredocs/nowdocs, backtick shell strings and the HTML text outside
# the PHP tags are spaced out first, so ``die`` in prose or string
# data can never fabricate the whole-file abort gate. Only the
# ``<?php`` open tags remain for this detector to blank (so the first
# statement after a tag is statement-initial). No grammar / parse
# errors → bail, toward no suppression.
# ---------------------------------------------------------------------------


_PHP_TAG = re.compile(r"<\?php|<\?=|<\?|\?>")

_PHP_ABORT = re.compile(r"throw\s+new\s+([A-Za-z_\\][\w\\]*)|die\b|exit\b")
# A statement-initial abort is preceded (ignoring whitespace) by one of
# these — i.e. it begins a statement, so it is not a branch/modifier body.
# (Open/close tags are stripped to whitespace first, so the first statement
# after ``<?php`` sees ``last_significant is None`` and counts as initial.)
_PHP_STMT_BOUNDARY = frozenset({";", "{", "}"})

_PHP_RETURN = re.compile(r"return\b")
# A brace provably opening a PHP function/method/closure body: a
# ``function`` keyword with no brace/semicolon between it and the
# ``{`` (covers names, parameter lists, ``use (...)`` closures and
# return-type declarations). Same abstain doctrine as the JS matcher:
# an unproven brace counts as file-scope, so a ``return`` inside it
# withholds the witness (a file-scope return ends the include before
# any later abort line runs).
_PHP_FN_BRACE = re.compile(r"\bfunction\b[^{};]*$")


def _detect_php(content: str) -> ModuleLoadAbort | None:
    from core.inventory.lexical_view import LexicalRefusal, blank_noncode

    try:
        stripped = blank_noncode("php", content)
    except LexicalRefusal:
        # Parse errors: recovered token boundaries are guesses; a
        # partial view could fabricate a whole-file abort. Bail —
        # toward no suppression.
        return None
    if stripped is None:
        # Grammar unavailable — cannot vouch a code view; no witness.
        return None

    def _spaces(m: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    # Blank the PHP open tags so the first statement after ``<?php``
    # is statement-initial and the tag chars never read as a boundary
    # (the close tags and surrounding HTML are already blanked).
    stripped = _PHP_TAG.sub(_spaces, stripped)
    depth = 0
    fn_depth = 0
    brace_is_fn: list[bool] = []
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
            is_fn = bool(_PHP_FN_BRACE.search(stripped, max(0, i - 400), i))
            brace_is_fn.append(is_fn)
            if is_fn:
                fn_depth += 1
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
            if brace_is_fn and brace_is_fn.pop():
                fn_depth -= 1
        elif c == "r" and fn_depth == 0 and (
                i == 0 or not (stripped[i - 1].isalnum()
                               or stripped[i - 1] in "_$")):
            if _PHP_RETURN.match(stripped, i):
                # A file-scope return (directly, or inside an executed
                # conditional block) ends the include before any later
                # abort runs. Abstain — toward no suppression.
                return None
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
# ``exit!`` must precede ``exit\b`` — leftmost-alternative semantics
# would otherwise always take the ``exit\b`` prefix match, leaving the
# ``exit!`` alternative dead.
_RB_ABORT = re.compile(r"^(raise\s+\S|abort\b|exit!|exit\b|fail\s+\S|Kernel\.(abort|exit))")
# Modifier forms that make the abort conditional or CAUGHT on the same
# line. ``rescue`` matters as much as the conditionals: an inline
# ``raise "boom" rescue nil`` is caught immediately — execution
# continues, the file loads, and flagging it fabricates the whole-file
# dead gate on a live file.
_RB_MODIFIER = re.compile(r"\b(if|unless|while|until|rescue)\b")
# An endless method definition (``def foo = 42``, ``def foo(a) = a``)
# opens NO body and has NO ``end`` — counting it as an opener leaves
# the depth stuck at 1 and silently disables detection for the rest
# of the file. Setter defs (``def foo=(v)``) keep their ``end`` and
# must NOT match: the ``=`` alternative with parens requires the
# parameter list first, and the paren-less alternative requires
# whitespace on both sides of the ``=``.
_RB_ENDLESS_DEF = re.compile(
    r"^def\s+(?:self\s*\.\s*)?[A-Za-z_]\w*[!?]?"
    r"(?:\s*\([^()]*\)\s*=(?![=~>])|\s+=\s)"
)
# A top-level ``return`` (valid at Ruby file scope) ends the file's
# execution — any later abort line never runs. Modifier-conditional
# forms (``return if cond``) are ambiguous the same way; both abstain.
_RB_RETURN = re.compile(r"^return\b")


def _detect_ruby(content: str) -> ModuleLoadAbort | None:
    # Scan the tokenizer-grade blanked view: comments, strings, heredoc
    # bodies and the ``__END__`` section are spaced out, so a column-0
    # ``raise`` / ``exit`` line inside a heredoc or multi-line string
    # (idiomatic Ruby: SQL, usage banners) can never fabricate the
    # whole-file abort gate. String DELIMITERS survive blanking, so a
    # real ``raise "boom"`` still reads as raise-with-argument. No
    # grammar / parse errors → bail, toward no suppression.
    from core.inventory.lexical_view import LexicalRefusal, blank_noncode

    try:
        blanked = blank_noncode("ruby", content)
    except LexicalRefusal:
        return None
    if blanked is None:
        return None
    depth = 0
    for idx, line in enumerate(blanked.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        is_col0 = line[:1] not in (" ", "\t")
        if depth == 0:
            if _RB_RETURN.match(stripped):
                # Top-level return — execution ends here; a later abort
                # never runs. Abstain, toward no suppression.
                return None
            if (not is_col0 and _RB_OPENER.match(stripped)
                    and not _RB_ONELINER.search(stripped)
                    and not _RB_ENDLESS_DEF.match(stripped)):
                # An INDENTED opener at depth zero breaks the column-0
                # nesting model: following column-0 lines (including an
                # abort) may sit inside its body, unconditionally-looking
                # but conditional. Bail on the whole file — toward no
                # suppression.
                return None
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
            elif (_RB_OPENER.match(stripped)
                    and not _RB_ONELINER.search(stripped)
                    and not _RB_ENDLESS_DEF.match(stripped)):
                # one-liner (``def f; end``) and endless defs
                # (``def f = 42``) are net-zero — don't increment.
                depth += 1
    return None


__all__ = ["ModuleLoadAbort", "detect_module_load_abort"]

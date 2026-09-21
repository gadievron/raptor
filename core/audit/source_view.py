"""Sanitized source views — comments, strings, and dead regions blanked.

Lexical checkers that regex raw source treat prose as code: a comment
that merely MENTIONS a sink ("/* do not use memcpy here */") satisfies
a presence check, and a comment mentioning a declaration ("/* legacy:
void check_perm() removed */") forges an absence/shape receipt.  Both
directions are hostile-repo steerable, so every lexical receipt must
be earned against a view with comments and string/char literals
blanked out.

:func:`sanitized_view` is the shared chokepoint: single-pass scanner,
newlines preserved (line numbers stay valid), blanked spans replaced
with spaces.  Language is chosen from the file extension; unknown
extensions get the C-family scanner (its comment/string forms are the
common denominator for C/C++/Java/Go/Rust/JS/TS).  Per-language
string grammar rides on top of that common denominator: C/C++ raw
strings (``R"delim(…)delim"``), Rust raw strings (``r#"…"#``), Java
text blocks (triple-quote delimited), Go raw backticks, JS/TS template literals
(``${…}`` interpolation stays visible — it is executable code, and
blanking it forged absence receipts), PHP ``#`` comments and
heredoc/nowdoc bodies, and Lua ``--``/``--[[…]]`` comments with
``[[…]]`` long strings.  All the multi-line forms carry state across
lines, so a comment marker inside string data can never open or
close comment state (the swallow direction), and an escaped quote
can never close a literal early.

``keep_strings=True`` selects the comments-only view: string
literals stay verbatim while comments still blank.  Consumers whose
refusal logic must SEE string prose (the prefilter's trivial-wrapper
judged view — over-inclusion there only costs a review) read this
mode; the preprocessor-dead blanking is skipped in it because that
detection is only sound over a fully-blanked view (kept string data
spelling ``#if 0`` would otherwise mint a fake dead region — the
swallow direction).

Division of responsibility: this module is the shared REGEX-GRADE
single-pass scanner for in-flight textual views over sources and
segments (checker receipts, prefilter views) — no parser
dependencies, tolerant of snippets.  Node-fidelity blanking of whole
inventory files (grammar-table-driven, tree-sitter-backed) lives in
:mod:`core.inventory.lexical_view`; new consumers pick one of the
two, never a bespoke stripper.

The C-family scanner also blanks the two preprocessor-dead channels
with the same one-planted-line attacker capability as a comment:
``#if 0 … #endif`` regions (whole-condition constant-zero spellings
only — ``0``/``(0)``/``0x0``/``0L``/``00`` are dead in every build;
any macro-bearing condition, including a zero prefix like
``#if 0 || FOO``, is build-dependent and not judged here — that
residual is documented, not covered) and backslash-line-continued
``//`` comments
(splicing happens before comment recognition, so the continued line
is comment text to the compiler).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Extensions handled by the hash-comment (Python/shell-style) scanner.
_HASH_COMMENT_EXTS = (
    ".py", ".pyi", ".sh", ".bash", ".rb", ".pl", ".tcl",
    ".yaml", ".yml", ".toml",
)

# Language-id routing for callers that already know the language
# (checkers holding an inventory language id or a tree-sitter grammar
# name rather than a file path).
_HASH_COMMENT_LANGS = frozenset({
    "python", "ruby", "shell", "bash", "perl", "yaml", "toml",
})

_LUA_EXTS = (".lua",)


@dataclass(frozen=True)
class _CFamilySpec:
    """Per-language string grammar riding on the C-family scanner.

    ``backtick``: ``"none"`` (a backtick is code), ``"raw"`` (Go raw
    string — multi-line, no escapes), or ``"template"`` (JS/TS
    template literal — multi-line, escapes, ``${…}`` interpolation
    scanned as code).  ``single_quote_strings``: JS/TS treat
    ``'...'`` as a full string literal; everywhere else in the C
    family a single quote only ever opens a short char/rune literal —
    treating it as a to-end-of-line string made a Rust lifetime tick
    (``&'a str``) blank the rest of the line, forging absence
    receipts.  The remaining flags switch on the language's own
    multi-line/raw string forms and PHP's extra comment/heredoc
    grammar.
    """

    backtick: str = "none"
    single_quote_strings: bool = False
    hash_line_comments: bool = False
    cpp_raw_strings: bool = False
    rust_raw_strings: bool = False
    java_text_blocks: bool = False
    php_heredocs: bool = False
    regex_literals: bool = False


_DEFAULT_C_SPEC = _CFamilySpec()
_JS_SPEC = _CFamilySpec(
    backtick="template", single_quote_strings=True, regex_literals=True)

_C_FAMILY_SPECS = {
    # C headers are shared with C++ and C11 has no competing meaning
    # for the raw-string opener shape, so C gets the C++ raw grammar
    # too (a false raw-open needs the exact `R"delim(` spelling).
    "c": _CFamilySpec(cpp_raw_strings=True),
    "cpp": _CFamilySpec(cpp_raw_strings=True),
    "rust": _CFamilySpec(rust_raw_strings=True),
    "java": _CFamilySpec(java_text_blocks=True),
    "go": _CFamilySpec(backtick="raw"),
    "javascript": _JS_SPEC,
    "typescript": _JS_SPEC,
    "jsx": _JS_SPEC,
    "tsx": _JS_SPEC,
    "php": _CFamilySpec(hash_line_comments=True, php_heredocs=True),
}

_C_FAMILY_EXT_LANG = {
    ".c": "c", ".h": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".rs": "rust", ".java": "java", ".go": "go",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".php": "php", ".phtml": "php",
}


# Char-literal shape: 'x' or a short escape ('\n', '\'', '\x41').
_CHAR_LIT_RE = re.compile(r"'(?:\\[^\n]{1,3}|[^'\\\n])'")


def sanitized_view(
    source: str, file_path: str = "", *, language: str | None = None,
    keep_strings: bool = False,
) -> str:
    """Return *source* with comments and string literals blanked.

    Every blanked character becomes a space; newlines inside blanked
    regions are preserved, so offsets and line numbers computed on the
    view map 1:1 onto the original text.

    The scanner is chosen from *language* (an inventory language id
    such as ``"python"``/``"java"``/``"go"``) when given, else from
    the *file_path* extension. Segments work too: the input does not
    have to be a whole file, so a checker can sanitize just the
    handler/clause text it is about to regex.

    ``keep_strings=True`` blanks comments only, leaving string
    literals verbatim (see the module docstring for the direction
    contract and why preprocessor-dead blanking is skipped in that
    mode).
    """
    if not source:
        return source
    if language:
        lang = language.lower()
        if lang == "lua":
            return _strip_lua(source, keep_strings=keep_strings)
        if lang in _HASH_COMMENT_LANGS:
            return _strip_python_like(source, keep_strings=keep_strings)
        spec = _C_FAMILY_SPECS.get(lang, _DEFAULT_C_SPEC)
    else:
        lower = (file_path or "").lower()
        if lower.endswith(_LUA_EXTS):
            return _strip_lua(source, keep_strings=keep_strings)
        if lower.endswith(_HASH_COMMENT_EXTS):
            return _strip_python_like(source, keep_strings=keep_strings)
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        spec = _C_FAMILY_SPECS.get(
            _C_FAMILY_EXT_LANG.get(ext, ""), _DEFAULT_C_SPEC)
    view = _strip_c_family(source, spec, keep_strings=keep_strings)
    return view if keep_strings else _blank_if0_regions(view)


# Preprocessor-dead region detection. Runs on the comment/string-
# blanked view, so a ``#if 0`` inside a comment or string is already
# spaces and never triggers.
#
# Always-dead conditions are matched CONSTANT-ONLY with the whole
# condition anchored: every zero spelling (``0``, ``(0)``, ``0x0``,
# ``0L``, ``00``, ``0u``, nested parens) is unconditionally dead in
# every build, while any macro-bearing condition — including a zero
# PREFIX like ``#if 0 || FOO``, which is LIVE when FOO is truthy —
# is refused (build-dependent truth is not judged here).
_PP_IF_COND_RE = re.compile(r"^[ \t]*#[ \t]*if\b(?P<cond>.*)$")
_PP_ALWAYS_DEAD_COND_RE = re.compile(
    r"[ \t(]*0+(?:[xX]0+)?[uUlL]*[ \t)]*"
)
_PP_IF_RE = re.compile(r"^[ \t]*#[ \t]*(?:if|ifdef|ifndef)\b")
_PP_ENDIF_RE = re.compile(r"^[ \t]*#[ \t]*endif\b")
_PP_ELSE_RE = re.compile(r"^[ \t]*#[ \t]*(?:else|elif)\b")


def _is_always_dead_if(ln: str) -> bool:
    """True for an ``#if`` whose whole condition is a constant zero
    (any spelling) — dead in every build. Trailing comment text is
    already spaces on the blanked view this runs over; a trailing
    ``\r`` (CRLF input) is tolerated."""
    m = _PP_IF_COND_RE.match(ln)
    if m is None:
        return False
    cond = m.group("cond").rstrip("\r")
    return _PP_ALWAYS_DEAD_COND_RE.fullmatch(cond) is not None


def _blank_if0_regions(view: str) -> str:
    """Blank always-dead ``#if`` regions from a comment/string-blanked
    view.

    Preprocessor-dead text is prose to the compiler exactly like a
    comment — a planted ``#if 0`` block steers lexical receipts with
    the same one-line attacker capability. Dead runs from the
    directive to its matching ``#endif``, or to a matching
    ``#else``/``#elif`` (those arms may be live); nested conditionals
    inside the dead region are tracked by depth. Conservative on
    purpose: only whole-condition constant-zero spellings are judged
    (see ``_PP_ALWAYS_DEAD_COND_RE``) — any macro-bearing condition
    is build-dependent and left visible; an unterminated region
    blanks to end of input (dead until proven otherwise — refusal
    direction for receipt consumers). Line lengths are preserved, so
    offsets keep mapping 1:1.
    """
    lines = view.split("\n")
    out: list[str] = []
    depth = 0
    for ln in lines:
        if depth == 0:
            if _is_always_dead_if(ln):
                depth = 1
                out.append(" " * len(ln))
            else:
                out.append(ln)
            continue
        if _PP_IF_RE.match(ln):
            depth += 1
        elif _PP_ENDIF_RE.match(ln):
            depth -= 1
        elif depth == 1 and _PP_ELSE_RE.match(ln):
            depth = 0
        out.append(" " * len(ln))
    return "\n".join(out)


def _blank(chars: list[str], start: int, end: int) -> None:
    """Blank ``chars[start:end]``, keeping newlines."""
    for i in range(start, end):
        if chars[i] != "\n":
            chars[i] = " "


def _strip_c_family(
    source: str, spec: _CFamilySpec, *, keep_strings: bool = False,
) -> str:
    chars = list(source)
    n = len(source)

    def blank_str(start: int, end: int) -> None:
        """Blank STRING content — a no-op on the comments-only view."""
        if not keep_strings:
            _blank(chars, start, end)

    i = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            end = source.find("\n", i)
            # Backslash-newline splicing happens BEFORE comment
            # recognition (C/C++/Java): a ``// … \`` comment
            # continues onto the next physical line, which is
            # comment text to the compiler — a guard "hidden"
            # there must blank like any other comment byte.
            while end > 0 and (
                source[end - 1] == "\\"
                or (source[end - 1] == "\r" and end > 1
                    and source[end - 2] == "\\")
            ):
                end = source.find("\n", end + 1)
            end = n if end < 0 else end
            _blank(chars, i, end)
            i = end
        elif ch == "/" and nxt == "*":
            close = source.find("*/", i + 2)
            end = n if close < 0 else close + 2
            _blank(chars, i, end)
            i = end
        elif (spec.regex_literals and ch == "/"
                and (rex_end := _js_regex_end(source, i)) is not None):
            # JS/TS regex literal. Lexed BEFORE it can mint comment
            # state: `/\//` (the escaped-slash regex) read in code
            # position as division-then-`//` blanked real code after
            # the regex out of BOTH views — the swallow direction.
            # The comment arms above still win at `//`/`/*` (a regex
            # cannot start with `/` or `*`), and _js_regex_end judges
            # the division-vs-regex ambiguity from the preceding
            # token, falling back to division (scan on) when the
            # candidate does not close on its own line.
            blank_str(i + 1, rex_end - 1)
            i = rex_end
        elif spec.hash_line_comments and ch == "#":
            end = source.find("\n", i)
            end = n if end < 0 else end
            _blank(chars, i, end)
            i = end
        elif (spec.php_heredocs and ch == "<"
                and source.startswith("<<<", i)):
            nxt_i = _php_heredoc(source, i, blank_str)
            i = nxt_i if nxt_i is not None else i + 3
        elif (spec.java_text_blocks and ch == '"'
                and source.startswith('"""', i)):
            end = _java_text_block_end(source, i)
            blank_str(i + 3, max(i + 3, end - 3))
            i = end
        elif (spec.cpp_raw_strings and ch == '"'
                and (delim := _cpp_raw_delim(source, i)) is not None):
            # R"delim( … )delim" — content is raw across lines; an
            # interior quote or comment marker is data, never a close.
            closer = ')' + delim + '"'
            body = i + 1 + len(delim) + 1
            close = source.find(closer, body)
            end = n if close < 0 else close + len(closer)
            blank_str(body, n if close < 0 else close)
            i = end
        elif (spec.rust_raw_strings and ch == '"'
                and (hashes := _rust_raw_hashes(source, i)) is not None):
            closer = '"' + "#" * hashes
            close = source.find(closer, i + 1)
            end = n if close < 0 else close + len(closer)
            blank_str(i + 1, n if close < 0 else close)
            i = end
        elif ch == "'" and not spec.single_quote_strings:
            # Char/rune literal only, and only when it has the
            # char-literal shape (closing quote within a couple of
            # characters, escapes allowed). A lone tick — a Rust
            # lifetime, an apostrophe in code — is NOT a literal and
            # must not swallow the rest of the line.
            end = _char_literal_end(source, i)
            if end is None:
                i += 1
            else:
                blank_str(i + 1, end - 1)
                i = end
        elif ch == "`" and spec.backtick == "template":
            i = _template_literal(source, chars, i, blank_str)
        elif ch == '"' or ch == "'" or (
                ch == "`" and spec.backtick == "raw"):
            end = _string_end(source, i, ch, raw=(ch == "`"))
            # Keep the delimiters so shapes like ``""`` stay visible;
            # blank only the contents.
            blank_str(i + 1, min(end, n) - 1 if end <= n else n)
            i = end
        else:
            i += 1
    return "".join(chars)


def _strip_python_like(source: str, *, keep_strings: bool = False) -> str:
    chars = list(source)
    n = len(source)
    i = 0
    while i < n:
        ch = source[i]
        if ch == "#":
            if i > 0 and source[i - 1] == "$":
                # Perl `$#array` (last index) / shell `$#` (arg
                # count): a sigil-prefixed `#` is code, not a comment
                # opener — blanking from it swallowed sink-as-argument
                # references out of the wrapper's reference view (the
                # suppression direction).
                i += 1
                continue
            end = source.find("\n", i)
            end = n if end < 0 else end
            _blank(chars, i, end)
            i = end
        elif ch in ('"', "'"):
            triple = source[i:i + 3] in ('"""', "'''")
            if triple:
                close = source.find(source[i:i + 3], i + 3)
                end = n if close < 0 else close + 3
                if not keep_strings:
                    _blank(chars, i + 3, max(i + 3, end - 3))
                i = end
            else:
                end = _string_end(source, i, ch)
                if not keep_strings:
                    _blank(chars, i + 1, min(end, n) - 1 if end <= n else n)
                i = end
        else:
            i += 1
    return "".join(chars)


def _char_literal_end(source: str, start: int) -> int | None:
    """Index just past a char-literal's closing quote, or None.

    Accepts the char-literal shape only: one plain character
    (``'x'``) or a short escape (``'\\n'``, ``'\\x41'`` — at most
    three characters after the backslash). Anything else is not a
    literal.
    """
    m = _CHAR_LIT_RE.match(source, start)
    return m.end() if m else None


def _string_end(source: str, start: int, quote: str, *, raw: bool = False) -> int:
    """Index just past the closing quote (or end of line/file).

    Unterminated single-line strings stop at the newline — a lone
    apostrophe in text must not swallow the rest of the file.
    """
    n = len(source)
    i = start + 1
    while i < n:
        ch = source[i]
        if ch == "\\" and not raw:
            i += 2
            continue
        if ch == quote:
            return i + 1
        if ch == "\n" and not raw:
            return i + 1
        i += 1
    return n


def _strip_lua(source: str, *, keep_strings: bool = False) -> str:
    """Lua scanner: ``--``/``--[[…]]`` comments, ``[[…]]``/``[=[…]=]``
    long strings (multi-line, no escapes), and quote strings.  ``//``
    is Lua 5.3 integer division and ``/*`` is not a comment — routing
    Lua through the C-family scanner blanked live code after those
    operators (the swallow direction)."""
    chars = list(source)
    n = len(source)
    i = 0
    while i < n:
        ch = source[i]
        if ch == "-" and source.startswith("--", i):
            m = _LUA_LONG_OPEN_RE.match(source, i + 2)
            if m:
                closer = "]" + m.group(1) + "]"
                close = source.find(closer, m.end())
                end = n if close < 0 else close + len(closer)
            else:
                end = source.find("\n", i)
                end = n if end < 0 else end
            _blank(chars, i, end)
            i = end
        elif ch == "[" and (m := _LUA_LONG_OPEN_RE.match(source, i)):
            closer = "]" + m.group(1) + "]"
            close = source.find(closer, m.end())
            end = n if close < 0 else close + len(closer)
            if not keep_strings:
                _blank(chars, m.end(), n if close < 0 else close)
            i = end
        elif ch in ('"', "'"):
            end = _string_end(source, i, ch)
            if not keep_strings:
                _blank(chars, i + 1, min(end, n) - 1 if end <= n else n)
            i = end
        else:
            i += 1
    return "".join(chars)


_LUA_LONG_OPEN_RE = re.compile(r"\[(=*)\[")

# Heredoc opener: ``<<<ID`` / ``<<<"ID"`` (interpolating) /
# ``<<<'ID'`` (nowdoc), nothing but whitespace to end of line.
_PHP_HEREDOC_OPEN_RE = re.compile(
    r"<<<[ \t]*(?:\"(\w+)\"|'(\w+)'|(\w+))[ \t]*\r?\n")


def _php_heredoc(source: str, i: int, blank_str) -> int | None:
    """Consume a PHP heredoc/nowdoc opened at ``i`` (``<<<``); blank
    its body up to the terminator line (PHP 7.3 flexible closers —
    the identifier may be indented and followed by punctuation).
    Returns the index just past the terminator identifier, or None
    when ``<<<`` does not open a heredoc here."""
    m = _PHP_HEREDOC_OPEN_RE.match(source, i)
    if m is None:
        return None
    ident = m.group(1) or m.group(2) or m.group(3)
    term = re.compile(
        rf"^[ \t]*{re.escape(ident)}(?![0-9A-Za-z_])", re.M)
    t = term.search(source, m.end())
    if t is None:
        blank_str(m.end(), len(source))
        return len(source)
    blank_str(m.end(), t.start())
    return t.end()


# d-char set per the C++ grammar: no space/parens/backslash/control
# AND no quote — admitting `"` let an ill-formed `R"abc"` shape
# (macro / #if-0 text) false-open a raw string and blank to EOF.
_CPP_RAW_DELIM_RE = re.compile(r"([^ ()\\\t\r\n\v\f\"]{0,16})\(")

#: Keywords a `/` may directly follow while still opening a REGEX
#: literal (value position). Closed JS/TS grammar taxonomy, not a
#: learned name vocabulary.
_JS_REGEX_PRECEDING_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete",
    "void", "do", "else", "case", "yield", "await", "throw",
})


def _js_regex_end(source: str, i: int) -> int | None:
    """Index just past the regex literal opened by the ``/`` at
    ``i``, or None when this position reads as division (or the
    candidate does not close on its own line — regex literals are
    single-line, so scanning on as code is the conservative
    fallback). Position rule (the standard lexer heuristic): after
    a value ender (identifier, number, ``)``, ``]``, quote) a ``/``
    divides; after an operator/opener/keyword/line start it opens a
    regex. Escapes and ``[...]`` classes (where ``/`` is literal)
    are honoured."""
    if source.startswith("//", i) or source.startswith("/*", i):
        return None
    j = i - 1
    while j >= 0 and source[j] in " \t":
        j -= 1
    if j >= 0:
        prev = source[j]
        if prev.isalnum() or prev in "_$":
            k = j
            while k >= 0 and (source[k].isalnum() or source[k] in "_$"):
                k -= 1
            word = source[k + 1:j + 1]
            if word[0].isdigit():
                return None
            if word not in _JS_REGEX_PRECEDING_KEYWORDS:
                return None
        elif prev in ")]\"'`":
            return None
    n = len(source)
    j = i + 1
    in_class = False
    while j < n:
        ch = source[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "\n":
            return None
        if in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
        elif ch == "/":
            return j + 1
        j += 1
    return None


def _cpp_raw_delim(source: str, i: int) -> str | None:
    """The raw-string delimiter when the quote at ``i`` opens a C/C++
    ``R"delim(`` literal (optionally ``u8``/``u``/``U``/``L``
    prefixed), else None. The prefix must not be the tail of a longer
    identifier."""
    j = i - 1
    if j < 0 or source[j] != "R":
        return None
    k = j - 1
    if k >= 1 and source[k] == "8" and source[k - 1] == "u":
        k -= 2
    elif k >= 0 and source[k] in "uUL":
        k -= 1
    if k >= 0 and (source[k].isalnum() or source[k] == "_"):
        return None
    m = _CPP_RAW_DELIM_RE.match(source, i + 1)
    return m.group(1) if m else None


def _rust_raw_hashes(source: str, i: int) -> int | None:
    """Hash count when the quote at ``i`` opens a Rust raw string
    (``r"…"``, ``r#"…"#``, ``br##"…"##``, any hash depth), else
    None."""
    j = i - 1
    hashes = 0
    while j >= 0 and source[j] == "#":
        hashes += 1
        j -= 1
    if j < 0 or source[j] != "r":
        return None
    k = j - 1
    if k >= 0 and source[k] == "b":
        k -= 1
    if k >= 0 and (source[k].isalnum() or source[k] == "_"):
        return None
    return hashes


def _java_text_block_end(source: str, i: int) -> int:
    """Index just past the ``\\\"\\\"\\\"`` closing the Java text
    block opened at ``i`` (escapes honoured), or end of input."""
    n = len(source)
    j = i + 3
    while j < n:
        if source[j] == "\\":
            j += 2
            continue
        if source.startswith('"""', j):
            return j + 3
        j += 1
    return n


def _template_literal(source: str, chars: list[str], i: int, blank_str) -> int:
    """Consume the JS/TS template literal opened by the backtick at
    ``i``: string content blanks (escape-aware), while ``${…}``
    interpolation is scanned as CODE — nested strings, templates, and
    comments inside it get their own treatment. Blanking the
    interpolation would hide executable code from receipt consumers
    (the swallow direction). Returns the index just past the closing
    backtick (or end of input)."""
    n = len(source)
    j = i + 1
    while j < n:
        ch = source[j]
        if ch == "\\":
            blank_str(j, min(j + 2, n))
            j += 2
            continue
        if ch == "`":
            return j + 1
        if ch == "$" and source.startswith("${", j):
            j += 2
            depth = 1
            while j < n and depth:
                c2 = source[j]
                if c2 == "{":
                    depth += 1
                    j += 1
                elif c2 == "}":
                    depth -= 1
                    j += 1
                elif c2 == "`":
                    j = _template_literal(source, chars, j, blank_str)
                elif c2 in ('"', "'"):
                    end = _string_end(source, j, c2)
                    blank_str(j + 1, min(end, n) - 1 if end <= n else n)
                    j = end
                elif c2 == "/" and source.startswith("//", j):
                    end = source.find("\n", j)
                    end = n if end < 0 else end
                    _blank(chars, j, end)
                    j = end
                elif c2 == "/" and source.startswith("/*", j):
                    close = source.find("*/", j + 2)
                    end = n if close < 0 else close + 2
                    _blank(chars, j, end)
                    j = end
                else:
                    j += 1
            continue
        blank_str(j, j + 1)
        j += 1
    return n

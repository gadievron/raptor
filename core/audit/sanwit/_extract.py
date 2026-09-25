"""Sanitizer-chain extraction from PHP function source.

The witness executes the chain AS WRITTEN, never a paraphrase: every
step is re-emitted from its original lexemes with only the chained
data variable renamed. That is only sound when the chain is provably
a pure straight-line composition — so extraction REFUSES, with a
specific reason, whenever it cannot isolate one:

* the anchoring sanitizer application is not a bare top-level
  assignment (conditional/loop/ternary application, or no
  application at all);
* any step expression falls outside the step grammar (allowlisted
  pure builtins, exactly one data slot, literal-only other
  arguments);
* control flow, braces or heredoc intrude on the chain span;
* the chain variable is transformed again after an intervening use
  or branch (stopping early would attribute a truncated chain and
  could mint a false insufficiency verdict).

The grammar is the containment boundary: probe code is built only
from allowlisted builtin names and validated literal lexemes, so
target-authored source never contributes executable structure beyond
the sanitizer chain itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ── step vocabulary ──────────────────────────────────────────────────

#: Pure, deterministic string-to-string builtins the chain may
#: contain, curated by category (seed-set policy: small curated sets
#: per category). Everything else refuses — including casts and
#: sprintf in this cut (named growth rows, not silent acceptance).
_STEP_ALLOWLIST: dict[str, tuple[str, ...]] = {
    "html-encode": (
        "htmlspecialchars", "htmlentities", "htmlspecialchars_decode",
        "html_entity_decode", "strip_tags", "nl2br",
    ),
    "shell-escape": ("escapeshellarg", "escapeshellcmd"),
    "quote-rewrite": (
        "addslashes", "stripslashes", "quotemeta",
        "str_replace", "str_ireplace", "preg_replace", "preg_quote",
    ),
    "case-trim": ("trim", "ltrim", "rtrim", "strtolower", "strtoupper"),
    "url-encode": (
        "urlencode", "urldecode", "rawurlencode", "rawurldecode",
    ),
}

ALLOWED_STEP_CALLABLES: frozenset[str] = frozenset(
    name for names in _STEP_ALLOWLIST.values() for name in names
)

#: Constant spellings admitted as non-data arguments (the
#: htmlspecialchars/htmlentities flag vocabulary), plus bare
#: true/false/null keywords. ``|`` combinations of these are allowed.
ALLOWED_CONSTANTS: frozenset[str] = frozenset({
    "ENT_QUOTES", "ENT_COMPAT", "ENT_NOQUOTES", "ENT_HTML401",
    "ENT_HTML5", "ENT_XML1", "ENT_XHTML", "ENT_SUBSTITUTE",
    "ENT_IGNORE",
})

_KEYWORD_LITERALS = frozenset({"true", "false", "null"})

# Control-flow / structure tokens that must not intrude on the chain
# span (word-boundary matched over comment-stripped text).
_CONTROL_RE = re.compile(
    r"\b(?:if|else|elseif|for|foreach|while|do|switch|case|return|"
    r"break|continue|try|catch|finally|throw|function|goto|match)\b"
    r"|[{}?]",
)


@dataclass(frozen=True)
class ChainStep:
    """One chain step, re-emittable with the data slot renamed."""

    callable_name: str
    #: Original lexeme text around the data slot: the step re-emits
    #: as ``before + <data expr> + after`` — byte-identical to the
    #: source except for the data variable's name.
    before: str
    after: str
    line: int

    def render(self, data_expr: str) -> str:
        return f"{self.before}{data_expr}{self.after}"

    def template(self) -> str:
        return self.render("{DATA}")


@dataclass(frozen=True)
class ChainExtraction:
    steps: tuple[ChainStep, ...]
    subject_var: str
    final_var: str


@dataclass(frozen=True)
class ExtractionRefusal:
    reason: str


# ── lexical pre-passes ───────────────────────────────────────────────


def _strip_comments(source: str) -> str | None:
    """Blank out PHP comments, preserving offsets. None on heredoc/
    nowdoc (``<<<``) — the chain lexer does not model those, refuse."""
    out = list(source)
    i, n = 0, len(source)
    state = ""  # "" | "'" | '"' | "//" | "/*"
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "":
            if ch == "<" and source[i:i + 3] == "<<<":
                return None
            if ch in ("'", '"'):
                state = ch
            elif ch == "/" and nxt == "/":
                state = "//"
                out[i] = out[i + 1] = " "
                i += 1
            elif ch == "#":
                state = "//"
                out[i] = " "
            elif ch == "/" and nxt == "*":
                state = "/*"
                out[i] = out[i + 1] = " "
                i += 1
        elif state in ("'", '"'):
            if ch == "\\":
                i += 2
                continue
            if ch == state:
                state = ""
        elif state == "//":
            if ch == "\n":
                state = ""
            else:
                out[i] = " "
        elif state == "/*":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                state = ""
                i += 1
            elif ch != "\n":
                out[i] = " "
        i += 1
    return "".join(out)


@dataclass(frozen=True)
class _Stmt:
    text: str
    depth: int   # brace depth at statement start
    line: int


def _statements(stripped: str) -> list[_Stmt]:
    """Split comment-stripped source into ``;``-terminated statements
    (splits only at paren depth 0, outside strings), tracking brace
    depth and line numbers."""
    stmts: list[_Stmt] = []
    buf: list[str] = []
    depth_brace = 0
    depth_paren = 0
    start_depth = 0
    line = 1
    start_line = 1
    state = ""
    escaped = False
    started = False

    def flush() -> None:
        nonlocal buf, started
        text = "".join(buf).strip()
        if text:
            stmts.append(_Stmt(text=text, depth=start_depth, line=start_line))
        buf = []
        started = False

    for ch in stripped:
        if ch == "\n":
            line += 1
        if state:
            buf.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == state:
                state = ""
            continue
        if ch in ("'", '"'):
            if not started:
                started, start_depth, start_line = True, depth_brace, line
            state = ch
            buf.append(ch)
            continue
        if ch == "{":
            flush()
            depth_brace += 1
            continue
        if ch == "}":
            flush()
            depth_brace -= 1
            continue
        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == ";" and depth_paren == 0:
            buf.append(ch)
            flush()
            continue
        if not started and not ch.isspace():
            started, start_depth, start_line = True, depth_brace, line
        buf.append(ch)
    flush()
    return stmts


# ── step-grammar tokenizer / parser ──────────────────────────────────

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<var>\$[A-Za-z_]\w*)
  | (?P<sq>'(?:[^'\\]|\\.)*')
  | (?P<dq>"(?:[^"\\]|\\.)*")
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<ident>\\?[A-Za-z_]\w*)
  | (?P<sym>[(),|\[\].])
    """,
    re.VERBOSE,
)


def _tokenize(expr: str) -> list[tuple[str, str]] | None:
    """(kind, lexeme) tokens, or None when any character falls outside
    the grammar's alphabet."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if m is None:
            return None
        pos = m.end()
        kind = m.lastgroup or ""
        if kind == "ws":
            continue
        tokens.append((kind, m.group()))
    return tokens


class _ParseRefusal(Exception):
    """Internal: carries the specific grammar-refusal reason."""


#: Double-quoted literals refuse on ANY ``$`` — outright, model-free.
#: PHP interpolation escape-parity is NOT modeled here on purpose: an
#: even backslash run before ``$`` ("\\\\${...}") passes a naive
#: lookbehind while interpolating LIVE, and ``${expr}`` executes
#: arbitrary expressions at probe scope. A ``$`` that rides into the
#: probe inside a double-quoted lexeme is therefore a grammar ESCAPE,
#: not data — and the per-execution token cannot save the verdict:
#: escaped code runs in the same process as the token, so the token
#: only ever authenticates NON-escape; the grammar is the one and
#: only defense against escape (one defense, not two). Sanitizer
#: chains essentially never need $-bearing string literals (zero
#: refusals across the positive fixture corpus), so the cost of the
#: blanket refusal is nil.
_DQ_DOLLAR_REFUSAL = (
    "double-quoted literal contains '$' — refused outright "
    "(interpolation escape-parity is not modeled; use a "
    "single-quoted literal)"
)


#: Expression-size ceiling (tokens). Real chain expressions are tens
#: of tokens; the cap bounds parser recursion (each nested call costs
#: >= 3 tokens, so depth stays far under the interpreter limit) and
#: hostile-source memory. Larger admits stranger expressions at
#: recursion-headroom cost; smaller starts refusing real multi-arg
#: replace tables.
_MAX_EXPR_TOKENS = 512


def _checked_tokens(expr: str) -> list[tuple[str, str]]:
    tokens = _tokenize(expr)
    if tokens is None:
        raise _ParseRefusal(
            "expression contains characters outside the step grammar",
        )
    if len(tokens) > _MAX_EXPR_TOKENS:
        raise _ParseRefusal(
            f"expression exceeds {_MAX_EXPR_TOKENS} tokens",
        )
    return tokens


class _Parser:
    """Recursive-descent parser for the step grammar.

    call     := IDENT '(' arg (',' arg)* ')'
    arg      := call | VAR | literal | flags | array
    literal  := SQ | DQ(no interpolation) | NUM | true|false|null
    flags    := CONST ('|' CONST)*
    array    := ('array' '(' | '[') literal (',' literal)* (')' | ']')

    Exactly one VAR (or one innermost nested call feeding the spine)
    may appear in the whole tree — the data slot.
    """

    def __init__(self, tokens: list[tuple[str, str]], expr: str) -> None:
        self.tokens = tokens
        self.expr = expr
        self.i = 0
        self.var_seen: list[tuple[int, int]] = []  # token spans of VARs

    def peek(self) -> tuple[str, str]:
        if self.i < len(self.tokens):
            return self.tokens[self.i]
        return ("eof", "")

    def take(self) -> tuple[str, str]:
        tok = self.peek()
        self.i += 1
        return tok

    def expect_sym(self, sym: str) -> None:
        kind, lex = self.take()
        if kind != "sym" or lex != sym:
            found = repr(lex) if lex else "end of expression"
            raise _ParseRefusal(f"expected {sym!r}, found {found}")

    # Each parse method returns a node dict; "call" nodes carry
    # ordered child nodes so the chain flattener can walk the spine.

    def parse_call(self) -> dict:
        kind, lex = self.take()
        if kind != "ident":
            raise _ParseRefusal(f"expected a function name, found {lex!r}")
        name = lex.lstrip("\\").lower()
        if name not in ALLOWED_STEP_CALLABLES:
            raise _ParseRefusal(
                f"function {lex!r} is not an allowlisted pure "
                "transform step",
            )
        start = self.i - 1
        self.expect_sym("(")
        args: list[dict] = [self.parse_arg()]
        while self.peek() == ("sym", ","):
            self.take()
            args.append(self.parse_arg())
        self.expect_sym(")")
        node = {
            "kind": "call", "name": name, "lexeme": lex, "args": args,
            "tok_start": start, "tok_end": self.i,
        }
        if name in ("preg_replace", "preg_quote"):
            self._check_preg(node)
        return node

    def parse_arg(self) -> dict:
        kind, lex = self.peek()
        if kind == "ident" and lex.lstrip("\\").lower() in (
            ALLOWED_STEP_CALLABLES
        ):
            return self.parse_call()
        if kind == "var":
            self.take()
            start = self.i - 1
            if self.peek() == ("sym", "["):
                # One level of literal indexing (`$_GET['x']`) joins
                # the data slot — the superglobal-read idiom. The
                # whole indexed access is substituted by the probe's
                # data variable; deeper indexing stays refused.
                self.take()
                k2, l2 = self.take()
                if k2 == "dq" and "$" in l2:
                    raise _ParseRefusal(_DQ_DOLLAR_REFUSAL)
                if k2 not in ("sq", "dq", "num"):
                    raise _ParseRefusal(
                        f"index {l2!r} is not a literal",
                    )
                self.expect_sym("]")
            node = {"kind": "var", "name": lex,
                    "tok_start": start, "tok_end": self.i}
            self.var_seen.append((node["tok_start"], node["tok_end"]))
            return node
        if kind in ("sq", "dq", "num"):
            self.take()
            if kind == "dq" and "$" in lex:
                raise _ParseRefusal(_DQ_DOLLAR_REFUSAL)
            return {"kind": "literal", "lexeme": lex}
        if kind == "ident":
            return self.parse_flags_or_keyword()
        if kind == "sym" and lex == "[":
            return self.parse_array("[", "]")
        found = repr(lex) if lex else "missing argument"
        raise _ParseRefusal(
            f"argument {found} is outside the literal grammar",
        )

    def parse_flags_or_keyword(self) -> dict:
        kind, lex = self.take()
        if lex.lower() in _KEYWORD_LITERALS:
            return {"kind": "literal", "lexeme": lex}
        if lex == "array" and self.peek() == ("sym", "("):
            return self.parse_array("(", ")")
        if lex not in ALLOWED_CONSTANTS:
            raise _ParseRefusal(
                f"constant {lex!r} is not in the allowed flag "
                "vocabulary",
            )
        while self.peek() == ("sym", "|"):
            self.take()
            kind2, lex2 = self.take()
            if kind2 != "ident" or lex2 not in ALLOWED_CONSTANTS:
                raise _ParseRefusal(
                    f"constant {lex2!r} is not in the allowed flag "
                    "vocabulary",
                )
        return {"kind": "flags"}

    def parse_array(self, open_sym: str, close_sym: str) -> dict:
        self.expect_sym(open_sym)
        if self.peek() != ("sym", close_sym):
            self._array_item()
            while self.peek() == ("sym", ","):
                self.take()
                if self.peek() == ("sym", close_sym):
                    break
                self._array_item()
        self.expect_sym(close_sym)
        return {"kind": "array"}

    def _array_item(self) -> None:
        kind, lex = self.take()
        if kind == "dq" and "$" in lex:
            raise _ParseRefusal(_DQ_DOLLAR_REFUSAL)
        if kind not in ("sq", "dq", "num") and (
            lex.lower() not in _KEYWORD_LITERALS
        ):
            raise _ParseRefusal(
                f"array element {lex!r} is not a literal",
            )

    def _check_preg(self, node: dict) -> None:
        """First preg_* argument must be a literal pattern without the
        (removed, but explicitly refused) ``e`` modifier."""
        args = node["args"]
        first = args[0] if args else None
        if not first or first.get("kind") != "literal":
            raise _ParseRefusal(
                f"{node['name']} pattern is not a literal",
            )
        lexeme = first["lexeme"]
        body = lexeme[1:-1]
        if len(body) >= 2:
            delim = body[0]
            end = body.rfind(delim)
            if end > 0 and "e" in body[end + 1:]:
                raise _ParseRefusal(
                    f"{node['name']} pattern carries the 'e' modifier",
                )


@dataclass(frozen=True)
class _AnchorParse:
    """Anchor-statement parse result.

    ``assembled`` marks the inline-assembly shape — a top-level
    concatenation whose single call operand is the chain and whose
    other operands are literals or foreign variables (sink assembly
    around the sanitized value). The chain cannot continue past an
    assembly, so the caller goes straight to boundary discipline.
    """

    root: dict
    tokens: list[tuple[str, str]]
    assembled: bool
    other_vars: tuple[str, ...]


def _parse_anchor_expr(expr: str) -> _AnchorParse:
    """Parse an anchor RHS: a pure grammar expression, or the
    inline-assembly concat form ``lit . CALL . lit . $other ...``
    with exactly one call operand."""
    expr = expr.strip()
    if expr.endswith(";"):
        expr = expr[:-1].rstrip()
    tokens = _checked_tokens(expr)
    if ("sym", ".") not in tokens:
        root, toks = _parse_grammar_expr(expr)
        return _AnchorParse(root, toks, assembled=False, other_vars=())

    # Split operands on top-level ``.`` (outside parens/brackets).
    operands: list[list[tuple[str, str]]] = [[]]
    depth = 0
    for tok in tokens:
        kind, lex = tok
        if kind == "sym" and lex in "([":
            depth += 1
        elif kind == "sym" and lex in ")]":
            depth -= 1
        if kind == "sym" and lex == "." and depth == 0:
            operands.append([])
            continue
        operands[-1].append(tok)

    call_operand: list[tuple[str, str]] | None = None
    other_vars: list[str] = []
    for op in operands:
        if not op:
            raise _ParseRefusal("empty concatenation operand")
        if len(op) == 1 and op[0][0] in ("sq", "dq", "num"):
            kind, lex = op[0]
            if kind == "dq" and "$" in lex:
                raise _ParseRefusal(_DQ_DOLLAR_REFUSAL)
            continue
        if len(op) == 1 and op[0][0] == "var":
            other_vars.append(op[0][1].lstrip("$"))
            continue
        if op[0][0] == "ident":
            if call_operand is not None:
                raise _ParseRefusal(
                    "more than one call operand in the assembly "
                    "concatenation",
                )
            call_operand = op
            continue
        raise _ParseRefusal(
            "concatenation operand is outside the assembly grammar",
        )
    if call_operand is None:
        raise _ParseRefusal(
            "no transform call among the concatenation operands",
        )
    parser = _Parser(call_operand, expr)
    root = parser.parse_call()
    if parser.i != len(call_operand):
        raise _ParseRefusal("trailing tokens after the transform call")
    if len(parser.var_seen) != 1:
        raise _ParseRefusal(
            f"call operand carries {len(parser.var_seen)} variable "
            "references — the step grammar requires exactly one data "
            "slot",
        )
    return _AnchorParse(
        root, call_operand, assembled=True, other_vars=tuple(other_vars),
    )


def _parse_grammar_expr(expr: str) -> tuple[dict, list[tuple[str, str]]]:
    """Parse *expr* under the step grammar → (root call node, tokens).

    Raises :class:`_ParseRefusal` with a specific reason otherwise.
    """
    expr = expr.strip()
    if expr.endswith(";"):
        expr = expr[:-1].rstrip()
    tokens = _checked_tokens(expr)
    parser = _Parser(tokens, expr)
    root = parser.parse_call()
    if parser.i != len(tokens):
        raise _ParseRefusal(
            "trailing tokens after the transform call",
        )
    if len(parser.var_seen) != 1:
        raise _ParseRefusal(
            f"expression carries {len(parser.var_seen)} variable "
            "references — the step grammar requires exactly one data "
            "slot",
        )
    return root, tokens


def _flatten_spine(
    root: dict, tokens: list[tuple[str, str]], line: int,
) -> tuple[list[ChainStep], str]:
    """Flatten nested calls innermost-first into ChainSteps.

    Returns (steps, subject variable name). The data spine is the
    unique path from the root call to the single VAR node; each call
    on the spine becomes one step whose before/after lexeme halves
    are re-joined from the ORIGINAL tokens (source-faithful).
    """

    def render_split(
        start: int, end: int, skip: tuple[int, int],
    ) -> tuple[str, str]:
        """Re-join the ORIGINAL lexemes around the data slot.

        Split by token INDEX, never by an in-band sentinel: a
        sentinel byte can legally occur inside a string lexeme (a
        NUL-bearing literal), and splitting on it corrupted the
        template (the slot landed inside the literal).
        """
        before_parts: list[str] = []
        after_parts: list[str] = []
        prev_kind = ""
        for idx in range(start, end):
            if skip[0] <= idx < skip[1]:
                prev_kind = "slot"
                continue
            kind, lex = tokens[idx]
            target = before_parts if idx < skip[0] else after_parts
            if prev_kind and _needs_space(prev_kind, kind):
                target.append(" ")
            target.append(lex)
            prev_kind = kind
        return "".join(before_parts), "".join(after_parts)

    def _needs_space(prev: str, cur: str) -> bool:
        return prev in ("ident", "var", "num") and cur in (
            "ident", "var", "num",
        )

    steps: list[ChainStep] = []
    subject = ""

    def walk(node: dict) -> None:
        nonlocal subject
        spine_child = None
        for arg in node["args"]:
            if arg.get("kind") in ("call", "var"):
                spine_child = arg
                break
        if spine_child is None:  # pragma: no cover — parser guarantees
            raise _ParseRefusal("no data slot in transform call")
        if spine_child["kind"] == "call":
            walk(spine_child)
        else:
            subject = spine_child["name"].lstrip("$")
        before, after = render_split(
            node["tok_start"], node["tok_end"],
            (spine_child["tok_start"], spine_child["tok_end"]),
        )
        steps.append(ChainStep(
            callable_name=node["name"],
            before=before, after=after, line=line,
        ))

    walk(root)
    return steps, subject


# ── chain assembly ───────────────────────────────────────────────────

_ASSIGN_RE = re.compile(r"^\$([A-Za-z_]\w*)\s*=(?![=>])\s*(.+)$", re.DOTALL)


def _mentions_var(text: str, var: str) -> bool:
    return re.search(rf"\${re.escape(var)}\b", text) is not None


def _blank_strings(text: str) -> str:
    """Replace string-literal CONTENTS with spaces (quotes kept) so
    structural regexes cannot match inside literals."""
    out = list(text)
    state = ""
    escaped = False
    for i, ch in enumerate(text):
        if state:
            if escaped:
                escaped = False
                out[i] = " "
                continue
            if ch == "\\":
                escaped = True
                out[i] = " "
                continue
            if ch == state:
                state = ""
                continue
            out[i] = " "
        elif ch in ("'", '"'):
            state = ch
    return "".join(out)


def _divergent_use(old: str, rest: list[_Stmt]) -> _Stmt | None:
    """First later statement still touching an abandoned carrier.

    When the chain's carrier moves (alias or transform into a new
    variable), the OLD variable still holds the pre-move value; any
    later use of it means the sink may see a value the extracted
    chain does not describe — mis-attribution in either direction,
    so the caller refuses.
    """
    for stmt in rest:
        if _mentions_var(stmt.text, old):
            return stmt
    return None


def _body_depth(source: str) -> int:
    """Brace depth of the function body's statements: 1 when the
    source carries the ``function`` header, 0 for a bare body."""
    if re.match(r"\s*(?:[A-Za-z_]\w*\s+)*function\b", source):
        return 1
    return 0


def extract_chain(
    source: str, sanitizer_names: tuple[str, ...],
) -> ChainExtraction | ExtractionRefusal:
    """Extract the pure sanitizer chain anchored on *sanitizer_names*.

    Returns :class:`ChainExtraction` or a reasoned
    :class:`ExtractionRefusal` — never a guess.
    """
    if not source or not source.strip():
        return ExtractionRefusal("no function source available")
    stripped = _strip_comments(source)
    if stripped is None:
        return ExtractionRefusal(
            "heredoc/nowdoc present — the chain lexer does not model it",
        )
    stmts = _statements(stripped)
    depth = _body_depth(stripped)

    name_re = re.compile(
        r"\b(?:" + "|".join(re.escape(n) for n in sanitizer_names)
        + r")\s*\(",
        re.IGNORECASE,
    )
    anchor_idx = next(
        (i for i, s in enumerate(stmts) if name_re.search(s.text)), None,
    )
    if anchor_idx is None:
        return ExtractionRefusal(
            "no application of the named sanitizer(s) found in the "
            "function source",
        )
    anchor = stmts[anchor_idx]
    if anchor.depth != depth:
        return ExtractionRefusal(
            "sanitizer application is nested inside a conditional/"
            "loop block — cannot isolate an unconditional chain",
        )
    m = _ASSIGN_RE.match(anchor.text.rstrip().rstrip(";").strip())
    if m is None:
        return ExtractionRefusal(
            "sanitizer application is not a bare assignment "
            "statement — cannot isolate the chain",
        )
    current = m.group(1)
    try:
        parsed = _parse_anchor_expr(m.group(2))
        steps, subject = _flatten_spine(
            parsed.root, parsed.tokens, anchor.line,
        )
    except _ParseRefusal as exc:
        return ExtractionRefusal(f"anchor statement: {exc}")
    if parsed.assembled and subject in parsed.other_vars:
        return ExtractionRefusal(
            f"subject ${subject} also reaches the assembly "
            "unsanitized — the chain does not govern the sink value",
        )

    allow_call_re = re.compile(
        r"\b(?:" + "|".join(sorted(ALLOWED_STEP_CALLABLES)) + r")\s*\(",
        re.IGNORECASE,
    )
    idx = anchor_idx + 1
    boundary: str | None = None
    if parsed.assembled:
        # The sanitized value is already embedded in a larger string;
        # the chain cannot continue, only the boundary discipline
        # below applies (to the assembled variable).
        boundary = f"inline assembly at line {anchor.line}"
    while boundary is None and idx < len(stmts):
        stmt = stmts[idx]
        text = stmt.text.rstrip().rstrip(";").strip()
        am = _ASSIGN_RE.match(text)
        if (
            am is not None
            and stmt.depth == depth
            and am.group(2).strip() == f"${current}"
        ):
            # Plain alias: the chain's carrier moves to the new
            # variable (zero steps). Not following it would leave
            # later transforms of the alias invisible and attribute
            # a truncated chain — but the ABANDONED carrier must be
            # dead from here on: if it is used or transformed later,
            # the two copies can diverge and the sink may consume the
            # one the chain does not describe.
            if am.group(1) != current:
                used = _divergent_use(current, stmts[idx + 1:])
                if used is not None:
                    return ExtractionRefusal(
                        f"carrier ${current} is aliased to "
                        f"${am.group(1)} at line {stmt.line} but "
                        f"still used at line {used.line} — the "
                        "copies can diverge; cannot bind the chain "
                        "to the sink value"
                    )
            current = am.group(1)
            idx += 1
            continue
        if (
            am is not None
            and stmt.depth == depth
            and _mentions_var(am.group(2), current)
            and allow_call_re.search(am.group(2))
        ):
            # Transform-shaped continuation: an allowlisted callable
            # applied over the chain variable. Anything else that
            # merely MENTIONS the variable (sink assembly, string
            # interpolation into another variable) terminates the
            # chain at the boundary below instead.
            try:
                root, tokens = _parse_grammar_expr(am.group(2))
                more, subj = _flatten_spine(root, tokens, stmt.line)
            except _ParseRefusal as exc:
                return ExtractionRefusal(
                    f"chain step at line {stmt.line}: {exc}",
                )
            if subj != current:
                return ExtractionRefusal(
                    f"chain step at line {stmt.line} transforms "
                    f"${subj}, not the chained ${current}",
                )
            if am.group(1) != current:
                # Transform into a NEW variable: same divergence
                # hazard as the alias branch — the old carrier still
                # holds the pre-transform value.
                used = _divergent_use(current, stmts[idx + 1:])
                if used is not None:
                    return ExtractionRefusal(
                        f"carrier ${current} is transformed into "
                        f"${am.group(1)} at line {stmt.line} but "
                        f"still used at line {used.line} — the "
                        "copies can diverge; cannot bind the chain "
                        "to the sink value"
                    )
            steps.extend(more)
            current = am.group(1)
            idx += 1
            continue
        if _mentions_var(stmt.text, current):
            boundary = f"first use at line {stmt.line}"
            break
        if stmt.depth != depth or _CONTROL_RE.search(stmt.text):
            boundary = f"control flow at line {stmt.line}"
            break
        idx += 1

    # Post-boundary discipline: the chain may END at a use or a
    # branch (that is the normal sink hand-off), but it must not
    # CONTINUE past one — a truncated chain could mint a false
    # insufficiency. From the boundary statement onward, refuse when
    # the chain variable is reassigned (compound assignments
    # included) or fed into another allowlisted transform. Plain
    # uses — sink calls, concatenation/interpolation into OTHER
    # variables — are legitimate sink assembly and terminate the
    # chain cleanly.
    if boundary is not None:
        # UNANCHORED over string-blanked text: an embedded
        # reassignment (`$z = $a = f($a);`) or a braceless control
        # body (`if ($m) $a = ...;`) is still a reassignment — a
        # statement-start anchor let both slip past and hid
        # STRENGTHENING transforms (false insufficiency).
        reassign_re = re.compile(
            rf"\${re.escape(current)}\s*"
            rf"(?:[.+\-*/%]|\?\?|\*\*)?=(?![=>])",
        )
        # Destructuring re-binds too: `list(..., $v, ...) = f();`
        # and `[$a, $v] = f();` assign the chain variable without a
        # direct `$v =` shape. The bracket arm requires a fresh `[`
        # (not preceded by a word char / `$` / `]` / `)`), so an
        # array WRITE keyed by the variable (`$cache[$v] = 1`) stays
        # a plain use, not a re-binding.
        destructure_re = re.compile(
            rf"(?:\blist\s*\([^()]{{0,200}}\${re.escape(current)}\b"
            rf"[^()]{{0,200}}\)|(?<![\w$\])])"
            rf"\[[^\[\]]{{0,200}}\${re.escape(current)}\b"
            rf"[^\[\]]{{0,200}}\])\s*=(?![=>])",
            re.IGNORECASE,
        )
        transform_feed_re = re.compile(
            r"\b(?:" + "|".join(sorted(ALLOWED_STEP_CALLABLES))
            + r")\s*\([^()]*\$" + re.escape(current) + r"\b",
            re.IGNORECASE,
        )
        for later in stmts[idx:]:
            blanked = _blank_strings(later.text)
            if reassign_re.search(blanked) or destructure_re.search(
                blanked,
            ) or transform_feed_re.search(
                blanked,
            ):
                return ExtractionRefusal(
                    f"chain variable ${current} is transformed or "
                    f"reassigned after an intervening boundary "
                    f"({boundary}; line {later.line}) — cannot "
                    "isolate a pure straight-line chain",
                )

    return ChainExtraction(
        steps=tuple(steps), subject_var=subject, final_var=current,
    )

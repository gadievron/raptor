"""Definite-assignment prover for uninitialised-value claims on C code.

Refutes an uninitialised-return / uninitialised-use claim on a C
function by proving, mechanically, that the variable the claim names
is assigned on every path from its declaration to every use in the
function.  The refuting fact is a dataflow tautology over the
macro-expanded source — mechanically true however the claim's prose is
read — which is what qualifies it for proof grade in the refutation
lattice (consumers wire it into ``_PROOF_GATES``; this module only
computes the fact).

Mechanism
---------

1.  **Macro expansion from the target tree's own headers.**  The
    anchor file's ``#include`` closure is resolved inside the target
    tree (the file's directory, ``<target>/include``, then the target
    root) and scanned for ``#define``/``#undef``.  Macro invocations in
    the function source are then expanded with that table:

    - a macro whose full expansion is *statement-shaped* (kernel
      iteration macros such as ``list_for_each_entry``) is spliced in
      one level at a time so its control structure joins the CFG;
    - a macro whose full expansion is *expression-shaped* is reduced
      to a placeholder that preserves exactly what the analysis needs:
      an evaluated read of the claimed variable stays a read,
      occurrences inside ``typeof``/``__typeof__`` operands are
      unevaluated and disappear, and any assignment to / address-of
      the claimed variable inside a macro body refuses the proof.

    Expansion is refused — NO PROOF, never a guess — on: a macro name
    with conflicting definitions anywhere in the closure, a macro that
    is ``#undef``-ed, an expansion containing control-flow escape
    tokens (``goto``/``return``/``break``/``continue``/``switch``/
    labels/``asm``), unsupported preprocessor constructs, or any
    budget/cap overrun.

2.  **CFG walk (definite assignment).**  The expanded function is
    parsed with tree-sitter C; any parse error refuses.  A recursive
    abstract walk tracks the set of unassigned path contexts (each a
    set of branch conditions with polarity) through the structured
    statement forms.  Whole-variable assignment (``v = expr`` with the
    bare identifier on the left) is the only assigning form; writes to
    members/elements never assign the whole variable.  Every evaluated
    occurrence of the variable that is not the bare left-hand side of
    such an assignment is a use; a use reachable with a non-empty
    unassigned context set is a violation.

3.  **Optional Z3 arm.**  When the structural walk finds violations,
    each violating path's branch conditions are checked for joint
    satisfiability (:mod:`core.smt_solver.path_feasibility`).  If every
    such path is infeasible the property still holds.  The arm is
    heavily fenced: it runs only when no macro reduction occurred, no
    keyword-named macro exists in the closure, and only over
    conditions whose every variable is a PARAMETER of ISO-C integer
    type that is never reassigned in the function — locals can be
    indeterminate at the read and function-scope externs can change
    between reads, so joint unsatisfiability over such reads is not a
    refutation — with a single consistent width/signedness profile.
    Without z3, or on any vetting failure, the arm degrades to "no
    proof" — never to a weaker "proof".

Refused constructs (always NO PROOF)
------------------------------------

``goto`` / labels / ``switch`` (fallthrough and missing-default
semantics), ``asm``, ``setjmp``/``longjmp`` family, address-of the
claimed variable (a callee could assign through the pointer),
compound/update assignments to the claimed variable, assignment to the
claimed variable under a short-circuit operator, statement expressions
in the original source, preprocessor directives inside the function,
variable shadowing, VLA-shaped ``typeof`` operands, and any statement
form outside the structured allowlist.

Soundness bound (documented, deliberate)
----------------------------------------

The macro table is textual: it covers definitions the include-closure
scan can read.  Headers the scan cannot resolve (generated headers,
build-system include paths, ``-D`` command-line definitions) can hide
a macro this module then mistakes for a plain function call or
identifier.  Config-conditional definitions cut both ways: a
``#define`` collected from an inactive preprocessor branch expands as
written rather than as built, and the divergent build need not
involve anything invisible OR any conflicting definition — the
config-guarded-macro-with-function-fallback idiom compiles a by-value
CALL (which cannot assign a local) where the text shows an assigning
macro.  That third route is refused mechanically when the fallback is
closure-visible (a macro name that is also a declared function is a
conflict); a fallback living in another translation unit with no
closure-visible declaration remains open.  A benign tree gains
nothing from these gaps — the analysed text is the code as written —
but a crafted tree could plant divergence, so consumers gate the
proof on an operator repo-trust assertion, exactly like the other
witness whose soundness assumes non-adversarial target code.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Caps.  Exceeding any of them refuses the proof.
# ---------------------------------------------------------------------------

_MAX_SOURCE_BYTES = 256 * 1024
_MAX_CLOSURE_FILES = 8192
_MAX_CLOSURE_BYTES = 128 * 1024 * 1024
_MAX_EXPANSIONS = 256
_MAX_SPLICES = 16
_MAX_EXPANSION_TOKENS = 20000
_MAX_TOTAL_TOKENS = 100000
_MAX_EXPANSION_DEPTH = 32
_MAX_CONTEXTS = 64
_MAX_CONTEXT_CONDS = 12
_MAX_LOOP_ITERATIONS = 8

_TABLE_CACHE_MAX = 8


class ProofRefusal(Exception):
    """The prover cannot certify the property — NO PROOF.

    Raised for every unresolvable construct; the conservative failure
    direction is absolute.  ``reason`` names the refusing construct.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class DefiniteAssignmentResult:
    """Outcome of :func:`check_definite_assignment`.

    ``proven`` is True ONLY when every proof obligation discharged;
    everything else — including every refusal — is ``proven=False``
    with the refusing construct named in ``reason``.  ``method`` is
    ``"structural"`` (pure CFG walk) or ``"structural+smt"`` (the Z3
    arm discharged residual paths); provenance fields record what the
    proof rests on so consumers can persist it.
    """

    proven: bool
    variable: str
    reason: str
    method: str = ""
    expanded_macros: tuple[str, ...] = ()
    unresolved_includes: int = 0
    macro_files_scanned: int = 0
    smt_paths_discharged: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "proven": self.proven,
            "variable": self.variable,
            "reason": self.reason,
            "method": self.method,
            "expanded_macros": list(self.expanded_macros),
            "unresolved_includes": self.unresolved_includes,
            "macro_files_scanned": self.macro_files_scanned,
            "smt_paths_discharged": self.smt_paths_discharged,
        }


# ---------------------------------------------------------------------------
# Tokenizer (C preprocessing tokens, comments dropped)
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<comment>/\*.*?\*/|//[^\n]*)
    | (?P<string>L?"(?:\\.|[^"\\\n])*")
    | (?P<char>L?'(?:\\.|[^'\\\n])*')
    | (?P<num>\.?[0-9](?:[0-9a-zA-Z_.]|[eEpP][+\-])*)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<punct><<=|>>=|\.\.\.|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\|
        |\+=|-=|\*=|/=|%=|&=|\^=|\|=|\#\#
        |[-+*/%&|^~!<>=?:;,.(){}\[\]\#\\@])
    """,
    re.VERBOSE | re.DOTALL,
)

# (kind, spelling)
Token = tuple[str, str]


def _tokenize(text: str) -> list[Token]:
    """C-level tokenization; whitespace and comments dropped.

    Any byte the token grammar cannot classify refuses the proof — an
    unrecognised character means the text is not the C this module
    understands.
    """
    out: list[Token] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _TOKEN_RE.match(text, pos)
        if m is None:
            raise ProofRefusal(
                f"untokenizable character {text[pos]!r} at offset {pos}"
            )
        pos = m.end()
        kind = str(m.lastgroup)
        if kind in ("ws", "comment"):
            continue
        out.append((kind, m.group()))
    return out


def _strip_comments(text: str) -> str:
    """Remove /* */ and // comments, preserving string/char literals."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            quote = c
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            out.append(text[i:j])
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(" ")
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" ")
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Include closure + macro table
# ---------------------------------------------------------------------------

_INCLUDE_RE = re.compile(
    r'^[ \t]*#[ \t]*include[ \t]*(<[^>\n]+>|"[^"\n]+")', re.MULTILINE,
)
_DIRECTIVE_RE = re.compile(r"^[ \t]*#[ \t]*(\w+)(.*)$")


@dataclass(frozen=True)
class MacroDef:
    """One ``#define`` collected from the closure."""

    name: str
    params: tuple[str, ...] | None  # None = object-like
    variadic: bool
    body: str
    path: str


@dataclass
class MacroTable:
    """All definitions visible from the anchor file's include closure.

    ``poisoned`` names macros with a definition this module cannot
    parse — any invocation refuses.  A bare ``#undef`` is NOT recorded:
    with exactly one distinct definition in the closure the
    order-dependence it introduces collapses into the documented
    unreadable-header residual (either the definition was active — the
    expansion is faithful — or the name was a plain identifier there,
    which is the same exposure class as a macro living in a header the
    closure cannot read); with conflicting definitions the ambiguity
    rule refuses regardless.
    """

    defs: dict[str, list[MacroDef]] = field(default_factory=dict)
    poisoned: set[str] = field(default_factory=set)
    # Function names declared/defined anywhere in the closure.  A
    # macro whose name is ALSO a closure-visible function is refused
    # as a conflict: the config-guarded-macro-with-function-fallback
    # idiom means the build may compile a by-value CALL (which cannot
    # assign a local) where the text shows an assigning macro — a
    # divergence with no conflicting #define and nothing invisible.
    # Collection is best-effort (tree-sitter parse per file); a missed
    # declaration falls back to the trust-gated residual.
    function_names: set[str] = field(default_factory=set)
    unresolved_includes: tuple[str, ...] = ()
    files_scanned: int = 0


def _join_continuations(text: str) -> list[str]:
    """Physical lines with backslash-newline continuations joined."""
    lines: list[str] = []
    buf: list[str] = []
    for raw in text.split("\n"):
        if raw.endswith("\\"):
            buf.append(raw[:-1])
            continue
        buf.append(raw)
        lines.append(" ".join(buf))
        buf = []
    if buf:
        lines.append(" ".join(buf))
    return lines


def _parse_define(rest: str, path: str) -> MacroDef | None:
    """Parse the text after ``#define``.  None = unparseable (the name,
    if extractable, is poisoned by the caller)."""
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", rest)
    if m is None:
        return None
    name = m.group(1)
    after = rest[m.end():]
    params: tuple[str, ...] | None = None
    variadic = False
    if after.startswith("("):
        depth = 0
        i = 0
        for i, ch in enumerate(after):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
        else:
            return None
        raw_params = after[1:i]
        after = after[i + 1:]
        plist: list[str] = []
        for p in raw_params.split(","):
            p = p.strip()
            if not p:
                continue
            if p == "...":
                variadic = True
            elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p):
                plist.append(p)
            else:
                # GNU named variadics and anything fancier are
                # unsupported — the definition stays in the table as
                # unparseable so an invocation refuses.
                return None
        params = tuple(plist)
    body = _strip_comments(after).strip()
    return MacroDef(
        name=name, params=params, variadic=variadic, body=body, path=path,
    )


def resolve_include_closure(
    target_path: str | Path,
    rel_file: str,
    *,
    max_files: int = _MAX_CLOSURE_FILES,
    max_bytes: int = _MAX_CLOSURE_BYTES,
) -> tuple[list[Path], list[str]]:
    """Resolve *rel_file*'s ``#include`` closure inside the target tree.

    Quoted includes try the including file's directory first, then the
    shared roots (``<target>/include``, ``<target>``); angled includes
    try the shared roots only.  Includes that do not resolve inside the
    tree are returned in the second element (system headers, generated
    headers) — callers decide whether that matters.

    Returns ``(resolved_files, unresolved_include_specs)``.  The anchor
    file itself is the first entry.  Raises :class:`ProofRefusal` on a
    cap overrun.
    """
    root = Path(target_path).resolve()
    anchor = (root / rel_file).resolve()
    if not anchor.is_relative_to(root) or not anchor.is_file():
        raise ProofRefusal(f"anchor file not under target tree: {rel_file}")
    shared_roots = [root / "include", root]

    resolved: list[Path] = []
    unresolved: list[str] = []
    seen: set[Path] = set()
    queue: list[Path] = [anchor]
    total_bytes = 0
    while queue:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        if len(seen) > max_files:
            raise ProofRefusal("include closure exceeds the file cap")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unresolved.append(str(path))
            continue
        total_bytes += len(text)
        if total_bytes > max_bytes:
            raise ProofRefusal("include closure exceeds the byte cap")
        resolved.append(path)
        for m in _INCLUDE_RE.finditer(text):
            spec = m.group(1)
            inner = spec[1:-1]
            if ".." in Path(inner).parts or Path(inner).is_absolute():
                unresolved.append(spec)
                continue
            candidates: list[Path] = []
            if spec.startswith('"'):
                candidates.append(path.parent / inner)
            candidates.extend(r / inner for r in shared_roots)
            for cand in candidates:
                try:
                    cand = cand.resolve()
                except OSError:
                    continue
                if cand.is_relative_to(root) and cand.is_file():
                    if cand not in seen:
                        queue.append(cand)
                    break
            else:
                unresolved.append(spec)
    return resolved, unresolved


def _declared_function_names(text: str, parser: Any) -> set[str]:
    """Function names a file declares or defines (best-effort parse)."""
    names: set[str] = set()
    try:
        tree = parser.parse(text.encode("utf-8", errors="replace"))
    except Exception:
        return names
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "function_declarator":
            d = n.child_by_field_name("declarator")
            if d is not None and d.type == "identifier":
                names.add(_node_text(d))
        stack.extend(n.children)
    return names


def _build_macro_table(target_path: str | Path, rel_file: str) -> MacroTable:
    files, unresolved = resolve_include_closure(target_path, rel_file)
    table = MacroTable(unresolved_includes=tuple(unresolved))
    parser = _c_parser()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        table.files_scanned += 1
        if parser is not None:
            table.function_names |= _declared_function_names(text, parser)
        for line in _join_continuations(text):
            dm = _DIRECTIVE_RE.match(line)
            if dm is None:
                continue
            directive, rest = dm.group(1), dm.group(2)
            if directive == "define":
                parsed = _parse_define(rest, str(path))
                if parsed is None:
                    nm = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", rest)
                    if nm is not None:
                        # Unparseable definition: poison the name so
                        # any invocation refuses.
                        table.poisoned.add(nm.group(1))
                    continue
                table.defs.setdefault(parsed.name, []).append(parsed)
    return table


_TABLE_CACHE: dict[tuple[str, str], MacroTable] = {}


def _macro_table_for(
    target_path: str | Path | None, rel_file: str | None,
) -> MacroTable:
    if not target_path or not rel_file:
        return MacroTable()
    key = (str(target_path), rel_file)
    cached = _TABLE_CACHE.get(key)
    if cached is not None:
        return cached
    table = _build_macro_table(target_path, rel_file)
    if len(_TABLE_CACHE) >= _TABLE_CACHE_MAX:
        _TABLE_CACHE.pop(next(iter(_TABLE_CACHE)))
    _TABLE_CACHE[key] = table
    return table


# C keywords.  A macro NAMED after a keyword (the kernel's
# config-gated branch-profiling ``#define if(cond, ...)`` is the
# canonical shape) is never expanded: an unconditionally active
# keyword rewrite would break every use in the tree, so such
# definitions are conditional instrumentation wrappers.  The walk is
# NOT inherently polarity-blind: its constant-condition folding
# believes literal truth values, and the SMT arm believes condition
# polarity outright — so the presence of any keyword-named definition
# in the closure disables BOTH (see :func:`check_definite_assignment`
# and :class:`_Walker`), leaving the fully both-branches-conservative
# core.  An ACTIVE hostile keyword rewrite that hides control flow
# (rather than branch semantics) is part of the documented
# unreadable/config-conditional residual the trust gate covers.
_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default",
    "do", "double", "else", "enum", "extern", "float", "for", "goto",
    "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch",
    "typedef", "union", "unsigned", "void", "volatile", "while",
    "_Bool", "_Static_assert", "_Alignof", "_Alignas", "_Generic",
    "_Noreturn", "_Thread_local", "_Atomic",
})


def _normalized_body(d: MacroDef) -> tuple:
    try:
        toks = _tokenize(d.body)
    except ProofRefusal:
        return ("<untokenizable>", d.body)
    return (d.params, d.variadic, tuple(s for _k, s in toks))


def _lookup_macro(table: MacroTable, name: str) -> MacroDef | None:
    """Unique usable definition of *name*, or None when the name is not
    a known macro.  Conflicting or poisoned names refuse the proof —
    the expansion the build would use is not decidable from text."""
    if name in _C_KEYWORDS:
        return None
    defs = table.defs.get(name)
    if name in table.poisoned:
        raise ProofRefusal(
            f"macro {name} has an unparseable definition in the closure"
        )
    if not defs:
        return None
    if name in table.function_names:
        raise ProofRefusal(
            f"macro {name} is also declared as a function in the "
            f"closure — a config-conditional definition with a "
            f"function fallback diverges by build"
        )
    first = _normalized_body(defs[0])
    for other in defs[1:]:
        if _normalized_body(other) != first:
            raise ProofRefusal(
                f"macro {name} has conflicting definitions in the closure"
            )
    return defs[0]


# ---------------------------------------------------------------------------
# Macro expansion
# ---------------------------------------------------------------------------


class _Budget:
    def __init__(self) -> None:
        self.expansions = 0
        self.splices = 0

    def spend_expansion(self) -> None:
        self.expansions += 1
        if self.expansions > _MAX_EXPANSIONS:
            raise ProofRefusal("macro expansion budget exceeded")

    def spend_splice(self) -> None:
        self.splices += 1
        if self.splices > _MAX_SPLICES:
            raise ProofRefusal("macro splice budget exceeded")


def _collect_args(
    tokens: list[Token], open_idx: int,
) -> tuple[list[list[Token]], int]:
    """Parse a balanced argument list starting at ``tokens[open_idx] ==
    '('``.  Returns (args, index_after_close)."""
    assert tokens[open_idx][1] == "("
    args: list[list[Token]] = []
    cur: list[Token] = []
    depth = 0
    i = open_idx
    while i < len(tokens):
        _k, s = tokens[i]
        if s in "([{":
            depth += 1
            if depth > 1:
                cur.append(tokens[i])
        elif s in ")]}":
            depth -= 1
            if depth == 0:
                if s != ")":
                    raise ProofRefusal(
                        "mismatched bracket in macro argument list"
                    )
                if cur or args:
                    args.append(cur)
                return args, i + 1
            cur.append(tokens[i])
        elif s == "," and depth == 1:
            args.append(cur)
            cur = []
        elif depth >= 1:
            cur.append(tokens[i])
        i += 1
    raise ProofRefusal("unbalanced macro argument list")


def _stringify(arg: list[Token]) -> Token:
    text = " ".join(s for _k, s in arg)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return ("string", f'"{text}"')


def _paste(left: Token, right: Token) -> Token:
    merged = left[1] + right[1]
    toks = _tokenize(merged)
    if len(toks) != 1:
        raise ProofRefusal(f"token paste produced non-token {merged!r}")
    return toks[0]


def _substitute(
    d: MacroDef,
    args: list[list[Token]] | None,
    *,
    expand_arg: Any,
) -> list[Token]:
    """Substitute *args* into *d*'s body.

    ``expand_arg`` maps an argument token list to its (possibly
    expanded) replacement for ordinary parameter positions; ``#`` and
    ``##`` positions always take the raw argument, per the standard.
    """
    body = _tokenize(d.body)
    params = list(d.params or ())
    argmap: dict[str, list[Token]] = {}
    if d.params is not None:
        args = args if args is not None else []
        fixed = args[: len(params)]
        if len(fixed) < len(params):
            # Fewer arguments than parameters: empty-token arguments
            # are only valid when they are genuinely empty positions.
            if len(args) == 0 and len(params) == 1:
                fixed = [[]]
            else:
                raise ProofRefusal(
                    f"macro {d.name} invoked with too few arguments"
                )
        for p, a in zip(params, fixed):
            argmap[p] = a
        if d.variadic:
            rest = args[len(params):]
            va: list[Token] = []
            for j, a in enumerate(rest):
                if j:
                    va.append(("punct", ","))
                va.extend(a)
            argmap["__VA_ARGS__"] = va
        elif len(args) > len(params):
            raise ProofRefusal(
                f"macro {d.name} invoked with too many arguments"
            )

    out: list[Token] = []
    i = 0
    n = len(body)
    while i < n:
        kind, s = body[i]
        # Stringify: # param
        if s == "#" and i + 1 < n and body[i + 1][1] in argmap:
            out.append(_stringify(argmap[body[i + 1][1]]))
            i += 2
            continue
        if s == "#":
            raise ProofRefusal(
                f"unsupported # operator use in macro {d.name}"
            )
        # Paste: X ## Y (with the GNU , ## __VA_ARGS__ comma swallow)
        if i + 1 < n and body[i + 1][1] == "##":
            if i + 2 >= n:
                raise ProofRefusal(f"dangling ## in macro {d.name}")
            right_tok = body[i + 2]
            if s == "," and right_tok[1] == "__VA_ARGS__":
                va = argmap.get("__VA_ARGS__", [])
                if va:
                    out.append(body[i])
                    out.extend(va)
                i += 3
                continue
            left_list = argmap[s] if s in argmap else [body[i]]
            right_list = (
                argmap[right_tok[1]]
                if right_tok[1] in argmap else [right_tok]
            )
            if not left_list or not right_list:
                pasted = left_list + right_list
                out.extend(pasted)
                i += 3
                continue
            out.extend(left_list[:-1])
            pasted_tok = _paste(left_list[-1], right_list[0])
            out.append(pasted_tok)
            out.extend(right_list[1:])
            i += 3
            continue
        if kind == "ident" and s in argmap:
            out.extend(expand_arg(argmap[s]))
            i += 1
            continue
        out.append(body[i])
        i += 1
    return out


def _expand_fully(
    tokens: list[Token],
    table: MacroTable,
    budget: _Budget,
    active: frozenset[str] = frozenset(),
    depth: int = 0,
) -> list[Token]:
    """Full recursive expansion of *tokens* (classification input).

    A self-referential macro (its own name reappearing under
    expansion) refuses — the fixpoint the compiler would reach is not
    modelled here.
    """
    if depth > _MAX_EXPANSION_DEPTH:
        raise ProofRefusal("macro expansion depth exceeded")
    out: list[Token] = []
    i = 0
    while i < len(tokens):
        kind, s = tokens[i]
        if kind != "ident":
            out.append(tokens[i])
            i += 1
            continue
        if s in active and s in table.defs:
            raise ProofRefusal(f"recursive macro {s}")
        d = _lookup_macro(table, s)
        if d is None:
            out.append(tokens[i])
            i += 1
            continue
        if d.params is not None:
            if i + 1 >= len(tokens) or tokens[i + 1][1] != "(":
                # Function-like macro name without an argument list is
                # a plain identifier (the C behaviour).
                out.append(tokens[i])
                i += 1
                continue
            args, after = _collect_args(tokens, i + 1)
            budget.spend_expansion()
            sub = _substitute(
                d, args,
                expand_arg=lambda a: _expand_fully(
                    a, table, budget, active | {s}, depth + 1,
                ),
            )
            expanded = _expand_fully(
                sub, table, budget, active | {s}, depth + 1,
            )
            out.extend(expanded)
            i = after
        else:
            budget.spend_expansion()
            sub = _tokenize(d.body)
            expanded = _expand_fully(
                sub, table, budget, active | {s}, depth + 1,
            )
            out.extend(expanded)
            i += 1
        if len(out) > _MAX_EXPANSION_TOKENS:
            raise ProofRefusal("macro expansion token cap exceeded")
    return out


# ---------------------------------------------------------------------------
# Expansion classification and reduction
# ---------------------------------------------------------------------------

# Tokens that can transfer control out of (or into) an expansion in a
# way the reduction cannot model.  ``if``/``for``/``while``/``do`` are
# deliberately NOT here: local control flow inside a GNU statement
# expression cannot skip the enclosing statement.
_CTRL_ESCAPE = frozenset({
    "goto", "return", "break", "continue", "switch", "case", "default",
    "asm", "__asm", "__asm__", "setjmp", "_setjmp", "sigsetjmp",
    "longjmp", "siglongjmp", "_Pragma", "__label__",
})

_STMT_KEYWORDS = frozenset({"if", "for", "while", "do"})

_TYPEOF_NAMES = frozenset({"typeof", "__typeof", "__typeof__"})

_ASSIGN_OPS = frozenset({
    "=", "+=", "-=", "*=", "/=", "%=", "&=", "^=", "|=", "<<=", ">>=",
})


def _stmt_expr_spans(tokens: list[Token]) -> list[tuple[int, int]]:
    """Index spans (inclusive open, inclusive close) of GNU ``({ ... })``
    statement-expression groups."""
    spans: list[tuple[int, int]] = []
    stack: list[int] = []
    depth_stack: list[int] = []
    depth = 0
    for i, (_k, s) in enumerate(tokens):
        if s == "(":
            depth += 1
            if i + 1 < len(tokens) and tokens[i + 1][1] == "{":
                stack.append(i)
                depth_stack.append(depth)
        elif s == ")":
            if depth_stack and depth == depth_stack[-1]:
                spans.append((stack.pop(), i))
                depth_stack.pop()
            depth -= 1
    return spans


def _inside(idx: int, spans: list[tuple[int, int]]) -> bool:
    return any(a <= idx <= b for a, b in spans)


def _typeof_spans(tokens: list[Token]) -> list[tuple[int, int]]:
    """Spans covered by ``typeof(...)`` operands (unevaluated)."""
    spans: list[tuple[int, int]] = []
    i = 0
    while i < len(tokens):
        kind, s = tokens[i]
        if kind == "ident" and s in _TYPEOF_NAMES:
            j = i + 1
            if j < len(tokens) and tokens[j][1] == "(":
                depth = 0
                k = j
                while k < len(tokens):
                    if tokens[k][1] == "(":
                        depth += 1
                    elif tokens[k][1] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    k += 1
                if depth != 0:
                    raise ProofRefusal("unbalanced typeof operand")
                for m in range(j, k + 1):
                    if tokens[m][1] == "[":
                        raise ProofRefusal(
                            "array declarator inside typeof operand "
                            "(possible VLA — evaluated)"
                        )
                spans.append((i, k))
                i = k + 1
                continue
        i += 1
    return spans


def _scan_expansion_for_variable(
    tokens: list[Token], variable: str,
) -> int:
    """Count evaluated reads of *variable* in an expansion; refuse on
    any occurrence the reduction cannot preserve faithfully."""
    for _k, s in tokens:
        if s in _CTRL_ESCAPE:
            raise ProofRefusal(
                f"macro expansion contains control-escape token {s!r}"
            )
    # Label shape: IDENT ':' at a statement boundary.
    for i, (kind, s) in enumerate(tokens):
        if (
            kind == "ident"
            and i + 1 < len(tokens)
            and tokens[i + 1][1] == ":"
            and (i == 0 or tokens[i - 1][1] in (";", "{", "}"))
        ):
            raise ProofRefusal("macro expansion contains a label")
    skip = _typeof_spans(tokens)
    reads = 0
    for i, (kind, s) in enumerate(tokens):
        if kind != "ident" or s != variable or _inside(i, skip):
            continue
        nxt = tokens[i + 1][1] if i + 1 < len(tokens) else ""
        prv = tokens[i - 1][1] if i > 0 else ""
        prv2 = tokens[i - 2][1] if i > 1 else ""
        if nxt in _ASSIGN_OPS or nxt in ("++", "--") or prv in ("++", "--"):
            raise ProofRefusal(
                f"macro expansion modifies claimed variable {variable}"
            )
        if prv == "&" and nxt not in ("->", ".", "["):
            unary = prv2 in (
                "", "(", "[", ",", ";", "{", "}", "=", "return",
            ) or prv2 in _ASSIGN_OPS
            if unary:
                raise ProofRefusal(
                    f"macro expansion takes the address of {variable}"
                )
        reads += 1
    return reads


def _is_statement_shaped(tokens: list[Token]) -> bool:
    """True when a full expansion is a statement (or statement prefix,
    e.g. a ``for`` header) rather than an expression."""
    spans = _stmt_expr_spans(tokens)
    depth = 0
    for i, (kind, s) in enumerate(tokens):
        if _inside(i, spans):
            if s == "(":
                depth += 1
            elif s == ")":
                depth -= 1
            continue
        if s in "([":
            depth += 1
        elif s in ")]":
            depth -= 1
        elif depth == 0:
            if s in (";", "{", "}"):
                return True
            if kind == "ident" and s in _STMT_KEYWORDS:
                return True
    return False


def _reduce_expression_expansion(
    tokens: list[Token], variable: str, serial: int,
) -> list[Token]:
    """Placeholder for an expression-shaped expansion: preserves the
    evaluated reads of the claimed variable and nothing else.

    The placeholder value is an OPAQUE identifier, never a constant:
    a constant would let the walker's polarity-sensitive folding
    const-prune a macro-guarded branch away (``if (GUARD(x)) use(v)``
    reducing to ``if ((0)) …`` erases a real use), turning an unknown
    guard into a false proof.  An unknown identifier keeps the branch
    UNKNOWN — both arms walked.  ``serial`` makes each reduction's
    identifier distinct so two different macros can never mint a
    correlated-condition pair the source does not have.
    """
    opaque = f"__defassign_opaque_{serial}"
    reads = _scan_expansion_for_variable(tokens, variable)
    if reads:
        return [
            ("punct", "("), ("ident", opaque), ("punct", ","),
            ("punct", "("), ("ident", variable), ("punct", ")"),
            ("punct", ")"),
        ]
    return [("punct", "("), ("ident", opaque), ("punct", ")")]


@dataclass
class _ProcessedSource:
    tokens: list[Token]
    expanded_macros: list[str]
    reductions: int
    splices: int

    @property
    def text(self) -> str:
        return " ".join(s for _k, s in self.tokens)


def _process_function_tokens(
    tokens: list[Token],
    table: MacroTable,
    variable: str,
) -> _ProcessedSource:
    """Expand/reduce every macro invocation in the function tokens."""
    budget = _Budget()
    expanded: list[str] = []
    reductions = 0
    rounds = 0
    while True:
        rounds += 1
        if rounds > _MAX_EXPANSIONS:
            raise ProofRefusal("macro processing round cap exceeded")
        if len(tokens) > _MAX_TOTAL_TOKENS:
            raise ProofRefusal("processed source token cap exceeded")
        hit = None
        for i, (kind, s) in enumerate(tokens):
            if kind != "ident":
                continue
            d = _lookup_macro(table, s)
            if d is None:
                continue
            if d.params is not None and (
                i + 1 >= len(tokens) or tokens[i + 1][1] != "("
            ):
                continue
            hit = (i, d)
            break
        if hit is None:
            break
        i, d = hit
        if d.params is not None:
            args, after = _collect_args(tokens, i + 1)
        else:
            args, after = None, i + 1
        full = _expand_fully(
            (
                tokens[i:after]
            ),
            table, budget,
        )
        expanded.append(d.name)
        if _is_statement_shaped(full):
            budget.spend_splice()
            one_level = _substitute(d, args, expand_arg=lambda a: a)
            tokens = tokens[:i] + one_level + tokens[after:]
        else:
            reductions += 1
            placeholder = _reduce_expression_expansion(
                full, variable, reductions,
            )
            tokens = tokens[:i] + placeholder + tokens[after:]
    return _ProcessedSource(
        tokens=tokens,
        expanded_macros=expanded,
        reductions=reductions,
        splices=budget.splices,
    )


# ---------------------------------------------------------------------------
# tree-sitter plumbing
# ---------------------------------------------------------------------------


def _c_parser() -> Any | None:
    try:
        from core.inventory.extractors import _ts_parser_for
        return _ts_parser_for("c")
    except Exception:
        return None


def _walk_nodes(node: Any) -> Iterator[Any]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _node_text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


def _parse_function(text: str) -> Any:
    parser = _c_parser()
    if parser is None:
        raise ProofRefusal("tree-sitter C grammar unavailable")
    tree = parser.parse(text.encode("utf-8"))
    root = tree.root_node
    for n in _walk_nodes(root):
        if n.type == "ERROR" or n.is_missing:
            raise ProofRefusal(
                "expanded source does not parse as C "
                f"(near {_node_text(n)[:40]!r})"
            )
    fns = [n for n in root.children if n.type == "function_definition"]
    if len(fns) != 1:
        raise ProofRefusal(
            f"expected exactly one function definition, found {len(fns)}"
        )
    return fns[0]


# ---------------------------------------------------------------------------
# Declaration discovery
# ---------------------------------------------------------------------------


def _declarator_name(node: Any) -> Any | None:
    """The identifier a declarator binds, or None."""
    n = node
    while n is not None:
        if n.type == "identifier":
            return n
        if n.type in (
            "pointer_declarator", "array_declarator",
            "function_declarator", "parenthesized_declarator",
            "init_declarator", "attributed_declarator",
        ):
            n = n.child_by_field_name("declarator") or (
                n.named_children[0] if n.named_children else None
            )
            continue
        return None
    return None


@dataclass
class _VarDecl:
    node: Any
    is_static: bool
    is_parameter: bool


def _find_variable_decls(fn_node: Any, variable: str) -> list[_VarDecl]:
    decls: list[_VarDecl] = []
    declarator = fn_node.child_by_field_name("declarator")
    if declarator is not None:
        for n in _walk_nodes(declarator):
            if n.type == "parameter_declaration":
                name = _declarator_name(
                    n.child_by_field_name("declarator") or n,
                )
                if name is not None and _node_text(name) == variable:
                    decls.append(_VarDecl(
                        node=n, is_static=False, is_parameter=True,
                    ))
    body = fn_node.child_by_field_name("body")
    if body is None:
        raise ProofRefusal("function has no body")
    for n in _walk_nodes(body):
        if n.type != "declaration":
            continue
        storage = [
            _node_text(c) for c in n.children
            if c.type == "storage_class_specifier"
        ]
        if "extern" in storage:
            for c in n.named_children:
                nm = _declarator_name(c)
                if nm is not None and _node_text(nm) == variable:
                    raise ProofRefusal(
                        f"{variable} has extern storage in the function"
                    )
            continue
        for c in n.named_children:
            if c.type in ("init_declarator",):
                nm = _declarator_name(c)
                if nm is not None and _node_text(nm) == variable:
                    decls.append(_VarDecl(
                        node=c,
                        is_static="static" in storage,
                        is_parameter=False,
                    ))
            elif c.type in (
                "identifier", "pointer_declarator", "array_declarator",
                "parenthesized_declarator", "attributed_declarator",
            ):
                nm = _declarator_name(c)
                if nm is not None and _node_text(nm) == variable:
                    decls.append(_VarDecl(
                        node=c,
                        is_static="static" in storage,
                        is_parameter=False,
                    ))
    return decls


# ---------------------------------------------------------------------------
# Definite-assignment walk
# ---------------------------------------------------------------------------

# A path context: the branch conditions (text, negated) under which the
# variable can reach a point unassigned.
_Cond = tuple[str, bool]
_Context = frozenset[_Cond]
_State = frozenset  # of _Context

_EMPTY_STATE: _State = frozenset()
_ENTRY_STATE: _State = frozenset({frozenset()})

_SETJMP_FAMILY = frozenset({
    "setjmp", "_setjmp", "sigsetjmp", "longjmp", "siglongjmp",
})

_ALLOWED_STATEMENTS = frozenset({
    "compound_statement", "expression_statement", "declaration",
    "if_statement", "for_statement", "while_statement", "do_statement",
    "return_statement", "break_statement", "continue_statement",
    "comment", "else_clause",
})


@dataclass
class _Violation:
    contexts: _State
    use_text: str


class _LoopFrame:
    def __init__(self) -> None:
        self.break_pool: set[_Context] = set()
        self.continue_pool: set[_Context] = set()


class _Walker:
    """Structured recursive definite-assignment walk.

    The state is the set of path contexts under which the claimed
    variable is still unassigned; the empty set means "assigned on
    every path reaching here".  Anything outside the structured
    statement allowlist refuses.
    """

    def __init__(self, variable: str, *, const_prune: bool = True) -> None:
        self.variable = variable
        # Constant-condition folding (``while (1)`` has no false exit)
        # is the one polarity-SENSITIVE step of the walk: it believes
        # the literal's truth value.  Callers disable it when the
        # closure defines a keyword-named macro (an active ``#define
        # if`` rewrite could invert or kill a branch), making the walk
        # fully both-branches conservative in that regime.
        self.const_prune = const_prune
        self.violations: list[_Violation] = []
        self.loop_stack: list[_LoopFrame] = []
        self.decl_seen = False

    # -- expression handling ------------------------------------------------

    def _refuse_expr_constructs(self, node: Any) -> None:
        for n in _walk_nodes(node):
            if n.type == "compound_statement":
                raise ProofRefusal(
                    "statement expression in expression position"
                )
            if n.type == "function_definition":
                raise ProofRefusal("nested function definition")
            if n.type == "identifier" and _node_text(n) in _SETJMP_FAMILY:
                raise ProofRefusal(
                    f"{_node_text(n)} reachable in the function"
                )
            if "asm" in n.type:
                raise ProofRefusal("asm construct in expression")

    def _var_occurrences(self, node: Any) -> list[Any]:
        return [
            n for n in _walk_nodes(node)
            if n.type == "identifier" and _node_text(n) == self.variable
        ]

    def _assignment_for(self, occ: Any) -> Any | None:
        """The simple assignment ``var = ...`` this occurrence is the
        left-hand side of, or None."""
        parent = occ.parent
        if (
            parent is not None
            and parent.type == "assignment_expression"
            and parent.child_by_field_name("left") == occ
        ):
            op = parent.child_by_field_name("operator")
            op_text = _node_text(op) if op is not None else "="
            if op_text != "=":
                raise ProofRefusal(
                    f"compound assignment to {self.variable}"
                )
            return parent
        return None

    def _check_occurrence_shapes(self, occ: Any) -> None:
        parent = occ.parent
        if parent is None:
            return
        if parent.type == "pointer_expression":
            # tree-sitter-c uses pointer_expression for both & and *;
            # only the address-of form is fatal.
            op = parent.child_by_field_name("operator")
            if op is not None and _node_text(op) == "&":
                raise ProofRefusal(
                    f"address of {self.variable} is taken"
                )

    @staticmethod
    def _has_nonexecuting_ancestor(node: Any, stop: Any) -> bool:
        """True when *node* sits under an ancestor (up to and including
        *stop*) that may skip or never evaluate it: short-circuit
        operators, the conditional operator, or an unevaluated-operand
        construct such as ``sizeof``."""
        n = node.parent
        while n is not None:
            if n.type == "conditional_expression":
                return True
            if n.type in (
                "sizeof_expression", "alignof_expression",
                "offsetof_expression", "generic_expression",
            ):
                return True
            if n.type == "binary_expression":
                op = n.child_by_field_name("operator")
                if op is not None and _node_text(op) in ("&&", "||"):
                    return True
            if n == stop:
                break
            n = n.parent
        return False

    def _scan_expression(self, node: Any, state: _State) -> _State:
        """Scan a full expression; record violations for reads of the
        claimed variable under a non-empty unassigned state; return the
        state after the expression (empty when it assigns)."""
        if node is None:
            return state
        if node.type == "parenthesized_expression":
            inner = [
                c for c in node.named_children if c.type != "comment"
            ]
            if len(inner) == 1:
                return self._scan_expression(inner[0], state)
        self._refuse_expr_constructs(node)
        # Standalone read-modify-write forms (loop counters): the read
        # precedes the write deterministically when the form IS the
        # whole expression.  Nested forms refuse below.
        if node.type == "update_expression":
            arg = node.child_by_field_name("argument")
            if arg is not None and arg.type == "identifier" \
                    and _node_text(arg) == self.variable:
                if state:
                    self.violations.append(_Violation(
                        contexts=state, use_text=_node_text(node)[:80],
                    ))
                return _EMPTY_STATE
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            op = node.child_by_field_name("operator")
            if (
                left is not None and left.type == "identifier"
                and _node_text(left) == self.variable
                and op is not None and _node_text(op) != "="
            ):
                rhs = node.child_by_field_name("right")
                rhs_occs = self._var_occurrences(rhs) if rhs else []
                for other in rhs_occs:
                    self._check_occurrence_shapes(other)
                if state:
                    self.violations.append(_Violation(
                        contexts=state, use_text=_node_text(node)[:80],
                    ))
                return _EMPTY_STATE
        occs = self._var_occurrences(node)
        if not occs:
            return state
        assignments = []
        for occ in occs:
            self._check_occurrence_shapes(occ)
            parent = occ.parent
            if parent is not None and parent.type == "update_expression":
                raise ProofRefusal(
                    f"update expression on {self.variable} nested in a "
                    f"larger expression"
                )
            a = self._assignment_for(occ)
            if a is not None:
                assignments.append((occ, a))
        if len(assignments) > 1:
            raise ProofRefusal(
                f"multiple assignments to {self.variable} in one "
                f"expression"
            )
        if assignments:
            occ, assign = assignments[0]
            if self._has_nonexecuting_ancestor(assign, node):
                raise ProofRefusal(
                    f"assignment to {self.variable} under a "
                    f"short-circuit or unevaluated operator"
                )
            rhs = assign.child_by_field_name("right")
            for other in occs:
                if other == occ:
                    continue
                inside_rhs = False
                p = other
                while p is not None:
                    if p == rhs:
                        inside_rhs = True
                        break
                    p = p.parent
                if not inside_rhs:
                    raise ProofRefusal(
                        f"read and write of {self.variable} in one "
                        f"expression with unspecified order"
                    )
                if state:
                    self.violations.append(_Violation(
                        contexts=state, use_text=_node_text(other)[:80],
                    ))
            return _EMPTY_STATE
        # Reads only.
        if state:
            self.violations.append(_Violation(
                contexts=state, use_text=_node_text(node)[:80],
            ))
        return state

    # -- condition push -----------------------------------------------------

    @staticmethod
    def _cond_text(node: Any) -> str:
        text = _node_text(node).strip()
        while text.startswith("(") and text.endswith(")"):
            inner = text[1:-1]
            depth = 0
            ok = True
            for ch in inner:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth < 0:
                        ok = False
                        break
            if not ok or depth != 0:
                break
            text = inner.strip()
        return text

    @classmethod
    def _const_value(cls, cond: Any) -> int | None:
        """Integer value of a constant condition (``while (1)``), or
        None when the condition is not a bare literal."""
        text = cls._cond_text(cond)
        try:
            return int(text, 0)
        except ValueError:
            return None

    def _push(
        self, state: _State, cond: Any | None, negated: bool,
    ) -> _State:
        if not state:
            return state
        if cond is None:
            return state
        if self.const_prune:
            konst = self._const_value(cond)
            if konst is not None:
                taken = (konst != 0) if not negated else (konst == 0)
                return state if taken else _EMPTY_STATE
        text = self._cond_text(cond)
        out = set()
        for ctx in state:
            new = frozenset(ctx | {(text, negated)})
            if len(new) > _MAX_CONTEXT_CONDS:
                raise ProofRefusal("path context condition cap exceeded")
            out.add(new)
        if len(out) > _MAX_CONTEXTS:
            raise ProofRefusal("path context cap exceeded")
        return frozenset(out)

    # -- statements ----------------------------------------------------------

    def walk(self, node: Any, state: _State) -> _State:
        t = node.type
        if t not in _ALLOWED_STATEMENTS:
            raise ProofRefusal(f"unsupported statement form: {t}")
        if t == "comment":
            return state
        if t == "compound_statement":
            for child in node.named_children:
                state = self.walk(child, state)
            return state
        if t == "declaration":
            return self._walk_declaration(node, state)
        if t == "expression_statement":
            for child in node.named_children:
                if child.type == "comment":
                    continue
                state = self._scan_expression(child, state)
            return state
        if t == "return_statement":
            for child in node.named_children:
                if child.type == "comment":
                    continue
                self._scan_expression(child, state)
            return _EMPTY_STATE
        if t == "if_statement":
            return self._walk_if(node, state)
        if t == "while_statement":
            return self._walk_while(node, state)
        if t == "do_statement":
            return self._walk_do(node, state)
        if t == "for_statement":
            return self._walk_for(node, state)
        if t == "break_statement":
            if not self.loop_stack:
                raise ProofRefusal("break outside a loop")
            self.loop_stack[-1].break_pool.update(state)
            return _EMPTY_STATE
        if t == "continue_statement":
            if not self.loop_stack:
                raise ProofRefusal("continue outside a loop")
            self.loop_stack[-1].continue_pool.update(state)
            return _EMPTY_STATE
        if t == "else_clause":
            for child in node.named_children:
                if child.type == "comment":
                    continue
                return self.walk(child, state)
            return state
        raise ProofRefusal(f"unsupported statement form: {t}")

    def _walk_declaration(self, node: Any, state: _State) -> _State:
        for c in node.named_children:
            if c.type == "init_declarator":
                nm = _declarator_name(c)
                value = c.child_by_field_name("value")
                is_var = nm is not None and _node_text(nm) == self.variable
                # Declarator expressions evaluate at the declaration
                # even WITH an initializer (pointer-to-VLA:
                # ``int (*rows)[x] = init;`` reads x) — the non-init
                # branch scans them but this branch only scanned the
                # initializer, so such a read was invisible and the
                # prover could certify "assigned before every use"
                # over an uninitialized size read (missed reads are
                # the unsound direction for this prover).
                decl = c.child_by_field_name("declarator")
                if decl is not None:
                    for n in _walk_nodes(decl):
                        if (
                            n.type == "identifier"
                            and (nm is None or n.id != nm.id)
                            and _node_text(n) == self.variable
                            and state
                        ):
                            self.violations.append(_Violation(
                                contexts=state,
                                use_text=_node_text(c)[:80],
                            ))
                if is_var:
                    if self.decl_seen:
                        raise ProofRefusal(
                            f"{self.variable} declared more than once"
                        )
                    if value is not None and self._var_occurrences(value):
                        # C scoping puts the declarator in scope inside
                        # its own initializer.
                        raise ProofRefusal(
                            f"initializer of {self.variable} reads "
                            f"{self.variable} itself"
                        )
                    self.decl_seen = True
                    state = _EMPTY_STATE
                    continue
                if value is not None:
                    state = self._scan_expression(value, state)
            elif c.type in (
                "identifier", "pointer_declarator", "array_declarator",
                "parenthesized_declarator", "attributed_declarator",
            ):
                nm = _declarator_name(c)
                if nm is not None and _node_text(nm) == self.variable:
                    if self.decl_seen:
                        raise ProofRefusal(
                            f"{self.variable} declared more than once"
                        )
                    self.decl_seen = True
                    state = _ENTRY_STATE
                    continue
                # Array sizes and other declarator expressions can read
                # the claimed variable.
                for n in _walk_nodes(c):
                    if (
                        n.type == "identifier"
                        and _node_text(n) == self.variable
                        and state
                    ):
                        self.violations.append(_Violation(
                            contexts=state,
                            use_text=_node_text(c)[:80],
                        ))
        return state

    def _walk_if(self, node: Any, state: _State) -> _State:
        cond = node.child_by_field_name("condition")
        state = self._scan_expression(cond, state)
        s_then = self._push(state, cond, False)
        s_else = self._push(state, cond, True)
        consequence = node.child_by_field_name("consequence")
        if consequence is not None:
            s_then = self.walk(consequence, s_then)
        alternative = node.child_by_field_name("alternative")
        if alternative is not None:
            s_else = self.walk(alternative, s_else)
        return frozenset(s_then | s_else)

    def _loop_fixpoint(
        self,
        state: _State,
        cond: Any | None,
        body: Any,
        *,
        update: Any | None = None,
        body_first: bool = False,
    ) -> _State:
        frame = _LoopFrame()
        self.loop_stack.append(frame)
        try:
            if body_first:
                # do { body } while (cond)
                seen: _State = state  # states at body entry
                exit_pool: set[_Context] = set()
                for _ in range(_MAX_LOOP_ITERATIONS):
                    frame.continue_pool = set()
                    s_body = self.walk(body, seen)
                    s_body = frozenset(
                        s_body | frozenset(frame.continue_pool),
                    )
                    s_cond = self._scan_expression(cond, s_body)
                    exit_pool.update(self._push(s_cond, cond, True))
                    s_next = self._push(s_cond, cond, False)
                    new_seen = frozenset(seen | s_next)
                    if len(new_seen) > _MAX_CONTEXTS:
                        raise ProofRefusal("path context cap exceeded")
                    if new_seen == seen:
                        break
                    seen = new_seen
                else:
                    raise ProofRefusal("loop analysis did not converge")
                return frozenset(
                    frozenset(exit_pool) | frozenset(frame.break_pool),
                )
            # while (cond) body  /  for (; cond; update) body
            seen = state  # states at condition evaluation
            for _ in range(_MAX_LOOP_ITERATIONS):
                s_cond = (
                    self._scan_expression(cond, seen)
                    if cond is not None else seen
                )
                s_in = self._push(s_cond, cond, False)
                frame.continue_pool = set()
                s_body = self.walk(body, s_in)
                s_body = frozenset(
                    s_body | frozenset(frame.continue_pool),
                )
                if update is not None:
                    s_body = self._scan_expression(update, s_body)
                new_seen = frozenset(seen | s_body)
                if len(new_seen) > _MAX_CONTEXTS:
                    raise ProofRefusal("path context cap exceeded")
                if new_seen == seen:
                    break
                seen = new_seen
            else:
                raise ProofRefusal("loop analysis did not converge")
            if cond is None:
                exit_state: _State = _EMPTY_STATE
            else:
                s_cond = self._scan_expression(cond, seen)
                exit_state = self._push(s_cond, cond, True)
            return frozenset(exit_state | frozenset(frame.break_pool))
        finally:
            self.loop_stack.pop()

    def _walk_while(self, node: Any, state: _State) -> _State:
        cond = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if body is None:
            raise ProofRefusal("while statement without a body")
        return self._loop_fixpoint(state, cond, body)

    def _walk_do(self, node: Any, state: _State) -> _State:
        cond = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if body is None:
            raise ProofRefusal("do statement without a body")
        return self._loop_fixpoint(state, cond, body, body_first=True)

    def _walk_for(self, node: Any, state: _State) -> _State:
        init = node.child_by_field_name("initializer")
        cond = node.child_by_field_name("condition")
        update = node.child_by_field_name("update")
        body = node.child_by_field_name("body")
        if body is None:
            raise ProofRefusal("for statement without a body")
        if init is not None:
            if init.type == "declaration":
                state = self._walk_declaration(init, state)
            else:
                state = self._scan_expression(init, state)
        return self._loop_fixpoint(state, cond, body, update=update)


# ---------------------------------------------------------------------------
# Z3 arm
# ---------------------------------------------------------------------------

_INT_TYPE_PROFILES: dict[tuple[str, ...], tuple[bool, int]] = {
    # normalized type-token tuple -> (signed, width)
    ("int",): (True, 32),
    ("signed", "int"): (True, 32),
    ("signed",): (True, 32),
    ("unsigned",): (False, 32),
    ("unsigned", "int"): (False, 32),
    ("long",): (True, 64),
    ("long", "int"): (True, 64),
    ("long", "long"): (True, 64),
    ("long", "long", "int"): (True, 64),
    ("unsigned", "long"): (False, 64),
    ("unsigned", "long", "int"): (False, 64),
    ("unsigned", "long", "long"): (False, 64),
    ("unsigned", "long", "long", "int"): (False, 64),
    ("size_t",): (False, 64),
    ("int32_t",): (True, 32),
    ("int64_t",): (True, 64),
    ("uint32_t",): (False, 32),
    ("uint64_t",): (False, 64),
}

_REL_OPS = frozenset({"<", "<=", ">", ">=", "==", "!="})


def _parameter_int_types(fn_node: Any) -> dict[str, tuple[bool, int]]:
    """Names of PARAMETERS with a resolvable ISO integer type (no
    pointers/arrays), mapped to (signed, width).

    Parameters only, deliberately: they are the sole variables whose
    value at every condition read is well-defined and stable without
    further reasoning.  A local could be uninitialised at the read
    (indeterminate — two reads need not agree, and the reads are UB),
    and an extern declared at function scope could be changed by any
    intervening call — joint unsatisfiability over unstable reads is
    not a refutation.  Mutation of a parameter is separately refused
    by the caller's assigned-names check.
    """
    out: dict[str, tuple[bool, int]] = {}
    for n in _walk_nodes(fn_node):
        if n.type != "parameter_declaration":
            continue
        declarator = n.child_by_field_name("declarator")
        if declarator is None or declarator.type != "identifier":
            continue  # pointer/array declarators are out of scope
        type_tokens: list[str] = []
        for c in n.children:
            if c.type in ("primitive_type", "sized_type_specifier",
                          "type_identifier"):
                type_tokens.extend(_node_text(c).split())
        key = tuple(t for t in type_tokens if t != "const")
        prof = _INT_TYPE_PROFILES.get(key)
        if prof is not None:
            out[_node_text(declarator)] = prof
    return out


def _assigned_names(fn_node: Any) -> set[str]:
    """Every identifier that is written or address-taken anywhere in
    the function (assignment, compound assignment, update, unary &)."""
    body = fn_node.child_by_field_name("body")
    names: set[str] = set()
    if body is None:
        return names
    for n in _walk_nodes(body):
        if n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                names.add(_node_text(left))
        elif n.type == "update_expression":
            arg = n.child_by_field_name("argument")
            if arg is not None and arg.type == "identifier":
                names.add(_node_text(arg))
        elif n.type == "pointer_expression":
            op = n.child_by_field_name("operator")
            arg = n.child_by_field_name("argument")
            if (
                op is not None and _node_text(op) == "&"
                and arg is not None and arg.type == "identifier"
            ):
                names.add(_node_text(arg))
    return names


def _vet_condition_text(
    text: str,
    int_types: dict[str, tuple[bool, int]],
    mutated: set[str],
) -> tuple[bool, int] | None:
    """Profile of a condition the Z3 arm may faithfully encode, or
    None when the condition is out of its fenced fragment."""
    try:
        toks = _tokenize(text)
    except ProofRefusal:
        return None
    profile: tuple[bool, int] | None = None
    has_rel = False
    for i, (kind, s) in enumerate(toks):
        if kind == "ident":
            if s in ("NULL", "sizeof") or s in _SETJMP_FAMILY:
                return None
            if i + 1 < len(toks) and toks[i + 1][1] == "(":
                return None  # function call
            prof = int_types.get(s)
            if prof is None or s in mutated:
                return None
            if profile is None:
                profile = prof
            elif profile != prof:
                return None
        elif kind == "punct":
            if s in _REL_OPS:
                has_rel = True
                continue
            if s in ("+", "-", "*", "|", "&", "<<", ">>", "(", ")"):
                continue
            return None
        elif kind == "num":
            if s.startswith("0") and len(s) > 1 and not s.lower().startswith("0x"):
                return None
            continue
        else:
            return None
    if profile is None or not has_rel:
        return None
    return profile


def _discharge_with_smt(
    violations: list[_Violation],
    fn_node: Any,
) -> tuple[bool, int]:
    """Try to prove every violating path infeasible.  Returns
    (all_discharged, paths_checked); degrades to (False, n) on any
    vetting failure, unparsed condition, sat/unknown verdict, or z3
    absence — never to a false proof."""
    try:
        from core.smt_solver import (
            BV_C_INT32,
            BV_C_INT64,
            BV_C_UINT32,
            BV_C_UINT64,
        )
        from core.smt_solver.path_feasibility import (
            PathCondition,
            check_path_feasibility,
        )
    except Exception:
        return False, 0
    profile_map = {
        (True, 32): BV_C_INT32,
        (True, 64): BV_C_INT64,
        (False, 32): BV_C_UINT32,
        (False, 64): BV_C_UINT64,
    }
    int_types = _parameter_int_types(fn_node)
    mutated = _assigned_names(fn_node)
    contexts: set[_Context] = set()
    for v in violations:
        contexts.update(v.contexts)
    checked = 0
    for ctx in contexts:
        if not ctx:
            return False, checked  # unconditionally-reachable path
        profiles = set()
        for text, _neg in ctx:
            prof = _vet_condition_text(text, int_types, mutated)
            if prof is None:
                return False, checked
            profiles.add(prof)
        if len(profiles) != 1:
            return False, checked
        conditions = [
            PathCondition(text=text, step_index=i, negated=neg)
            for i, (text, neg) in enumerate(sorted(ctx))
        ]
        result = check_path_feasibility(
            conditions, profile=profile_map[profiles.pop()],
        )
        checked += 1
        if result.feasible is not False:
            return False, checked
        if result.unknown:
            # Every condition must have been encoded: an unsat over a
            # subset is sound, but the vetting above promised full
            # coverage — treat a gap as a vetting failure.
            return False, checked
    return True, checked


# ---------------------------------------------------------------------------
# Helpers for consumers
# ---------------------------------------------------------------------------


def function_local_names(func_source: str) -> frozenset[str]:
    """Names of locals and parameters declared by *func_source*.

    Best-effort (parse errors tolerated): consumers use this only to
    match claim prose against candidate variable names — the proof
    itself re-parses strictly.
    """
    parser = _c_parser()
    if parser is None:
        return frozenset()
    try:
        tree = parser.parse(func_source.encode("utf-8"))
    except Exception:
        return frozenset()
    names: set[str] = set()
    for n in _walk_nodes(tree.root_node):
        if n.type in ("declaration", "parameter_declaration"):
            for c in n.named_children:
                nm = _declarator_name(c)
                if nm is not None:
                    names.add(_node_text(nm))
    return frozenset(names)


def function_parameter_names(func_source: str) -> frozenset[str]:
    """Names of the PARAMETERS *func_source* declares (best-effort).

    Consumers separating a claim's candidate variables into parameters
    versus locals use this: an uninitialised-value detector cannot
    flag a parameter, so a candidate set consisting solely of
    parameters can never cover such a receipt.
    """
    parser = _c_parser()
    if parser is None:
        return frozenset()
    try:
        tree = parser.parse(func_source.encode("utf-8"))
    except Exception:
        return frozenset()
    names: set[str] = set()
    for n in _walk_nodes(tree.root_node):
        if n.type == "parameter_declaration":
            nm = _declarator_name(
                n.child_by_field_name("declarator") or n,
            )
            if nm is not None:
                names.add(_node_text(nm))
    return frozenset(names)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def check_definite_assignment(
    func_source: str,
    variable: str,
    *,
    target_path: str | Path | None = None,
    rel_file: str | None = None,
) -> DefiniteAssignmentResult:
    """Prove *variable* is assigned on every path to every use in
    *func_source* (a single C function definition).

    *target_path*/*rel_file* locate the function's file inside the
    target tree so macro definitions come from the tree's own headers
    (read-only).  Without them, only macro-free sources can prove.

    Returns a :class:`DefiniteAssignmentResult`; every refusal is
    ``proven=False`` with the refusing construct named — the
    conservative direction is absolute.
    """

    def refusal(reason: str, **extra: Any) -> DefiniteAssignmentResult:
        logger.debug(
            "definite-assignment refusal for %r: %s", variable, reason,
        )
        return DefiniteAssignmentResult(
            proven=False, variable=variable, reason=reason, **extra,
        )

    if not variable or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable):
        return refusal(f"not a C identifier: {variable!r}")
    if not func_source or len(func_source) > _MAX_SOURCE_BYTES:
        return refusal("function source empty or too large")
    if re.search(r"^\s*#", func_source, re.MULTILINE):
        return refusal(
            "preprocessor directive inside the function source"
        )

    try:
        table = _macro_table_for(target_path, rel_file)
        if variable in table.defs or variable in table.poisoned:
            return refusal(
                f"{variable} is itself a macro name in the closure"
            )
        tokens = _tokenize(func_source)
        processed = _process_function_tokens(tokens, table, variable)
        fn_node = _parse_function(processed.text)

        decls = _find_variable_decls(fn_node, variable)
        provenance: dict[str, Any] = {
            "expanded_macros": tuple(processed.expanded_macros),
            "unresolved_includes": len(table.unresolved_includes),
            "macro_files_scanned": table.files_scanned,
        }
        if not decls:
            return refusal(
                f"{variable} is not declared in the function",
                **provenance,
            )
        if len(decls) > 1:
            return refusal(
                f"{variable} is declared more than once (shadowing)",
                **provenance,
            )
        decl = decls[0]
        if decl.is_parameter:
            return DefiniteAssignmentResult(
                proven=True, variable=variable,
                reason=(
                    f"{variable} is a parameter — assigned by the "
                    f"caller on every path"
                ),
                method="structural", **provenance,
            )
        if decl.is_static:
            return DefiniteAssignmentResult(
                proven=True, variable=variable,
                reason=(
                    f"{variable} has static storage — "
                    f"zero-initialized before first use"
                ),
                method="structural", **provenance,
            )

        # A keyword-named macro definition anywhere in the closure
        # (config-gated branch-profiling ``#define if`` is the
        # canonical shape) could rewrite branch semantics: disable the
        # walk's polarity-sensitive constant-condition folding AND the
        # SMT arm, leaving the fully both-branches-conservative core.
        keyword_macro_present = any(
            k in table.defs or k in table.poisoned for k in _C_KEYWORDS
        )
        walker = _Walker(
            variable, const_prune=not keyword_macro_present,
        )
        body = fn_node.child_by_field_name("body")
        walker.walk(body, _EMPTY_STATE)
        if not walker.decl_seen:
            return refusal(
                f"declaration of {variable} not reached by the walk",
                **provenance,
            )

        if not walker.violations:
            return DefiniteAssignmentResult(
                proven=True, variable=variable,
                reason=(
                    f"{variable} is assigned on every path to every "
                    f"use (structural definite-assignment walk over "
                    f"the macro-expanded source)"
                ),
                method="structural", **provenance,
            )

        # Z3 arm: only when no macro reduction blurred a condition and
        # no keyword-named macro definition could invert one.
        if processed.reductions == 0 and not keyword_macro_present:
            ok, checked = _discharge_with_smt(walker.violations, fn_node)
            if ok and checked:
                return DefiniteAssignmentResult(
                    proven=True, variable=variable,
                    reason=(
                        f"every path on which {variable} reaches a "
                        f"use unassigned has jointly unsatisfiable "
                        f"branch conditions ({checked} path(s), z3)"
                    ),
                    method="structural+smt",
                    smt_paths_discharged=checked, **provenance,
                )
        sample = walker.violations[0]
        return refusal(
            f"{variable} can reach a use unassigned "
            f"(e.g. {sample.use_text!r})",
            **provenance,
        )
    except ProofRefusal as exc:
        return refusal(exc.reason)
    except RecursionError:
        return refusal("recursion limit during analysis")
    except Exception as exc:  # noqa: BLE001 — refusal, never a crash
        logger.debug(
            "definite-assignment prover error", exc_info=True,
        )
        return refusal(f"internal error: {type(exc).__name__}")


__all__ = [
    "DefiniteAssignmentResult",
    "ProofRefusal",
    "check_definite_assignment",
    "function_local_names",
    "function_parameter_names",
    "resolve_include_closure",
]

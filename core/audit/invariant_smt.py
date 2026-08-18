"""SMT invariant-preservation harness.

Adjudicates invariant-shaped refutations: a review hypothesis (or its
refutation) states an invariant like ``obuf_len <= obuf_size`` and the
function mutates the involved variables. Existing channels could find
the taint flows but nothing could check the invariant itself, so these
verdicts stayed suspicious/inconclusive forever — blocking both
promotion and clean-conversion.

For each mutation site of an invariant variable the harness encodes
one inductive preservation step::

    invariant(pre)  ∧  transition(site)  ∧  ¬invariant(post)

* **unsat** — the site preserves the invariant (assuming it held
  before). All sites unsat → outcome ``preserved`` (supports the
  refutation / clean conversion).
* **sat** — re-asked in a second regime with every pre-state operand
  constrained ``>= 0`` (C size/length domains): still sat →
  ``violable`` with the non-negative model as receipt; unsat in the
  second regime → the site is ``preserved_nonneg`` (breakable only by
  a negative operand — the negative counterexample stays in the
  receipt, the two-regime split is never a hidden assumption).
* **unknown / unparseable** — ``inconclusive`` with a per-site reason,
  never a guess.

Scope — declared, not guessed:

* Linear integer arithmetic over named identifiers (struct member
  chains like ``s->obuf_len`` are treated as atomic names), integer
  constants, ``+``/``-``, ``min()``/``max()`` (encoded as ITE) and
  ``sizeof(...)`` (an opaque positive symbolic constant, one symbol
  per distinct argument text).
* Mathematical integers — no C wraparound/overflow modelling (the
  overflow verbs cover that); no pointer, heap or alias reasoning.
  Sites needing any of that are reported ``out_of_scope``.
* Inductive step only: the base case (invariant established at
  initialisation) is not proven here.

Degrades gracefully without z3 (outcome ``inconclusive``,
reason ``z3 unavailable``). No LLM calls, no subprocesses.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

RULE_ID = "smt:invariant-preservation"

# Identifier including struct member chains: a, s->len, cfg.size,
# ctx->hdr.len …
_IDENT = r"[A-Za-z_]\w*(?:(?:->|\.)\w+)*"

_CMP_OPS = ("<=", ">=", "==", "!=", "<", ">")

# Comparison operators that anchor an invariant. `>` guarded against
# `->` member access; alternation order makes `<=`/`>=` win over the
# single-char forms.
_OP_RE = re.compile(r"(<=|>=|==|!=|(?<!-)>(?![=\s]*[<>=])|<(?!=))")

# One side of an invariant: a flat linear expression made of atoms
# (identifier / int / sizeof(...) / min(...)/max(...)) joined by +/-.
# Bounded spans keep the scan linear on prose.
_ATOM = (
    rf"(?:sizeof\s*\([^()]{{0,48}}\)"
    rf"|(?:min|max)\s*\((?:[^()]|\([^()]{{0,48}}\)){{0,80}}\)"
    rf"|{_IDENT}|\d+)"
)
_SIDE_TAIL = rf"{_ATOM}(?:\s*[+\-]\s*{_ATOM})*"
# Anchored forms: the LAST expression before the operator and the
# FIRST expression after it (prose around them is ignored).
_LHS_RE = re.compile(rf"({_SIDE_TAIL})\s*$")
_RHS_RE = re.compile(rf"^\s*({_SIDE_TAIL})")

# How far around the operator an invariant side may reach.
_SIDE_WINDOW = 100

# Common C casts stripped before parsing.
_CAST_RE = re.compile(
    r"\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?"
    r"(?:size_t|ssize_t|u?int(?:8|16|32|64)?_t|int|long(?:\s+long)?"
    r"|short|char|off_t|ptrdiff_t)\s*\)",
)

_TOKEN_RE = re.compile(
    rf"\s*(sizeof\s*\([^()]*\)|min|max|{_IDENT}|\d+|[()+\-,])",
)


class _ParseError(Exception):
    pass


@dataclass
class SiteResult:
    """One mutation site's preservation verdict."""

    line: int
    code: str
    verdict: str            # preserved | violable | unknown | out_of_scope
    reason: str = ""
    model: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "line": self.line,
            "code": self.code,
            "verdict": self.verdict,
        }
        if self.reason:
            d["reason"] = self.reason
        if self.model:
            d["model"] = self.model
        return d


@dataclass
class InvariantPreservationResult:
    """Aggregate harness verdict for one invariant over one function."""

    outcome: str            # preserved | violable | inconclusive
    invariant: str
    sites: list[SiteResult] = field(default_factory=list)
    reason: str = ""
    rule_id: str = RULE_ID

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "invariant": self.invariant,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "sites": [s.to_dict() for s in self.sites],
        }


# ── expression parsing ──────────────────────────────────────────────


def _tokenize(text: str) -> list[str]:
    text = _CAST_RE.sub("", text)
    tokens: list[str] = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise _ParseError(f"unparseable at {text[pos:pos + 12]!r}")
        tokens.append(m.group(1).strip())
        pos = m.end()
    return tokens


class _ExprParser:
    """Recursive-descent parser for the supported linear fragment:

    expr   := term (('+'|'-') term)*
    term   := IDENT | INT | 'min(' expr ',' expr ')'
            | 'max(' expr ',' expr ')' | 'sizeof(...)' | '(' expr ')'
    """

    def __init__(self, tokens: list[str]):
        self._toks = tokens
        self._pos = 0

    def _peek(self) -> str | None:
        return self._toks[self._pos] if self._pos < len(self._toks) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise _ParseError("unexpected end of expression")
        self._pos += 1
        return tok

    def _expect(self, tok: str) -> None:
        got = self._next()
        if got != tok:
            raise _ParseError(f"expected {tok!r}, got {got!r}")

    def parse(self) -> tuple:
        node = self._expr()
        if self._peek() is not None:
            raise _ParseError(f"trailing tokens: {self._toks[self._pos:]}")
        return node

    def _expr(self) -> tuple:
        node = self._term()
        while self._peek() in ("+", "-"):
            op = self._next()
            rhs = self._term()
            node = ("add" if op == "+" else "sub", node, rhs)
        return node

    def _term(self) -> tuple:
        tok = self._next()
        if tok == "(":
            node = self._expr()
            self._expect(")")
            return node
        if tok == "-":
            inner = self._term()
            return ("sub", ("int", 0), inner)
        if tok in ("min", "max"):
            self._expect("(")
            a = self._expr()
            self._expect(",")
            b = self._expr()
            self._expect(")")
            return (tok, a, b)
        if tok.startswith("sizeof"):
            return ("sizeof", tok)
        if tok.isdigit():
            return ("int", int(tok))
        if re.fullmatch(_IDENT, tok):
            return ("var", tok)
        raise _ParseError(f"unexpected token {tok!r}")


def _parse_expr(text: str) -> tuple:
    return _ExprParser(_tokenize(text)).parse()


def _expr_vars(node: tuple) -> set[str]:
    kind = node[0]
    if kind == "var":
        return {node[1]}
    if kind in ("add", "sub", "min", "max"):
        return _expr_vars(node[1]) | _expr_vars(node[2])
    return set()


# ── invariant extraction ────────────────────────────────────────────


def extract_invariants(*texts: str) -> list[str]:
    """Extract candidate invariants (linear comparisons that mention at
    least one identifier) from hypothesis / counter / rationale text.
    Returns normalised ``lhs OP rhs`` strings, deduplicated in order."""
    seen: set[str] = set()
    out: list[str] = []
    for text in texts:
        if not text:
            continue
        for m in _OP_RE.finditer(text):
            op = m.group(1)
            # Sides never cross a line/statement boundary.
            left = text[max(0, m.start() - _SIDE_WINDOW):m.start()]
            left = re.split(r"[;\n]", left)[-1]
            right = text[m.end():m.end() + _SIDE_WINDOW]
            right = re.split(r"[;\n]", right)[0]
            lm = _LHS_RE.search(left)
            rm = _RHS_RE.search(right)
            if not lm or not rm:
                continue
            lhs_raw, rhs_raw = lm.group(1), rm.group(1)
            try:
                lhs = _parse_expr(lhs_raw)
                rhs = _parse_expr(rhs_raw)
            except _ParseError:
                continue
            variables = _expr_vars(lhs) | _expr_vars(rhs)
            if not variables:
                continue
            norm = re.sub(
                r"\s+", " ", f"{lhs_raw.strip()} {op} {rhs_raw.strip()}",
            )
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
    return out


def _parse_invariant(invariant: str) -> tuple[tuple, str, tuple]:
    text = invariant.strip()
    m = _OP_RE.search(text)
    if not m:
        raise _ParseError(f"not a comparison: {invariant!r}")
    return (
        _parse_expr(text[:m.start()]),
        m.group(1),
        _parse_expr(text[m.end():]),
    )


_NEGATED_OP = {
    "<=": ">", "<": ">=", ">=": "<", ">": "<=", "==": "!=", "!=": "==",
}


def negate_comparison(text: str) -> str | None:
    """Negate a linear comparison string (``a <= b`` → ``a > b``).

    Returns ``None`` when the text is not a comparison in the
    supported fragment — callers must then drop the condition rather
    than guess (the declared-scope discipline). Used by census-driven
    consumers to encode false-branch dominators."""
    try:
        _lhs, op, _rhs = _parse_invariant(text)
    except _ParseError:
        return None
    m = _OP_RE.search(text)
    if m is None:  # pragma: no cover — _parse_invariant just matched
        return None
    return (
        text[:m.start()].strip()
        + f" {_NEGATED_OP[op]} "
        + text[m.end():].strip()
    )


# ── mutation-site discovery ─────────────────────────────────────────

_ASSIGN_OPS = ("+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^=", "=")


def find_mutation_sites(
    source: str, variables: set[str],
) -> list[tuple[int, str, str, str, str]]:
    """Find lines that mutate any invariant variable.

    Returns ``(line_no, code, var, op, rhs)`` tuples. ``op`` is the
    assignment operator (``=``, ``+=``, …) or ``++``/``--``.
    """
    sites: list[tuple[int, str, str, str, str]] = []
    for line_no, raw in enumerate(source.splitlines(), start=1):
        code = raw.split("//", 1)[0]
        for var in sorted(variables, key=len, reverse=True):
            v = re.escape(var)
            m = re.search(
                rf"(?<![\w.>]){v}\s*"
                rf"(\+\+|--|<<=|>>=|[-+*/%&|^]=|=(?!=))\s*([^;]*)",
                code,
            )
            if m:
                op = m.group(1)
                rhs = (m.group(2) or "").strip()
                sites.append((line_no, code.strip(), var, op, rhs))
                continue
            m = re.search(rf"(\+\+|--)\s*{v}(?![\w.>-])", code)
            if m:
                sites.append((line_no, code.strip(), var, m.group(1), ""))
    return sites


# ── z3 encoding ─────────────────────────────────────────────────────


def _z3_available() -> bool:
    try:
        import z3  # noqa: F401
        return True
    except ImportError:
        return False


def _to_z3(node: tuple, env: dict, z3mod: Any):
    kind = node[0]
    if kind == "int":
        return z3mod.IntVal(node[1])
    if kind == "var":
        return env[node[1]]
    if kind == "sizeof":
        return env[node[1]]
    if kind == "add":
        return _to_z3(node[1], env, z3mod) + _to_z3(node[2], env, z3mod)
    if kind == "sub":
        return _to_z3(node[1], env, z3mod) - _to_z3(node[2], env, z3mod)
    if kind in ("min", "max"):
        a = _to_z3(node[1], env, z3mod)
        b = _to_z3(node[2], env, z3mod)
        cond = a <= b if kind == "min" else a >= b
        return z3mod.If(cond, a, b)
    raise _ParseError(f"unsupported node {kind}")


def _cmp_z3(lhs, op: str, rhs, z3mod: Any):
    return {
        "<=": lambda: lhs <= rhs,
        "<": lambda: lhs < rhs,
        ">=": lambda: lhs >= rhs,
        ">": lambda: lhs > rhs,
        "==": lambda: lhs == rhs,
        "!=": lambda: lhs != rhs,
    }[op]()


def _collect_symbols(node: tuple, env: dict, z3mod: Any, solver) -> None:
    kind = node[0]
    if kind == "var" and node[1] not in env:
        env[node[1]] = z3mod.Int(node[1])
    elif kind == "sizeof" and node[1] not in env:
        sym = z3mod.Int(f"__{len(env)}_{node[1][:24]}")
        env[node[1]] = sym
        solver.add(sym > 0)   # sizeof is always positive
    elif kind in ("add", "sub", "min", "max"):
        _collect_symbols(node[1], env, z3mod, solver)
        _collect_symbols(node[2], env, z3mod, solver)


def check_invariant_preservation(
    invariant: str,
    source: str,
    *,
    timeout_ms: int = 5000,
) -> InvariantPreservationResult:
    """Check that every mutation site in ``source`` preserves
    ``invariant`` (one inductive step per site). See module docstring
    for verdict semantics and the declared scope."""
    try:
        lhs, op, rhs = _parse_invariant(invariant)
    except _ParseError as exc:
        return InvariantPreservationResult(
            outcome="inconclusive",
            invariant=invariant,
            reason=f"invariant outside the linear fragment: {exc}",
        )

    variables = _expr_vars(lhs) | _expr_vars(rhs)
    if not variables:
        return InvariantPreservationResult(
            outcome="inconclusive",
            invariant=invariant,
            reason="invariant names no variables",
        )

    sites = find_mutation_sites(source or "", variables)
    if not sites:
        return InvariantPreservationResult(
            outcome="preserved",
            invariant=invariant,
            reason=(
                "no mutation sites for the invariant variables in this "
                "function (vacuously preserved; base case not checked)"
            ),
        )

    if not _z3_available():
        return InvariantPreservationResult(
            outcome="inconclusive",
            invariant=invariant,
            reason="z3 unavailable (pip install z3-solver)",
            sites=[
                SiteResult(line=ln, code=code, verdict="unknown",
                           reason="z3 unavailable")
                for ln, code, _v, _o, _r in sites
            ],
        )

    import z3

    site_results: list[SiteResult] = []
    for line_no, code, var, aop, rhs_text in sites:
        result = _check_one_site(
            z3, lhs, op, rhs, variables, line_no, code, var, aop,
            rhs_text, timeout_ms,
        )
        site_results.append(result)

    if any(s.verdict == "violable" for s in site_results):
        outcome = "violable"
        reason = "at least one mutation site can break the invariant"
    elif all(
        s.verdict in ("preserved", "preserved_nonneg")
        for s in site_results
    ):
        outcome = "preserved"
        caveats = [s for s in site_results
                   if s.verdict == "preserved_nonneg"]
        reason = (
            "every mutation site preserves the invariant "
            "(inductive step; base case not checked)"
        )
        if caveats:
            reason += (
                "; sites "
                + ",".join(f"L{s.line}" for s in caveats[:4])
                + " rely on non-negative operands (negative-value "
                "counterexamples in the receipt)"
            )
    else:
        outcome = "inconclusive"
        undecided = [
            f"line {s.line}: {s.reason or s.verdict}"
            for s in site_results
            if s.verdict in ("unknown", "out_of_scope")
        ]
        reason = "undecided sites — " + "; ".join(undecided[:4])

    return InvariantPreservationResult(
        outcome=outcome,
        invariant=invariant,
        sites=site_results,
        reason=reason,
    )


def _check_one_site(
    z3: Any,
    lhs: tuple,
    op: str,
    rhs: tuple,
    variables: set[str],
    line_no: int,
    code: str,
    var: str,
    aop: str,
    rhs_text: str,
    timeout_ms: int,
    pre_conditions: tuple = (),
) -> SiteResult:
    """Encode one mutation site's transition and query preservation.

    ``pre_conditions`` (census-driven multi-site harness) are
    comparison strings that dominate the site — polarity already
    resolved by the caller. Each is conjoined with the pre-state; an
    unparseable pre-condition makes the site ``out_of_scope`` (a guard
    we cannot encode must not be silently dropped: dropping would
    over-report violability, keeping it wrong would fake safety)."""
    # Build the post-state expression for the mutated variable.
    if aop in ("++", "--"):
        delta = ("int", 1)
        new_expr = ("add" if aop == "++" else "sub", ("var", var), delta)
    elif aop in ("=", "+=", "-="):
        try:
            parsed_rhs = _parse_expr(rhs_text)
        except _ParseError as exc:
            return SiteResult(
                line=line_no, code=code, verdict="out_of_scope",
                reason=(
                    f"assignment RHS outside the linear fragment "
                    f"({exc})"
                ),
            )
        if aop == "=":
            new_expr = parsed_rhs
        else:
            new_expr = (
                "add" if aop == "+=" else "sub",
                ("var", var), parsed_rhs,
            )
    else:
        return SiteResult(
            line=line_no, code=code, verdict="out_of_scope",
            reason=f"operator {aop!r} outside the linear fragment",
        )

    parsed_pres: list[tuple[tuple, str, tuple]] = []
    for cond in pre_conditions:
        try:
            parsed_pres.append(_parse_invariant(cond))
        except _ParseError as exc:
            return SiteResult(
                line=line_no, code=code, verdict="out_of_scope",
                reason=(
                    f"dominating condition {cond!r} outside the "
                    f"linear fragment ({exc})"
                ),
            )

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    env: dict[str, Any] = {}
    for node in (lhs, rhs, new_expr):
        _collect_symbols(node, env, z3, solver)
    for p_lhs, _p_op, p_rhs in parsed_pres:
        _collect_symbols(p_lhs, env, z3, solver)
        _collect_symbols(p_rhs, env, z3, solver)

    pre = _cmp_z3(_to_z3(lhs, env, z3), op, _to_z3(rhs, env, z3), z3)
    for p_lhs, p_op, p_rhs in parsed_pres:
        solver.add(_cmp_z3(
            _to_z3(p_lhs, env, z3), p_op, _to_z3(p_rhs, env, z3), z3,
        ))

    # Post-state: substitute the mutated variable with a primed symbol
    # defined by the transition.
    primed = z3.Int(f"{var}__post")
    post_env = dict(env)
    post_env[var] = primed
    post = _cmp_z3(
        _to_z3(lhs, post_env, z3), op, _to_z3(rhs, post_env, z3), z3,
    )

    solver.add(pre)
    solver.add(primed == _to_z3(new_expr, env, z3))
    solver.add(z3.Not(post))

    def _model_values(model) -> dict[str, int]:
        values: dict[str, int] = {}
        for name, sym in env.items():
            val = model.eval(sym, model_completion=True)
            try:
                values[name] = val.as_long()
            except AttributeError:
                pass
        try:
            values[f"{var}'"] = model.eval(
                primed, model_completion=True,
            ).as_long()
        except AttributeError:
            pass
        return values

    check = solver.check()
    if check == z3.unsat:
        return SiteResult(line=line_no, code=code, verdict="preserved")
    if check != z3.sat:
        return SiteResult(
            line=line_no, code=code, verdict="unknown",
            reason="solver returned unknown (timeout or undecidable)",
        )

    math_model = _model_values(solver.model())

    # Second regime: pure math admits negative operands that C size/
    # length domains usually exclude (a break that NEEDS size = -1 is
    # a different claim than a break with realistic operands). Re-ask
    # with every pre-state operand constrained >= 0; the two-regime
    # split is part of the receipt, never a hidden assumption.
    solver.push()
    for sym in env.values():
        solver.add(sym >= 0)
    nonneg_check = solver.check()
    nonneg_model = (
        _model_values(solver.model()) if nonneg_check == z3.sat else {}
    )
    solver.pop()

    if nonneg_check == z3.sat:
        return SiteResult(
            line=line_no, code=code, verdict="violable",
            reason=(
                "model breaks the invariant after this assignment "
                "(all operands non-negative)"
            ),
            model=nonneg_model,
        )
    if nonneg_check == z3.unsat:
        return SiteResult(
            line=line_no, code=code, verdict="preserved_nonneg",
            reason=(
                "preserved for non-negative operands; breakable only "
                "if an operand can go negative (counterexample in "
                "model)"
            ),
            model=math_model,
        )
    return SiteResult(
        line=line_no, code=code, verdict="unknown",
        reason="solver returned unknown (timeout or undecidable)",
    )


def check_site_preservation(
    invariant: str,
    code: str,
    *,
    line: int = 0,
    pre_conditions: tuple = (),
    timeout_ms: int = 5000,
) -> SiteResult:
    """One inductive preservation step for ONE mutation site — the
    census-driven multi-site entry point (protocol_state channel).

    ``code`` is the site's statement text (the caller has already
    normalised struct-member chains to the invariant's variable
    names); ``pre_conditions`` are polarity-resolved dominating
    comparisons. Verdict semantics and the two-regime nonneg handling
    are identical to :func:`check_invariant_preservation`; the
    ``out_of_scope`` discipline applies to both the invariant and the
    dominating conditions."""
    try:
        lhs, op, rhs = _parse_invariant(invariant)
    except _ParseError as exc:
        return SiteResult(
            line=line, code=code, verdict="out_of_scope",
            reason=f"invariant outside the linear fragment: {exc}",
        )
    variables = _expr_vars(lhs) | _expr_vars(rhs)
    sites = find_mutation_sites(code or "", variables)
    if not sites:
        return SiteResult(
            line=line, code=code.strip(), verdict="preserved",
            reason="no mutation of an invariant variable at this site",
        )
    if not _z3_available():
        return SiteResult(
            line=line, code=code.strip(), verdict="unknown",
            reason="z3 unavailable",
        )
    import z3
    _ln, site_code, var, aop, rhs_text = sites[0]
    result = _check_one_site(
        z3, lhs, op, rhs, variables, line or _ln, site_code, var, aop,
        rhs_text, timeout_ms, pre_conditions=tuple(pre_conditions),
    )
    return result

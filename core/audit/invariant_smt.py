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
  receipt). This conditional result makes aggregation inconclusive;
  it cannot support refutation or clean conversion. Source guards that
  establish the needed bounds already participate in the first query.
* **unknown / unparseable** — ``inconclusive`` with a per-site reason,
  never a guess.

Scope — declared, not guessed:

* Linear integer arithmetic over named identifiers (struct member
  chains like ``s->obuf_len`` are treated as atomic names), integer
  constants, ``+``/``-``, ``min()``/``max()`` (encoded as ITE) and
  simple object/type ``sizeof(...)`` operands (opaque nonnegative constants,
  including zero-sized extensions; lexical whitespace is canonicalized).
  Array and other unsupported operands require source/type modeling and decline.
* Mathematical integers — source casts and ambiguous leading-zero literals
  decline; no C wraparound/overflow modelling (the
  overflow verbs cover that); no pointer, heap or alias reasoning.
  Sites needing any of that are reported ``out_of_scope``.
* An explicitly resolved integer ABI can bind builtin integer ``sizeof``
  terms to target C-byte sizes. Its full record and provenance travel with
  the query and site receipts. Missing layouts retain the opaque size model;
  integer widths do not supply pointer, aggregate or boolean storage layouts.
* Inductive step only: the base case (invariant established at
  initialisation) is not proven here.

Proof-bearing site admission requires the optional C grammar; unavailable
or unsupported source is inconclusive. The legacy textual line inventory
is retained for non-proof consumers.

Degrades gracefully without z3 (outcome ``inconclusive``,
reason ``z3 unavailable``). Native queries run in the shared confined JSON
worker. No LLM calls or target code execution.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from core.source.lines import split_lines
from typing import Any

from core.smt_solver.session import check_solver, new_solver, query_budget, scoped, solver_reason_unknown
from .invariant_outcomes import aggregate_verdicts

from .invariant_expression import (
    IDENTIFIER as _IDENT,
    MAX_TEXT_CHARS as _MAX_INVARIANT_TEXT,
    ParseError as _ParseError,
    parse_expr as _parse_expr,
    expression_vars as _expr_vars,
    validate_expression,
    validate_counterexample,
)

logger = logging.getLogger(__name__)

RULE_ID = "smt:invariant-preservation"


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
# The +/- chain is bounded: with an unbounded chain, a run of
# single-char terms ("a+a+a+...") makes every atom start re-walk the
# chain tail when the end anchor fails — quadratic in the side text.
# Real invariant sides carry a handful of terms; 12 is generous
# (trade-off: a longer chain stops parsing as one side, versus an
# unbounded re-walk on hostile text).
_SIDE_TAIL = rf"{_ATOM}(?:\s*[+\-]\s*{_ATOM}){{0,12}}"
# Anchored forms: the LAST expression before the operator and the
# FIRST expression after it (prose around them is ignored).  The
# leading \b pins the search to atom starts — a mid-word start only
# ever fabricated a token (the "xff" tail of a hex literal), and an
# unpinned scan re-reads the same word from every offset.
_LHS_RE = re.compile(rf"\b({_SIDE_TAIL})\s*$")
_RHS_RE = re.compile(rf"^\s*({_SIDE_TAIL})")

# How far around the operator an invariant side may reach.
_SIDE_WINDOW = 100

@dataclass
class SiteResult:
    """One mutation site's preservation verdict."""

    line: int
    code: str
    verdict: str            # preserved | violable | unknown | out_of_scope
    reason: str = ""
    model: dict[str, int] = field(default_factory=dict)
    integer_abi: dict | None = None

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
        if self.integer_abi is not None:
            d["integer_abi"] = dict(self.integer_abi)
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


def _invariant_candidate_segments(text):
    """Keep multiline expression context attached to its comparison.

    Newlines can separate prose candidates, but C continuation operators
    and wrappers cannot be discarded as if they ended a predicate.
    """
    for statement in text.split(";"):
        if len(statement) > _MAX_INVARIANT_TEXT or any(token in statement for token in ("&&", "||", "?")):
            continue
        lines = statement.splitlines()
        significant = [line.strip() for line in lines if line.strip()]
        if any(left[-1] in "([!~.=<>+*/%&|^-," or right[0] in "()[]!~.=<>+*/%&|^-,"
               for left, right in zip(significant, significant[1:])):
            continue
        yield from lines


def extract_invariants(*texts: str) -> list[str]:
    """Extract complete supported comparisons from bounded prose segments.

    A semicolon/newline segment may contribute one comparison. Compound
    predicates, external expression wrappers, and partial literal/identifier
    tokens decline rather than changing the question sent to the solver.
    Returns normalized strings, deduplicated in discovery order.
    """
    seen: set[str] = set()
    out: list[str] = []
    for text in texts:
        if not text:
            continue
        for segment in _invariant_candidate_segments(text):
            comparisons = _OP_RE.finditer(segment)
            m = next(comparisons, None)
            if m is None or next(comparisons, None) is not None:
                continue
            left_start = max(0, m.start() - _SIDE_WINDOW)
            left = segment[left_start:m.start()]
            right = segment[m.end():m.end() + _SIDE_WINDOW]
            lm = _LHS_RE.search(left)
            rm = _RHS_RE.search(right)
            if not lm or not rm:
                continue
            lhs_raw, rhs_raw = lm.group(1), rm.group(1)
            start, end = left_start + lm.start(1), m.end() + rm.end(1)
            # The bounded matching window must not turn a long source token
            # or an unsupported literal suffix into a different identifier
            # or integer. Inspect actual neighbors outside that window too.
            if ((start and (segment[start - 1].isalnum() or segment[start - 1] == "_"))
                    or (end < len(segment) and (segment[end].isalnum() or segment[end] == "_"))):
                continue
            before, after = segment[:start].rstrip(), segment[end:].lstrip()
            if ((before and before[-1] in "()[]+*/%&|^~!.><-=,?")
                    or (after and after[0] in "()[]+*/%&|^><-=!?:,")):
                continue
            numeric_tail = re.search(r"(?<![\w.])[0-9]+$", rhs_raw) is not None
            if ((after.startswith(".") and (numeric_tail or re.match(r"\.\s*\w", after)))
                    or (end < len(segment) and segment[end] == "'" and numeric_tail)):
                continue
            try:
                lhs = _parse_expr(lhs_raw)
                rhs = _parse_expr(rhs_raw)
            except _ParseError:
                continue
            variables = _expr_vars(lhs) | _expr_vars(rhs)
            if not variables:
                continue
            norm = re.sub(
                r"\s+", " ", f"{lhs_raw.strip()} {m.group(1)} {rhs_raw.strip()}",
            )
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
    return out


def _parse_invariant(invariant: str) -> tuple[tuple, str, tuple]:
    text = invariant.strip()
    m = _OP_RE.search(text)
    if not m:
        msg = f"not a comparison: {invariant!r}"
        raise _ParseError(msg)
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

    Scans the sanitized view (comments/string literals blanked): a
    ``/* len = attacker */`` comment must not mint a mutation site.
    This compatibility line inventory is not a preservation proof. Proof
    consumers use the AST-backed invariant_source admission instead.
    """
    from .source_view import sanitized_view
    sites: list[tuple[int, str, str, str, str]] = []
    view = sanitized_view(source, language="c")
    for line_no, code in enumerate(split_lines(view), start=1):
        line_sites = []
        for var in sorted(variables, key=len, reverse=True):
            v = re.escape(var)
            for match in re.finditer(
                rf"(?<![\w.>]){v}\s*"
                rf"(\+\+|--|<<=|>>=|[-+*/%&|^]=|=(?!=))\s*([^;]*)",
                code,
            ):
                line_sites.append((match.start(), var, match.group(1), (match.group(2) or "").strip()))
            for match in re.finditer(rf"(\+\+|--)\s*{v}(?![\w.>-])", code):
                line_sites.append((match.start(), var, match.group(1), ""))
        for _, var, op, rhs in sorted(line_sites):
            sites.append((line_no, code.strip(), var, op, rhs))
    return sites


def find_alias_escapes(
    source: str, variables: set[str],
) -> list[tuple[int, str, str]]:
    """Lines where an invariant variable's address is taken.

    ``grow(&obuf_len, n)`` / ``memcpy(&len, src, 4)`` / ``p = &len``
    mutate through an alias the per-line regex cannot see. Returns
    ``(line_no, code, var)`` tuples — the caller must report these
    ``out_of_scope`` (needs alias reasoning), NEVER fold them into a
    vacuous 'preserved'. The match is lexically over-approximate
    (``a & len`` bitwise-AND also matches) — that only ever moves the
    outcome toward inconclusive, the safe direction for a witness
    that refutes.
    """
    from .source_view import sanitized_view
    escapes: list[tuple[int, str, str]] = []
    view = sanitized_view(source, language="c")
    member = r"(?:[A-Za-z_]\w*\s*(?:->|\.)\s*)"
    for line_no, code in enumerate(split_lines(view), start=1):
        for var in sorted(variables, key=len, reverse=True):
            v = re.escape(var)
            # &var and &s->var / &s.var (member paths ending in the
            # invariant variable — the verifier PoC's spelling).
            if re.search(rf"(?:^|[^&\w])&\s*{member}*{v}\b(?![\w(])",
                         code):
                escapes.append((line_no, code.strip(), var))
                continue
            # Member-spelling direct mutation (s->var += n): the
            # mutation-site regex deliberately excludes member paths
            # (whose member? needs points-to), so it must surface
            # here rather than vanish into vacuous 'preserved'.
            if re.search(
                rf"(?:->|\.)\s*{v}\s*"
                rf"(?:\+\+|--|<<=|>>=|[-+*/%&|^]=|=(?!=))",
                code,
            ):
                escapes.append((line_no, code.strip(), var))
    return escapes


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
    msg = f"unsupported node {kind}"
    raise _ParseError(msg)


def _cmp_z3(lhs, op: str, rhs, _z3mod: Any):
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
        solver.add(sym >= 0)  # Opaque types may have zero size in compiler extensions.
    elif kind in ("add", "sub", "min", "max"):
        _collect_symbols(node[1], env, z3mod, solver)
        _collect_symbols(node[2], env, z3mod, solver)


def check_invariant_preservation(
    invariant: str,
    source: str,
    *,
    timeout_ms: int = 5000,
    integer_abi=None,
) -> InvariantPreservationResult:
    """Check all mutation sites within one shared soft solver budget.

    This proves mathematical-integer induction steps, not C conversion,
    overflow, source reachability or the invariant's initialization.
    """
    from .invariant_worker import run_check
    with query_budget(timeout_ms) as deadline:
        return run_check("function", invariant, source, timeout_ms=timeout_ms, deadline=deadline, integer_abi=integer_abi)


def _check_invariant_preservation(
    invariant: str,
    source: str,
    *,
    timeout_ms: int = 5000,
    integer_abi=None,
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

    from .invariant_source import source_mutations
    sites, effects, refusal = source_mutations(source or "", variables)
    if refusal:
        return InvariantPreservationResult(outcome="inconclusive", invariant=invariant, reason=refusal)
    if not sites and not effects:
        return InvariantPreservationResult(outcome="preserved", invariant=invariant,
            reason="no mutation sites for the invariant variables in this function (vacuously preserved; base case not checked)")
    if not _z3_available():
        return InvariantPreservationResult(outcome="inconclusive", invariant=invariant,
            reason="z3 unavailable", sites=[SiteResult(line=site.line, code=site.code,
                verdict="unknown", reason="z3 unavailable") for site in sites + effects])
    import z3
    site_results = []
    for site in sites:
        if site.reason:
            result = SiteResult(line=site.line, code=site.code, verdict="out_of_scope", reason=site.reason)
        else:
            result = _check_one_site(z3, lhs, op, rhs, variables, site.line, site.code,
                                     site.var, site.op, site.rhs, timeout_ms, pre_conditions=site.guards, integer_abi=integer_abi)
        site_results.append(result)
    site_results.extend(SiteResult(line=effect.line, code=effect.code, verdict="out_of_scope", reason=effect.reason)
                        for effect in effects)

    outcome = aggregate_verdicts(s.verdict for s in site_results)
    if outcome == "violable":
        reason = "at least one mutation site can break the invariant"
    elif outcome == "preserved":
        reason = (
            "every mutation site preserves the invariant "
            "(inductive step; base case not checked)"
        )
    else:
        undecided = [
            f"line {s.line}: {s.reason or s.verdict}"
            for s in site_results
            if s.verdict in ("unknown", "out_of_scope", "preserved_nonneg")
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
    _variables: set[str],
    line_no: int,
    code: str,
    var: str,
    aop: str,
    rhs_text: str,
    timeout_ms: int,
    pre_conditions: tuple = (),
    integer_abi=None,
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

    try:
        validate_expression(new_expr)
    except _ParseError as exc:
        return SiteResult(line=line_no, code=code, verdict="out_of_scope", reason=str(exc))

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

    solver = new_solver(timeout_ms)
    env: dict[str, Any] = {}
    for node in (lhs, rhs, new_expr):
        _collect_symbols(node, env, z3, solver)
    for p_lhs, _p_op, p_rhs in parsed_pres:
        _collect_symbols(p_lhs, env, z3, solver)
        _collect_symbols(p_rhs, env, z3, solver)

    from .invariant_sizeof import resolved_sizeof_values
    expressions = [lhs, rhs, new_expr, *(node for a, _, b in parsed_pres for node in (a, b))]
    for name, value in resolved_sizeof_values(expressions, integer_abi).items():
        solver.add(env[name] == value)

    pre = _cmp_z3(_to_z3(lhs, env, z3), op, _to_z3(rhs, env, z3), z3)
    for p_lhs, p_op, p_rhs in parsed_pres:
        solver.add(_cmp_z3(
            _to_z3(p_lhs, env, z3), p_op, _to_z3(p_rhs, env, z3), z3,
        ))

    # Post-state: substitute the mutated variable with a primed symbol
    # defined by the transition.
    # Fresh native names contain "!", outside the admitted source identifier
    # grammar. They cannot alias an ordinary variable such as Count__post.
    primed = z3.FreshInt("invariant_post")
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

    check = check_solver(solver)
    if check == z3.unsat:
        return SiteResult(line=line_no, code=code, verdict="preserved")
    if check != z3.sat:
        return SiteResult(
            line=line_no, code=code, verdict="unknown",
            reason="solver returned unknown: " + solver_reason_unknown(solver),
        )

    math_model = _model_values(solver.model())
    if not validate_counterexample(lhs, op, rhs, new_expr, var, parsed_pres, math_model, integer_abi=integer_abi):
        return SiteResult(line=line_no, code=code, verdict="unknown",
                          reason="mathematical counterexample replay failed")

    # Second regime: pure math admits negative operands that C size/
    # length domains usually exclude (a break that NEEDS size = -1 is
    # a different claim than a break with realistic operands). Re-ask
    # with every pre-state operand constrained >= 0; the two-regime
    # split is part of the receipt, never a hidden assumption.
    with scoped(solver):
        for sym in env.values():
            solver.add(sym >= 0)
        nonneg_check = check_solver(solver)
        nonneg_model = (
            _model_values(solver.model()) if nonneg_check == z3.sat else {}
        )
        nonneg_reason = solver_reason_unknown(solver) if nonneg_check not in (z3.sat, z3.unsat) else ""

    if nonneg_check == z3.sat:
        if not validate_counterexample(lhs, op, rhs, new_expr, var, parsed_pres, nonneg_model, nonnegative=True, integer_abi=integer_abi):
            return SiteResult(line=line_no, code=code, verdict="unknown",
                              reason="non-negative counterexample replay failed")
        return SiteResult(
            line=line_no, code=code, verdict="violable",
            reason=(
                "model breaks the invariant after this assignment "
                "(all operands non-negative)"
            ),
            model=nonneg_model,
        )
    if nonneg_check == z3.unsat:
        if all(value >= 0 for name, value in math_model.items() if name != f"{var}'"):
            return SiteResult(line=line_no, code=code, verdict="unknown",
                              reason="non-negative counterexample contradicts preservation verdict")
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
        reason="solver returned unknown: " + nonneg_reason,
    )


def check_site_batch(
    invariant: str,
    sites: list[dict],
    *,
    timeout_ms: int = 5000,
    integer_abi=None,
) -> list[SiteResult] | None:
    """Check ordered code/line/pre_conditions records in one confined worker.

    None means the batch was unavailable or incomplete; callers must not
    aggregate it as preservation. Every accepted input has one result, even
    when the shared deadline expires. Each site's native budget stays at 5s.
    """
    from .invariant_batch import run_batch
    with query_budget(timeout_ms) as deadline:
        return run_batch(invariant, sites, timeout_ms=timeout_ms, deadline=deadline, integer_abi=integer_abi)


def check_site_preservation(
    invariant: str,
    code: str,
    *,
    line: int = 0,
    pre_conditions: tuple = (),
    timeout_ms: int = 5000,
    integer_abi=None,
) -> SiteResult:
    """Check exactly one direct mutation using a shared soft query budget."""
    from .invariant_worker import run_check
    with query_budget(timeout_ms) as deadline:
        return run_check("site", invariant, code, line=line, pre_conditions=pre_conditions,
                         timeout_ms=timeout_ms, deadline=deadline, integer_abi=integer_abi)


def _check_site_preservation(
    invariant: str,
    code: str,
    *,
    line: int = 0,
    pre_conditions: tuple = (),
    timeout_ms: int = 5000,
    integer_abi=None,
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
    from .invariant_source import source_mutations
    sites, effects, refusal = source_mutations(code or "", variables)
    if refusal or effects:
        return SiteResult(line=line, code=code.strip(), verdict="out_of_scope",
                          reason=refusal or effects[0].reason)
    if not sites:
        return SiteResult(line=line, code=code.strip(), verdict="preserved",
                          reason="no mutation of an invariant variable at this site")
    if len(sites) != 1:
        return SiteResult(line=line, code=code.strip(), verdict="out_of_scope",
                          reason="multiple mutations require a joint transition model")
    site = sites[0]
    if site.reason or len(pre_conditions) + len(site.guards) > 64:
        return SiteResult(line=line or site.line, code=site.code, verdict="out_of_scope",
                          reason=site.reason or "reaching guard budget exhausted")
    if not _z3_available():
        return SiteResult(line=line, code=code.strip(), verdict="unknown", reason="z3 unavailable")
    import z3
    return _check_one_site(z3, lhs, op, rhs, variables, line or site.line, site.code,
                           site.var, site.op, site.rhs, timeout_ms,
                           pre_conditions=tuple(pre_conditions) + site.guards, integer_abi=integer_abi)

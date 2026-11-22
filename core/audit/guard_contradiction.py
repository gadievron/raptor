"""Guard-contradiction oracle for the lifetime witness (C).

The lifetime witness reasons over a statement-level CFG in which both
branches of every ``if`` are ordinary successors, so a release guarded
by a condition and a later use guarded by its negation —

    if (err)
        kfree(p);
    if (!err)
        consume(p);

— share a lexical path and the witness refuses, re-flagging a dismissed
claim whose mechanism no execution can realise. This oracle proves such
a pair infeasible: it conjoins the governing ``if`` conditions of the
two statements and asks Z3 whether any single valuation satisfies them
all. Unsatisfiable means no one execution performs both statements,
because the admitted condition variables provably hold one value for
the whole call.

The answer is True ONLY on a machine-checked contradiction inside a
closed admission frame; every unmodeled construct answers False and the
caller keeps its refusal. The frame, each rule load-bearing:

- The function contains no goto, label, switch or case: entering an
  ``if`` branch then syntactically implies its condition's truth —
  nothing can jump into the middle of a branch.
- Governors are ``if`` conditions only, with polarity taken from which
  branch encloses the statement. Loop conditions are never collected:
  OMITTING a governor only weakens the conjunction, so unsatisfiability
  of the weaker set still proves path infeasibility.
- Conditions are built from ``!``, ``&&``, ``||``, parentheses, bare
  identifiers (truthiness) and identifier-vs-integer-literal
  comparisons. No calls, assignments, casts, commas, ternaries or
  identifier-vs-identifier comparisons — anything else refuses.
- Every condition identifier must be a parameter or local of the
  function with EXACTLY ONE declaring occurrence (no shadowing), a
  keyword-only integer type (``int``/``long``/``short``/``signed``/
  ``unsigned`` combinations — spellings no typedef or macro can
  legally shadow), at most a ``const`` qualifier, no storage class,
  and — for locals — an initializer and a declaration outside every
  loop. It must never be written anywhere in the body: no assignment
  of any operator, no ``++``/``--``, no ``&`` over any expression
  containing it. One value per call, loops included.
- Names known to the macro table are refused outright, and the caller
  vouches separately for parameters (``params_admissible``): a
  certified macro body may name a parameter the raw parse then cannot
  see being written, so parameters are admitted only after the
  caller's macro certification has covered them.
- Literals are plain decimal/hex with magnitude at most 32767 (exact
  under the usual arithmetic conversions for every C integer width);
  negative literals are admitted only against proven-signed
  identifiers — against an unsigned operand their converted value is
  width-dependent.

Encoding: each admitted identifier is one unbounded Z3 integer
(unsigned adds ``v >= 0``). Within this fragment the mathematical
reading agrees exactly with the C evaluation of every admitted atom,
so every real execution of the pair would yield a model — ``unsat``
therefore proves there is none. ``sat``, ``unknown``, a missing
solver, or any admission failure all answer False.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .defassign import _node_text, _walk_nodes

logger = logging.getLogger(__name__)

#: Constructs that break the "branch entry implies condition truth"
#: reading — a jump target inside a branch bypasses the test.
_JUMP_STMTS = frozenset({
    "goto_statement", "labeled_statement",
    "switch_statement", "case_statement",
})

_LOOP_STMTS = frozenset({
    "while_statement", "do_statement", "for_statement",
})

#: Statement-level parent types the governor climb may pass through
#: without recording anything. Loops are deliberately inert: omitting
#: a loop condition only WEAKENS the conjunction, so unsatisfiability
#: of the weaker set still proves the pair infeasible. Any other
#: statement-level parent is unmodeled and refuses the climb.
_CLIMB_INERT = _LOOP_STMTS | {
    "compound_statement", "else_clause",
    "expression_statement", "return_statement",
}

#: Keyword-only integer type words — not shadowable by typedef or by
#: a macro that survives the macro-name screen.
_TYPE_WORDS = frozenset({"int", "long", "short", "signed", "unsigned"})

_DECLARATOR_WRAPPERS = frozenset({
    "pointer_declarator", "array_declarator", "function_declarator",
    "parenthesized_declarator", "attributed_declarator",
})

_DEC_RE = re.compile(r"\d+\Z")
_HEX_RE = re.compile(r"0[xX][0-9a-fA-F]+\Z")

#: Exact under integer promotion for every C integer width >= 16 bits.
_MAX_LITERAL = 32767

_MAX_ATOMS = 64
_MAX_IDENTS = 16
_MAX_CLIMB = 128
_SOLVER_TIMEOUT_MS = 2000


class _Refuse(Exception):
    """Internal: the construct is outside the admission frame."""


def _resolve_declarator(node: Any) -> Any | None:
    """The identifier at the core of a declarator chain, else None."""
    d = node
    for _ in range(16):
        if d is None:
            return None
        if d.type == "identifier":
            return d
        if d.type in _DECLARATOR_WRAPPERS:
            d = d.child_by_field_name("declarator") or (
                d.named_children[0] if d.named_children else None
            )
            continue
        return None
    return None


def _strip_parens(node: Any) -> Any:
    n = node
    while n is not None and n.type == "parenthesized_expression":
        inner = [c for c in n.named_children if c.type != "comment"]
        if len(inner) != 1:
            return n
        n = inner[0]
    return n


def _literal_value(node: Any) -> int | None:
    """Plain bounded integer literal (optionally unary-minus), else None."""
    n = _strip_parens(node)
    negative = False
    if n is not None and n.type == "unary_expression":
        op = n.child_by_field_name("operator")
        arg = n.child_by_field_name("argument")
        if op is None or _node_text(op) != "-" or arg is None:
            return None
        negative = True
        n = _strip_parens(arg)
    if n is None or n.type != "number_literal":
        return None
    text = _node_text(n)
    # tree-sitter-c lexes a comparison operand like ``-1`` as one
    # number_literal token with the sign fused in.
    if text.startswith("-"):
        negative = not negative
        text = text[1:]
    if _DEC_RE.fullmatch(text):
        value = int(text, 10)
    elif _HEX_RE.fullmatch(text):
        value = int(text, 16)
    else:
        return None  # suffixed / float / char forms are out of frame
    if negative:
        value = -value
    if not (-_MAX_LITERAL - 1 <= value <= _MAX_LITERAL):
        return None
    return value


class GuardContradictionOracle:
    """Per-function oracle; admission facts are computed lazily."""

    def __init__(
        self,
        fn_node: Any,
        *,
        locals_: frozenset[str],
        params: frozenset[str],
        params_admissible: bool,
        macro_names: frozenset[str],
    ) -> None:
        self._fn = fn_node
        self._body = fn_node.child_by_field_name("body")
        self._locals = locals_
        self._params = params
        self._params_admissible = params_admissible
        self._macro_names = macro_names
        self._param_list = self._find_parameter_list()
        #: name -> "signed" | "unsigned" | None (refused), memoised.
        self._admission: dict[str, str | None] = {}
        self._enabled = self._body is not None and not any(
            n.type in _JUMP_STMTS for n in _walk_nodes(self._body)
        )

    # -- structure ---------------------------------------------------------

    def _find_parameter_list(self) -> Any | None:
        d = self._fn.child_by_field_name("declarator")
        for _ in range(16):
            if d is None:
                return None
            if d.type == "function_declarator":
                return d.child_by_field_name("parameters")
            if d.type in _DECLARATOR_WRAPPERS:
                d = d.child_by_field_name("declarator") or (
                    d.named_children[0] if d.named_children else None
                )
                continue
            return None
        return None

    def _governors(self, node: Any) -> list[tuple[Any, bool]] | None:
        """(condition, polarity) for every ``if`` enclosing *node*.

        None when the parent chain carries a construct the climb does
        not model — the caller must not prune.
        """
        govs: list[tuple[Any, bool]] = []
        cur = node
        for _ in range(_MAX_CLIMB):
            if cur is None or cur == self._body:
                return govs
            parent = cur.parent
            if parent is None:
                return None
            if parent.type == "if_statement":
                cond = parent.child_by_field_name("condition")
                if cur == parent.child_by_field_name("consequence"):
                    if cond is None:
                        return None
                    govs.append((cond, True))
                elif cur == parent.child_by_field_name("alternative"):
                    if cond is None:
                        return None
                    govs.append((cond, False))
                elif cur == cond:
                    pass  # the condition itself is not governed by it
                else:
                    return None
            elif parent.type == "else_clause":
                grand = parent.parent
                if (
                    grand is None or grand.type != "if_statement"
                    or grand.child_by_field_name("alternative") != parent
                ):
                    return None
                cond = grand.child_by_field_name("condition")
                if cond is None:
                    return None
                govs.append((cond, False))
                cur = grand
                continue
            elif parent.type not in _CLIMB_INERT and parent != self._body:
                # Expression-level parents (the climb may start at an
                # identifier occurrence) are inert; statement-level
                # parents must be explicitly modeled.
                if parent.type.endswith("_statement"):
                    return None
            cur = parent
        return None

    # -- identifier admission ------------------------------------------------

    def _signedness(self, name: str) -> str | None:
        if name in self._admission:
            return self._admission[name]
        verdict = self._derive_signedness(name)
        self._admission[name] = verdict
        return verdict

    def _derive_signedness(self, name: str) -> str | None:
        if name in self._macro_names:
            return None
        if name not in self._locals and name not in self._params:
            return None
        declaring: list[Any] = []
        scopes = [self._body]
        if self._param_list is not None:
            scopes.append(self._param_list)
        for scope in scopes:
            for n in _walk_nodes(scope):
                if n.type == "init_declarator":
                    ident = _resolve_declarator(
                        n.child_by_field_name("declarator"),
                    )
                    if ident is not None and _node_text(ident) == name:
                        declaring.append(n)
                elif n.type == "parameter_declaration":
                    ident = _resolve_declarator(
                        n.child_by_field_name("declarator"),
                    )
                    if ident is not None and _node_text(ident) == name:
                        declaring.append(n)
                elif n.type == "declaration":
                    type_node = n.child_by_field_name("type")
                    for child in n.named_children:
                        if child == type_node or child.type in (
                            "init_declarator", "comment",
                        ):
                            continue
                        ident = _resolve_declarator(child)
                        if ident is not None and _node_text(ident) == name:
                            declaring.append(child)
        if len(declaring) != 1:
            return None  # undeclared here, or shadowed — ambiguous
        decl = declaring[0]
        if decl.type == "parameter_declaration":
            if not self._params_admissible:
                return None
            if decl.parent != self._param_list:
                return None  # a function-pointer type's inner parameter
            inner = decl.child_by_field_name("declarator")
            if inner is None or inner.type != "identifier":
                return None  # pointer/array parameter — not a scalar
            holder = decl
        elif decl.type == "init_declarator":
            inner = decl.child_by_field_name("declarator")
            if inner is None or inner.type != "identifier":
                return None  # pointer/array declarator — not a scalar
            if decl.child_by_field_name("value") is None:
                return None  # uninitialised local — reads are undefined
            holder = decl.parent
            if holder is None or holder.type != "declaration":
                return None
            if self._inside_loop(holder):
                return None  # re-initialised per iteration
        else:
            return None  # bare (uninitialised) local declarator
        verdict = self._type_signedness(holder)
        if verdict is None:
            return None
        if not self._never_written(name):
            return None
        return verdict

    def _type_signedness(self, holder: Any) -> str | None:
        """Keyword-only integer signedness of a declaration/parameter
        node, refusing unknown qualifiers, storage classes and any
        child shape outside the canonical form."""
        type_node = holder.child_by_field_name("type")
        if type_node is None or type_node.type not in (
            "primitive_type", "sized_type_specifier",
        ):
            return None
        words = set(_node_text(type_node).split())
        if not words or not words <= _TYPE_WORDS:
            return None
        if words & self._macro_names:
            return None
        for child in holder.named_children:
            if child == type_node or child.type in (
                "init_declarator", "identifier", "comment",
            ):
                continue
            if child.type == "type_qualifier" and \
                    _node_text(child) == "const":
                continue
            return None  # volatile/_Atomic/storage class/attributes
        return "unsigned" if "unsigned" in words else "signed"

    def _inside_loop(self, node: Any) -> bool:
        cur = node.parent
        for _ in range(_MAX_CLIMB):
            if cur is None or cur == self._body:
                return False
            if cur.type in _LOOP_STMTS:
                return True
            cur = cur.parent
        return True  # unbounded nesting — treat as unmodeled

    def _never_written(self, name: str) -> bool:
        for n in _walk_nodes(self._body):
            if n.type == "assignment_expression":
                left = _strip_parens(n.child_by_field_name("left"))
                if left is not None and left.type == "identifier" \
                        and _node_text(left) == name:
                    return False
            elif n.type == "update_expression":
                arg = _strip_parens(n.child_by_field_name("argument"))
                if arg is not None and arg.type == "identifier" \
                        and _node_text(arg) == name:
                    return False
            elif n.type == "pointer_expression":
                op = n.child_by_field_name("operator")
                arg = n.child_by_field_name("argument")
                if op is not None and _node_text(op) == "&" \
                        and arg is not None and any(
                            x.type == "identifier"
                            and _node_text(x) == name
                            for x in _walk_nodes(arg)
                        ):
                    return False  # address taken — aliased writes possible
        return True

    # -- encoding ------------------------------------------------------------

    def _var(self, name: str, state: dict[str, Any], z3: Any) -> Any:
        if name in state["vars"]:
            return state["vars"][name][0]
        signedness = self._signedness(name)
        if signedness is None:
            raise _Refuse(name)
        if len(state["vars"]) >= _MAX_IDENTS:
            raise _Refuse("too many identifiers")
        v = z3.Int(name)
        state["vars"][name] = (v, signedness)
        return v

    def _atom(self, state: dict[str, Any]) -> None:
        state["atoms"] += 1
        if state["atoms"] > _MAX_ATOMS:
            raise _Refuse("too many atoms")

    _REL_OPS = frozenset({"==", "!=", "<", "<=", ">", ">="})
    _REL_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=",
                 "==": "==", "!=": "!="}

    def _encode(self, node: Any, state: dict[str, Any], z3: Any) -> Any:
        n = _strip_parens(node)
        if n is None:
            raise _Refuse("empty expression")
        t = n.type
        if t == "unary_expression":
            op = n.child_by_field_name("operator")
            arg = n.child_by_field_name("argument")
            if op is None or arg is None or _node_text(op) != "!":
                raise _Refuse("unary operator")
            return z3.Not(self._encode(arg, state, z3))
        if t == "binary_expression":
            op_node = n.child_by_field_name("operator")
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if op_node is None or left is None or right is None:
                raise _Refuse("binary shape")
            op = _node_text(op_node)
            if op == "&&":
                return z3.And(self._encode(left, state, z3),
                              self._encode(right, state, z3))
            if op == "||":
                return z3.Or(self._encode(left, state, z3),
                             self._encode(right, state, z3))
            if op not in self._REL_OPS:
                raise _Refuse(f"operator {op}")
            lv = _literal_value(left)
            rv = _literal_value(right)
            ls = _strip_parens(left)
            rs = _strip_parens(right)
            if rv is not None and ls is not None \
                    and ls.type == "identifier":
                name, literal = _node_text(ls), rv
            elif lv is not None and rs is not None \
                    and rs.type == "identifier":
                name, literal = _node_text(rs), lv
                op = self._REL_FLIP[op]
            else:
                raise _Refuse("comparison operands")
            var = self._var(name, state, z3)
            if literal < 0 and state["vars"][name][1] == "unsigned":
                # The converted literal's value is width-dependent.
                raise _Refuse("negative literal against unsigned")
            self._atom(state)
            if op == "==":
                return var == literal
            if op == "!=":
                return var != literal
            if op == "<":
                return var < literal
            if op == "<=":
                return var <= literal
            if op == ">":
                return var > literal
            return var >= literal
        if t == "identifier":
            var = self._var(_node_text(n), state, z3)
            self._atom(state)
            return var != 0
        if t == "number_literal":
            value = _literal_value(n)
            if value is None:
                raise _Refuse("literal form")
            return z3.BoolVal(value != 0)
        raise _Refuse(f"expression form {t}")

    # -- the verdict -----------------------------------------------------------

    def contradicts(self, stmt_a: Any, node_b: Any) -> bool:
        """True ONLY when no single execution can perform both
        *stmt_a* and *node_b*'s statement, proven by the
        unsatisfiability of their conjoined governing conditions."""
        if not self._enabled:
            return False
        try:
            from core.smt_solver.availability import z3
            if z3 is None:
                return False
            from core.smt_solver.session import check_solver, new_solver
            govs_a = self._governors(stmt_a)
            govs_b = self._governors(node_b)
            if not govs_a or not govs_b:
                # Both statements must be guarded — an unguarded side
                # executes on every path through its region.
                return False
            state: dict[str, Any] = {"vars": {}, "atoms": 0}
            clauses = []
            for cond, polarity in govs_a + govs_b:
                encoded = self._encode(cond, state, z3)
                clauses.append(encoded if polarity else z3.Not(encoded))
            for v, signedness in state["vars"].values():
                if signedness == "unsigned":
                    clauses.append(v >= 0)
            solver = new_solver(timeout_ms=_SOLVER_TIMEOUT_MS)
            solver.add(*clauses)
            return check_solver(solver) == z3.unsat
        except _Refuse:
            return False
        except Exception:  # noqa: BLE001 — never let the oracle decide by crashing
            logger.debug("guard-contradiction oracle error", exc_info=True)
            return False

"""Per-function taint summaries — Phase 13 of the sanitizer-cut arc.

Sub-arc C's second substrate. Given a Python module's call graph
(Phase 12) and its source text, compute for each function a
:class:`TaintSummary` answering two questions Phase 14's gate
needs:

1. **Which of my params taint the return?** — and which catalog-
   recognized callable's arg the taint passed through on the way.
   This is the "sanitizer-in-helper" rescue: a function whose return
   is `html.escape(arg)` will report ``return_effects`` containing
   ``(0, "html.escape", 0)`` so a call to it can be treated as a
   synthetic sanitizer binding for CWE-79.
2. **Which of my params flow into which call's arg?** — for each
   call site's ``(callee, arg_idx)`` pair, the set of param indices
   whose taint reaches that arg.

The two pieces compose: when caller F calls helper H, and H's
summary says param 0 taints the return via ``html.escape``, then
in F the symbol ``y = H(x)`` carries the same effect chain back into
F's continuation.

Computation:

* Per-function fixed-point inside the function's intra-procedural
  CFG (reaching-defs lifted to track param origin + sanitizer
  effect chain).
* Outer fixed-point over the call graph for mutual recursion —
  reverse-dependency worklist (recompute a function only when a
  summary it joins changed), pop budget ``N + max(10, 3 × N)`` for
  ``N`` in-module functions. Budget exhaustion marks EVERY
  non-unknown summary ``summary_unconverged=True``.
* Dynamic dispatch (``getattr`` / ``setattr`` / ``eval`` / ``exec``
  / ``globals`` / ``locals`` / ``__import__`` / ``importlib.*`` /
  ``**kwargs`` forwarding) marks the function as
  ``summary_unknown``. Phase 14 will refuse to consume unknown
  summaries and conservatively downgrade.

Public surface:

* :class:`TaintSummary` — frozen, hashable; field set documented
  on the class.
* :func:`build_taint_summaries(callgraph, source) -> Dict[str,
  TaintSummary]` — keyed by qualified function name from the call
  graph.
"""
from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path

from core.analysis.cfg_builder import (
    PyCFGNode,
    _PythonCFGBuilder,
    _pattern_capture_names,
)
from core.analysis.dataflow import reaching_defs
from core.analysis.python_module_callgraph import (
    PyModuleCallGraph,
    local_binding_names,
)

# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


# Direct-return marker used in ``return_effects`` to denote "param
# taints return without passing through any callable" — distinct
# from "param doesn't taint return at all" (absence from the set).
_DIRECT_RETURN_CALLABLE = ""
_DIRECT_RETURN_ARG = -1

# Effect-chain arg position for taint that reaches a call through a
# keyword argument or through a position made unknowable by ``*``
# unpacking. Distinct from every real positional index (and from the
# ``_DIRECT_RETURN_ARG`` sentinel) so a consumer keying on positions
# can never mistake it for a concrete one; the callable name still
# joins the chain, so Phase 14's all-chain-callables-must-be-catalog-
# sanitizers rule stays in force for these atoms.
_OPAQUE_ARG = -2


@dataclass(frozen=True)
class TaintSummary:
    """Per-function taint flow summary.

    ``params`` is the ordered tuple of parameter names, matching
    :attr:`PythonCFG.params`. Indices into ``params`` are the
    identity used throughout the rest of the summary.

    ``return_effects`` is a frozenset of ``(param_idx,
    callable_name, arg_idx)`` triples — each triple says "the taint
    from this caller-param passed through this callable's arg on
    its way to the return value." The ``("", -1)`` sentinel pair
    means "param taints return directly, no callable in between."
    Absence of a ``param_idx`` from the set means that param does
    NOT taint return.

    Async functions also retain every parameter directly in the returned
    coroutine's frame. Body-return effects are conservatively unioned with
    that retention; they do not imply the body ran at coroutine creation.

    ``call_arg_taint`` is a frozenset of ``(callee_name, arg_idx,
    param_idx)`` triples — for each call site in this function,
    which of MY params, if tainted at the call, taints the arg at
    ``arg_idx``. ``callee_name`` is the dotted callable name as it
    appears in the CFG's :class:`CallSite.name`; both in-module
    and external callees are recorded.

    ``summary_unknown`` is True when the function has dynamic
    dispatch (see module docstring); Phase 14 treats unknown
    summaries as opaque and downgrades the verdict on affected
    paths. ``summary_unknown_reason`` carries the short tag (e.g.
    ``"calls getattr"``) for audit.

    ``summary_unconverged`` is True when the intra-function or call-graph
    iteration budget ends before stability is observed. Treated like
    ``summary_unknown`` by Phase 14.
    """
    function: str
    params: tuple[str, ...]
    return_effects: frozenset[tuple[int, str, int]] = frozenset()
    call_arg_taint: frozenset[tuple[str, int, int]] = frozenset()
    summary_unknown: bool = False
    summary_unknown_reason: str = ""
    summary_unconverged: bool = False
    # Positional-binding boundary: how many leading ``params`` slots a
    # call can fill BY POSITION (posonly + positional-or-keyword).
    # ``params`` lists the ``*vararg``, keyword-only, and ``**kwarg``
    # names as ordinary entries, so a positional arg at index >= this
    # boundary lands in the vararg tuple (or nowhere) — index-based
    # mapping through those slots mis-attributed flows (an
    # exact-params-length call to ``def h(a, *rest, key=...)`` mapped
    # its third arg onto ``key``). None = not computed (hand-built /
    # seed summaries): consumers fall back to the legacy full-length
    # mapping.
    positional_limit: int | None = None
    # Names a call can bind BY KEYWORD (positional-or-keyword +
    # keyword-only). Excludes posonly names and the vararg/kwarg slot
    # names — ``h(kw=1)`` against ``def h(**kw)`` lands INSIDE the kw
    # dict, not on the ``kw`` params slot. None = not computed.
    keyword_params: frozenset[str] | None = None

    # ----- query helpers -----

    def param_taints_return(self, param_idx: int) -> bool:
        """True iff param at index ``param_idx`` taints the return."""
        return any(eff[0] == param_idx for eff in self.return_effects)

    def return_sanitizers_for_param(
        self, param_idx: int,
    ) -> frozenset[tuple[str, int]]:
        """``(callable_name, arg_idx)`` pairs through which
        ``param_idx``'s taint passed on its way to the return.
        Excludes the direct-return sentinel — only callable
        callees appear in the result. Phase 14's
        sanitizer-in-helper rescue keys on this set."""
        return frozenset(
            (callable_name, arg_idx)
            for pi, callable_name, arg_idx in self.return_effects
            if pi == param_idx and callable_name
        )

    def params_tainting_call_arg(
        self, callee: str, arg_idx: int,
    ) -> frozenset[int]:
        """Param indices whose taint reaches the ``arg_idx``
        argument of any call to ``callee`` inside this function."""
        return frozenset(
            pi for c, ai, pi in self.call_arg_taint
            if c == callee and ai == arg_idx
        )

    # ----- LLM context rendering -----

    def _param_name(self, idx: int) -> str:
        if 0 <= idx < len(self.params):
            return self.params[idx]
        return f"arg{idx}"

    def format_for_context(self, depth: str = "full") -> str:
        """Render for LLM context injection.

        Same contract as
        :meth:`core.analysis.summaries.FunctionSummary.format_for_context`
        — the audit context renderer duck-types every callee summary on
        this method, so any summary type reaching
        ``ctx["callee_summaries"]`` must provide it.

        depth="oneline" — one-sentence summary.
        depth="full"    — bulleted taint facts; empty string when the
        summary carries nothing worth prompt space.
        """
        tainting = sorted({eff[0] for eff in self.return_effects})
        caveats: list[str] = []
        if self.summary_unknown:
            reason = (
                f" ({self.summary_unknown_reason})"
                if self.summary_unknown_reason else ""
            )
            caveats.append(f"summary unknown{reason}")
        if self.summary_unconverged:
            caveats.append("fixed-point unconverged")

        if depth == "oneline":
            parts: list[str] = []
            if tainting:
                names = ",".join(f"`{self._param_name(i)}`" for i in tainting)
                parts.append(f"params {names} taint return")
            if self.call_arg_taint:
                parts.append(
                    f"{len(self.call_arg_taint)} call-arg propagation(s)"
                )
            parts.extend(caveats)
            detail = "; ".join(parts) if parts else "no taint effects"
            return f"`{self.function}()`: {detail}."

        if not tainting and not self.call_arg_taint and not caveats:
            return ""

        lines = [f"### Taint summary: `{self.function}()`"]
        if tainting:
            lines.append("**Param → return taint:**")
            for i in tainting:
                vias = sorted({
                    c for pi, c, _a in self.return_effects
                    if pi == i and c
                })
                via = (
                    " via " + ", ".join(f"`{v}`" for v in vias)
                    if vias else ""
                )
                lines.append(
                    f"- `{self._param_name(i)}` taints the return value{via}"
                )
        if self.call_arg_taint:
            lines.append("**Param → callee-arg taint:**")
            shown = sorted(self.call_arg_taint)[:10]
            for callee, arg_idx, pi in shown:
                lines.append(
                    f"- `{self._param_name(pi)}` → `{callee}()` "
                    f"arg #{arg_idx}"
                )
            more = len(self.call_arg_taint) - len(shown)
            if more > 0:
                lines.append(f"- (+{more} more propagation(s))")
        for c in caveats:
            lines.append(f"- caveat: {c}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dynamic-dispatch detection — ``summary_unknown``
# ---------------------------------------------------------------------------


_UNKNOWN_CALLABLES = frozenset({
    "getattr", "setattr", "delattr", "hasattr",
    "eval", "exec", "compile",
    "globals", "locals", "vars",
    "__import__",
    "importlib.import_module", "importlib.util.find_spec",
})


def _comprehension_writes_enclosing_frame(
    node: ast.GeneratorExp | ast.ListComp | ast.SetComp | ast.DictComp,
) -> bool:
    """Iteration can skip payloads, filters and later iterable expressions."""
    roots: list[ast.AST] = (
        [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
    )
    for index, generator in enumerate(node.generators):
        if index:
            roots.append(generator.iter)
        roots.extend(generator.ifs)
    return _expression_roots_write_enclosing_frame(roots)


def _expression_roots_write_enclosing_frame(roots: list[ast.AST]) -> bool:
    pending = list(roots)
    while pending:
        child = pending.pop()
        if isinstance(child, ast.NamedExpr):
            return True
        if isinstance(child, ast.Lambda):
            # Defaults run in the surrounding frame; the body owns a
            # separate local binding even when that body has a walrus.
            pending.extend(child.args.defaults)
            pending.extend(d for d in child.args.kw_defaults if d is not None)
            continue
        pending.extend(ast.iter_child_nodes(child))
    return False


def _deferred_frame_summary_reason(fn_ast: ast.AST) -> str | None:
    """Visit this frame, including defaults of nested definitions."""
    if not isinstance(fn_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None  # Synthetic lambda entries use the existing shape refusal.
    frame_bindings: frozenset[str] | None = None
    pending: list[ast.AST] = list(fn_ast.body)
    while pending:
        node = pending.pop()
        if (isinstance(node, ast.Return) and isinstance(node.value, ast.Lambda)
                and isinstance(node.value.body, ast.Name)):
            name = node.value.body.id
            # This exact bare-name body has no comprehension or nested scope.
            # Defaults are snapshots, but an outer local here is a live cell.
            if frame_bindings is None:
                frame_bindings = local_binding_names(fn_ast)
            if (name in frame_bindings
                    and name not in local_binding_names(node.value)):
                return "returned lambda retains an unmodelled enclosing cell"
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pending.extend(node.args.defaults)
            pending.extend(d for d in node.args.kw_defaults if d is not None)
            if not isinstance(node, ast.Lambda):
                pending.extend(node.decorator_list)
            continue
        if isinstance(node, ast.ClassDef):
            return "class namespace value transfer is not modelled"
        if isinstance(node, ast.match_case) and _pattern_capture_names(node.pattern):
            return "pattern capture value transfer is not modelled"
        if hasattr(ast, "TypeAlias") and isinstance(node, ast.TypeAlias):
            return "type alias deferred values are not modelled"
        if isinstance(node, ast.ExceptHandler) and node.name is not None:
            return "caught exception payload is not modelled"
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return "generator iteration outputs are not modelled"
        if isinstance(node, ast.GeneratorExp) and _comprehension_writes_enclosing_frame(node):
            return "generator defers an enclosing-frame assignment"
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            if _comprehension_writes_enclosing_frame(node):
                return "comprehension conditionally assigns an enclosing-frame name"
        if isinstance(node, ast.Assert) and node.msg is not None:
            if _expression_roots_write_enclosing_frame([node.msg]):
                return "assertion message conditionally assigns an enclosing-frame name"
        if isinstance(node, ast.IfExp):
            if _expression_roots_write_enclosing_frame([node.body, node.orelse]):
                return "expression conditionally assigns an enclosing-frame name"
        if isinstance(node, ast.BoolOp):
            if _expression_roots_write_enclosing_frame(node.values[1:]):
                return "expression conditionally assigns an enclosing-frame name"
        if isinstance(node, ast.Compare):
            if _expression_roots_write_enclosing_frame(node.comparators[1:]):
                return "expression conditionally assigns an enclosing-frame name"
        pending.extend(ast.iter_child_nodes(node))
    return None


def _scope_free_expression_nodes() -> tuple[type[ast.AST], ...]:
    """Shared expression grammar, with optional AST classes discovered locally."""
    return (
        ast.Name, ast.Constant, ast.Attribute, ast.Subscript, ast.Slice,
        ast.UnaryOp, ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp,
        ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Call, ast.keyword,
        ast.JoinedStr, ast.FormattedValue,
        # Optional on Python 3.12/3.13; Constant is already admitted.
        getattr(ast, "TemplateStr", ast.Constant),
        getattr(ast, "Interpolation", ast.Constant),
        ast.Starred, ast.Load, ast.operator, ast.unaryop, ast.boolop, ast.cmpop,
    )


def _scope_free_expression_loads(expr: ast.expr | None) -> frozenset[str]:
    """Loaded names in a bounded expression grammar with no nested scope or binder.

    Unsupported shapes contribute nothing here; the existing direct-base cell
    check remains independent. This is not a general free-variable analysis.
    """
    if expr is None:
        return frozenset()
    allowed = _scope_free_expression_nodes()
    names: set[str] = set()
    for node in ast.walk(expr):
        if not isinstance(node, allowed):
            return frozenset()
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            names.add(node.id)
    return frozenset(names)


def _comprehension_target_parts(
    target: ast.AST, *, allow_indirect_stores: bool = True,
) -> tuple[frozenset[str], tuple[ast.expr, ...]] | None:
    """Bare target bindings and read expressions, without entering their scopes."""
    names: set[str] = set()
    parts: list[ast.expr] = []
    pending = [target]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Starred):
            pending.append(node.value)
        elif isinstance(node, (ast.Tuple, ast.List)):
            pending.extend(node.elts)
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            if not allow_indirect_stores:
                return None
            parts.append(node.value)
            if isinstance(node, ast.Subscript):
                parts.append(node.slice)
        else:
            return None
    return frozenset(names), tuple(parts)


def _comprehension_target_scope(
    target: ast.AST,
    *,
    allow_indirect_stores: bool = True,
    require_scope_free_reads: bool = False,
) -> tuple[frozenset[str], frozenset[str]] | None:
    """Bare bindings and known scope-free reads for supported target stores.

    Attribute/subscript bases and indices are reads, not bindings. Unsupported
    read expressions contribute nothing here; this does not certify absence.
    Strict consumers require every part to fit the scope-free grammar.
    """
    scope = _comprehension_target_parts(target, allow_indirect_stores=allow_indirect_stores)
    if scope is None:
        return None
    allowed = _scope_free_expression_nodes() if require_scope_free_reads else ()
    reads: set[str] = set()
    for part in scope[1]:
        if require_scope_free_reads and not all(isinstance(node, allowed) for node in ast.walk(part)):
            return None
        reads.update(_scope_free_expression_loads(part))
    return scope[0], frozenset(reads)


def _validated_expression_targets(
    expression: ast.expr | None,
    *,
    target_read: bool = False,
) -> dict[ast.AST, tuple[frozenset[str], tuple[ast.expr, ...]]] | None:
    """Validate once, retaining target parts for the scoped read traversal.

    Target address expressions have their own closed grammar. The flag
    follows all descendants, including nested comprehension scopes. Writes
    and yield operands must belong to a lambda body. Defaults keep the
    ownership of their enclosing frame.
    """
    targets: dict[ast.AST, tuple[frozenset[str], tuple[ast.expr, ...]]] = {}
    if expression is None:
        return targets
    allowed = (*_scope_free_expression_nodes(), ast.Lambda, ast.arguments, ast.arg,
               ast.Store, ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom)
    pending: list[tuple[ast.AST, bool, bool]] = [(expression, target_read, False)]
    while pending:
        node, target_read, lambda_body = pending.pop()
        if (target_read and isinstance(node, (ast.NamedExpr, ast.Yield, ast.YieldFrom))
                and not lambda_body):
            return None
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            if not node.generators:
                return None
            for gen in node.generators:
                scope = _comprehension_target_parts(gen.target)
                if scope is None:
                    return None
                targets[gen.target] = scope
                pending.extend((part, True, lambda_body) for part in scope[1])
                pending.append((gen.iter, target_read, lambda_body))
                pending.extend((condition, target_read, lambda_body) for condition in gen.ifs)
            payload = (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
            pending.extend((part, target_read, lambda_body) for part in payload)
        else:
            if not isinstance(node, allowed):
                return None
            if isinstance(node, ast.NamedExpr) and not isinstance(node.target, ast.Name):
                return None
            for child in ast.iter_child_nodes(node):
                # Lambda defaults stay in the enclosing frame; only its body
                # owns assignment-expression bindings.
                child_lambda_body = lambda_body or isinstance(node, ast.Lambda) and child is node.body
                pending.append((child, target_read, child_lambda_body))
    return targets


def _lambda_body_bindings(body: ast.expr) -> frozenset[str] | None:
    """Assignment-expression bindings owned by this lambda's body.

    Nested lambda bodies own their bindings; their defaults evaluate here.
    Comprehension assignment expressions bind the containing lambda scope.
    """
    names: set[str] = set()
    pending: list[ast.AST] = [body]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Lambda):
            pending.extend(node.args.defaults)
            pending.extend(d for d in node.args.kw_defaults if d is not None)
            continue
        if isinstance(node, ast.NamedExpr):
            if not isinstance(node.target, ast.Name):
                return None
            names.add(node.target.id)
        pending.extend(ast.iter_child_nodes(node))
    return frozenset(names)


@dataclass(frozen=True, slots=True)
class _ExpressionScopeEvent:
    bindings: frozenset[str]
    enter: bool
    reads: frozenset[str] = frozenset()


def _scoped_expression_loads(expr: ast.expr | None) -> frozenset[str]:
    """Known reads through bounded lambda/comprehension scopes.

    Binding counts represent active lexical scopes without copying ancestor
    sets. All state is local to this invocation, including aborted scans.
    Unsupported nodes never certify absence; existing refusals stay active.
    """
    if expr is None:
        return frozenset()
    targets = _validated_expression_targets(expr)
    if targets is None:
        return frozenset()
    allowed = _scope_free_expression_nodes()
    names: set[str] = set()
    bound: dict[str, int] = {}
    pending: list[ast.AST | _ExpressionScopeEvent] = [expr]
    while pending:
        item = pending.pop()
        if isinstance(item, _ExpressionScopeEvent):
            if item.enter:
                for name in item.bindings:
                    bound[name] = bound.get(name, 0) + 1
                names.update(name for name in item.reads if name not in bound)
            else:
                for name in item.bindings:
                    count = bound[name] - 1
                    if count:
                        bound[name] = count
                    else:
                        del bound[name]
            continue
        node = item
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load) and node.id not in bound:
                names.add(node.id)
        elif isinstance(node, ast.Lambda):
            args = node.args
            parameters = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
            parameters.update(a.arg for a in (args.vararg, args.kwarg) if a is not None)
            pending.extend(d for d in (*args.defaults, *args.kw_defaults) if d is not None)
            local = _lambda_body_bindings(node.body)
            if local is None:
                return frozenset()
            bindings = frozenset(parameters | local)
            # Preserve body-before-default traversal while restoring the
            # surrounding scope before defaults are visited.
            pending.extend((_ExpressionScopeEvent(bindings, False), node.body,
                            _ExpressionScopeEvent(bindings, True)))
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            if not node.generators:
                return frozenset()
            scopes = [
                targets[gen.target]
                for gen in node.generators
            ]
            if any(scope is None for scope in scopes):
                return frozenset()
            bindings = frozenset(name for scope in scopes if scope is not None for name in scope[0])
            read_parts = [part for scope in scopes if scope is not None for part in scope[1]]
            pending.append(node.generators[0].iter)
            pending.append(_ExpressionScopeEvent(bindings, False))
            for index, gen in enumerate(node.generators):
                if index:
                    pending.append(gen.iter)
                pending.extend(gen.ifs)
            payload = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            pending.extend(payload)
            pending.extend(read_parts)
            pending.append(_ExpressionScopeEvent(bindings, True))
        elif isinstance(node, ast.Await):
            pending.append(node.value)
        elif isinstance(node, (ast.Yield, ast.YieldFrom)):
            if node.value is not None:
                pending.append(node.value)
        elif isinstance(node, ast.NamedExpr):
            if not isinstance(node.target, ast.Name):
                return frozenset()
            pending.append(node.value)
        elif isinstance(node, allowed):
            pending.extend(ast.iter_child_nodes(node))
        else:
            return frozenset()
    return frozenset(names)


def _child_expression_is_supported(expression: ast.expr | None) -> bool:
    """Closed child-expression grammar with complete comprehension targets."""
    return _validated_expression_targets(expression) is not None


def _scoped_statement_target_scope(
    target: ast.AST,
) -> tuple[frozenset[str], frozenset[str]] | None:
    """Read target addresses in the current frame, keeping own binders separate."""
    scope = _comprehension_target_parts(target)
    if scope is None:
        return None
    if any(_validated_expression_targets(part, target_read=True) is None for part in scope[1]):
        return None
    names: set[str] = set()
    for part in scope[1]:
        names.update(_scoped_expression_loads(part))
    return scope[0], frozenset(names)


def _match_literal_expression(expression: ast.expr) -> bool:
    """Recognise literal AST shapes without evaluating numeric expressions."""
    if isinstance(expression, ast.Constant):
        return True
    if isinstance(expression, ast.UnaryOp):
        return (isinstance(expression.op, ast.USub)
                and isinstance(expression.operand, ast.Constant)
                and type(expression.operand.value) in (int, float, complex))
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, (ast.Add, ast.Sub)):
        left = expression.left
        if isinstance(left, ast.UnaryOp) and isinstance(left.op, ast.USub):
            left = left.operand
        return (isinstance(left, ast.Constant) and type(left.value) in (int, float)
                and isinstance(expression.right, ast.Constant)
                and type(expression.right.value) is complex)
    return False


def _noncapturing_match_pattern_loads(pattern: ast.pattern) -> frozenset[str] | None:
    """Known lexical pattern reads, or None for a shape outside the closed grammar."""
    expressions: list[ast.expr] = []
    pending = [(pattern, False)]
    while pending:
        current, in_sequence = pending.pop()
        if isinstance(current, ast.MatchClass):
            if (_attribute_chain_str(current.cls) is None
                    or len(current.kwd_attrs) != len(current.kwd_patterns)):
                return None
            expressions.append(current.cls)
            pending.extend((child, False) for child in current.patterns)
            pending.extend((child, False) for child in current.kwd_patterns)
        elif isinstance(current, ast.MatchOr):
            if not current.patterns:
                return None
            pending.extend((child, False) for child in current.patterns)
        elif isinstance(current, ast.MatchMapping):
            if current.rest is not None or len(current.keys) != len(current.patterns):
                return None
            for key in current.keys:
                if _match_literal_expression(key):
                    continue
                if not isinstance(key, ast.Attribute) or _attribute_chain_str(key) is None:
                    return None
                expressions.append(key)
            pending.extend((child, False) for child in current.patterns)
        elif isinstance(current, ast.MatchSequence):
            pending.extend((child, True) for child in current.patterns)
        elif isinstance(current, ast.MatchValue):
            if _match_literal_expression(current.value):
                continue
            if not isinstance(current.value, ast.Attribute) or _attribute_chain_str(current.value) is None:
                return None
            expressions.append(current.value)
        elif isinstance(current, ast.MatchStar):
            if not in_sequence or current.name is not None:
                return None
        elif not (isinstance(current, ast.MatchAs)
                  and current.pattern is None and current.name is None
                  or isinstance(current, ast.MatchSingleton)):
            return None
    names: set[str] = set()
    for expression in expressions:
        names.update(_scope_free_expression_loads(expression))
    return frozenset(names)


def _literal_header_annotation(annotation: ast.expr | None) -> bool:
    """Closed, name-free literal/container annotations; never evaluate values."""
    if annotation is None:
        return True
    pending: list[ast.expr] = [annotation]
    while pending:
        node = pending.pop()
        if _match_literal_expression(node):
            continue
        if isinstance(node, (ast.Tuple, ast.List)):
            if not isinstance(node.ctx, ast.Load):
                return False
            pending.extend(node.elts)
        elif isinstance(node, ast.Set):
            pending.extend(node.elts)
        elif isinstance(node, ast.Dict):
            if len(node.keys) != len(node.values) or any(key is None for key in node.keys):
                return False
            pending.extend(key for key in node.keys if key is not None)
            pending.extend(node.values)
        else:
            return False
    return True


def _bounded_child_body_expression_loads(body: list[ast.stmt]) -> frozenset[str] | None:
    """Known lexical reads through a closed child grammar and nested function scopes."""
    if not body:
        return None
    operations: list[ast.expr | _ExpressionScopeEvent | None] = []
    pending: list[ast.stmt | _ExpressionScopeEvent] = list(reversed(body))
    while pending:
        statement = pending.pop()
        if isinstance(statement, _ExpressionScopeEvent):
            operations.append(statement)
            continue
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not statement.body:
                return None
            child_body = statement.body
            if (child_body and isinstance(child_body[0], ast.Expr)
                    and isinstance(child_body[0].value, ast.Constant)
                    and isinstance(child_body[0].value.value, str)):
                child_body = child_body[1:]
            args = statement.args
            parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
            parameters.extend(arg for arg in (args.vararg, args.kwarg) if arg is not None)
            if (statement.type_params
                    or not _literal_header_annotation(statement.returns)
                    or any(not _literal_header_annotation(parameter.annotation)
                           for parameter in parameters)):
                return None
            # Decorators and defaults run before child bindings are entered.
            operations.extend(statement.decorator_list)
            operations.extend(args.defaults)
            operations.extend(default for default in args.kw_defaults if default is not None)
            bindings = local_binding_names(statement)
            pending.append(_ExpressionScopeEvent(bindings, False))
            pending.extend(reversed(child_body))
            pending.append(_ExpressionScopeEvent(bindings, True))
        elif isinstance(statement, (ast.Expr, ast.Return)):
            operations.append(statement.value)
        elif isinstance(statement, ast.Raise):
            operations.extend((statement.exc, statement.cause))
        elif isinstance(statement, ast.Assert):
            operations.extend((statement.test, statement.msg))
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            if (any(alias.name == "*" for alias in statement.names)
                    or isinstance(statement, ast.ImportFrom) and statement.module == "__future__"):
                return None
            # Import names bind in the child; they are not expression reads.
            # This lexical scan supplies no authority about import effects.
        elif isinstance(statement, ast.Match):
            pattern_reads = [_noncapturing_match_pattern_loads(case.pattern) for case in statement.cases]
            if not statement.cases or any(reads is None for reads in pattern_reads):
                return None
            for reads in pattern_reads:
                if reads is not None:
                    operations.append(_ExpressionScopeEvent(frozenset(), True, reads))
            operations.append(statement.subject)
            for case in reversed(statement.cases):
                operations.append(case.guard)
                pending.extend(reversed(case.body))
        elif isinstance(statement, (ast.Try, ast.TryStar)):
            if any(handler.name is not None for handler in statement.handlers):
                return None
            pending.extend(reversed(statement.finalbody))
            pending.extend(reversed(statement.orelse))
            for handler in reversed(statement.handlers):
                operations.append(handler.type)
                pending.extend(reversed(handler.body))
            pending.extend(reversed(statement.body))
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                operations.append(item.context_expr)
                if item.optional_vars is not None:
                    scope = _scoped_statement_target_scope(item.optional_vars)
                    if scope is None:
                        return None
                    operations.append(_ExpressionScopeEvent(frozenset(), True, scope[1]))
            pending.extend(reversed(statement.body))
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                scope = _scoped_statement_target_scope(target)
                if scope is None:
                    return None
                operations.append(_ExpressionScopeEvent(frozenset(), True, scope[1]))
        elif isinstance(statement, (ast.If, ast.While)):
            operations.append(statement.test)
            pending.extend(reversed(statement.orelse))
            pending.extend(reversed(statement.body))
        elif isinstance(statement, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.For, ast.AsyncFor)):
            if isinstance(statement, ast.AnnAssign) and not isinstance(
                statement.annotation, (ast.Name, ast.Constant)
            ):
                return None
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                scope = _scoped_statement_target_scope(target)
                if scope is None:
                    return None
                operations.append(_ExpressionScopeEvent(frozenset(), True, scope[1]))
            if isinstance(statement, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                operations.append(statement.value)
            else:
                operations.append(statement.iter)
                pending.extend(reversed(statement.orelse))
                pending.extend(reversed(statement.body))
        elif not isinstance(statement, (ast.Pass, ast.Break, ast.Continue)):
            return None
    if not all(isinstance(operation, _ExpressionScopeEvent)
               or _child_expression_is_supported(operation) for operation in operations):
        return None
    names: set[str] = set()
    bound: dict[str, int] = {}
    for operation in operations:
        if isinstance(operation, _ExpressionScopeEvent):
            if operation.enter:
                for name in operation.bindings:
                    bound[name] = bound.get(name, 0) + 1
                names.update(name for name in operation.reads if name not in bound)
            else:
                for name in operation.bindings:
                    count = bound[name] - 1
                    if count:
                        bound[name] = count
                    else:
                        del bound[name]
        else:
            names.update(name for name in _scoped_expression_loads(operation) if name not in bound)
    return frozenset(names)


def _bounded_body_expression_loads(body: list[ast.stmt]) -> frozenset[str] | None:
    """Known reads in a bounded body grammar, or None for unsupported statements.

    Validate the complete statement grammar before inspecting expressions.
    Own-name binding and captured-cell identity are checked by the caller;
    this does not model assignment values or return-value flow.
    """
    expressions: list[ast.expr | None] = []
    target_reads: set[str] = set()
    pending = list(reversed(body))
    while pending:
        statement = pending.pop()
        if isinstance(statement, (ast.Expr, ast.Return)):
            expressions.append(statement.value)
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not statement.body:
                return None
            child_body = statement.body
            if (child_body and isinstance(child_body[0], ast.Expr)
                    and isinstance(child_body[0].value, ast.Constant)
                    and isinstance(child_body[0].value.value, str)):
                child_body = child_body[1:]
            args = statement.args
            parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
            if args.vararg is not None:
                parameters.append(args.vararg)
            if args.kwarg is not None:
                parameters.append(args.kwarg)
            if (statement.type_params
                    or not _literal_header_annotation(statement.returns)
                    or any(not _literal_header_annotation(parameter.annotation)
                           for parameter in parameters)):
                return None
            defaults = [*args.defaults, *(default for default in args.kw_defaults if default is not None)]
            header_reads = [*statement.decorator_list, *defaults]
            if not all(_child_expression_is_supported(expression) for expression in header_reads):
                return None
            # Header expressions belong to the defining frame, before child parameters.
            expressions.extend(header_reads)
            # A parsed docstring-only body has no remaining lexical reads.
            child_reads = (_bounded_child_body_expression_loads(child_body)
                           if child_body else frozenset())
            if child_reads is None:
                return None
            target_reads.update(child_reads - local_binding_names(statement))
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            if (any(alias.name == "*" for alias in statement.names)
                    or isinstance(statement, ast.ImportFrom) and statement.module == "__future__"):
                return None
            # Import names bind in the child; they are not expression reads.
            # This lexical scan supplies no authority about import effects.
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                scope = _scoped_statement_target_scope(target)
                if scope is None:
                    return None
                target_reads.update(scope[1])
        elif isinstance(statement, ast.Raise):
            expressions.extend([statement.exc, statement.cause])
        elif isinstance(statement, ast.Assert):
            expressions.extend([statement.test, statement.msg])
        elif isinstance(statement, (ast.If, ast.While)):
            expressions.append(statement.test)
            pending.extend(reversed(statement.orelse))
            pending.extend(reversed(statement.body))
        elif isinstance(statement, ast.Match):
            pattern_reads = [_noncapturing_match_pattern_loads(case.pattern) for case in statement.cases]
            if not statement.cases or any(reads is None for reads in pattern_reads):
                return None
            for reads in pattern_reads:
                if reads is not None:
                    target_reads.update(reads)
            expressions.append(statement.subject)
            for case in reversed(statement.cases):
                expressions.append(case.guard)
                pending.extend(reversed(case.body))
        elif isinstance(statement, (ast.Try, ast.TryStar)):
            if any(handler.name is not None for handler in statement.handlers):
                return None
            pending.extend(reversed(statement.finalbody))
            pending.extend(reversed(statement.orelse))
            for handler in reversed(statement.handlers):
                expressions.append(handler.type)
                pending.extend(reversed(handler.body))
            pending.extend(reversed(statement.body))
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                expressions.append(item.context_expr)
                if item.optional_vars is not None:
                    scope = _scoped_statement_target_scope(item.optional_vars)
                    if scope is None:
                        return None
                    target_reads.update(scope[1])
            pending.extend(reversed(statement.body))
        elif isinstance(statement, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.For, ast.AsyncFor)):
            if isinstance(statement, ast.AnnAssign) and not isinstance(
                statement.annotation, (ast.Name, ast.Constant)
            ):
                return None
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                scope = _scoped_statement_target_scope(target)
                if scope is None:
                    return None
                # These stores share the function scope; the caller masks all
                # own bindings rather than creating a target-local scope here.
                target_reads.update(scope[1])
            if isinstance(statement, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                expressions.append(statement.value)
            else:
                expressions.append(statement.iter)
                pending.extend(reversed(statement.orelse))
                pending.extend(reversed(statement.body))
        elif not isinstance(statement, (ast.Pass, ast.Break, ast.Continue)):
            return None
    names = target_reads
    for expression in expressions:
        names.update(_scoped_expression_loads(expression))
    return frozenset(names)


def _detect_summary_unknown(fn_ast: ast.AST) -> str | None:
    """Return a short reason string if the function should be marked
    ``summary_unknown``, otherwise None.

    Triggers:

    * Direct call to a name in :data:`_UNKNOWN_CALLABLES` (e.g.
      ``getattr(o, name)(...)``).
    * ``**kwargs`` forwarding — any call whose keyword args list
      contains a ``**`` expansion (``g(**kwargs)``). The expanded
      content can't be statically resolved.
    * An optional assignment expression in a conditional expression,
      short-circuit operand, chained comparison, assertion message or eager
      comprehension: it may not overwrite
      the incoming local value.
    * A local class definition: its executed namespace can retain input,
      but enclosing-frame propagation models only the definition header.
    * A directly returned lambda with a bare enclosing-local body: it
      retains a live cell, which default-value propagation does not model.
    * An immediately returned, undecorated, non-generic local function
      whose single return or bounded body reads an enclosing cell
      through supported expressions, lambdas or comprehensions,
      or a directly returned call to it: the object or call depends on a cell.
    * A capturing match pattern: subject-to-capture value transfer is
      not modelled by the def-only pattern nodes.
    * A type alias: later access can evaluate its deferred value, which
      ordinary local assignment propagation does not model.
    * A named exception handler: the caught object can carry input through
      an exceptional edge whose value transfer is not modelled.
    * A generator function: iteration output is not a normal return value.
    * A generator expression with a deferred assignment expression: its
      enclosing-frame writes depend on consumption, which is not modelled.
    * A ``global`` / ``nonlocal`` declaration — a name bound outside
      the local frame is not a local: any call between the tracked
      assignment and the return can rewrite it (module slot /
      enclosing closure), so the straight-line-locals premise the
      propagation runs on is void for the whole function.

    Only the FUNCTION's own body is checked — nested function
    definitions are summarised separately so their dynamic dispatch
    doesn't poison the outer summary.
    """
    deferred_reason = _deferred_frame_summary_reason(fn_ast)
    if deferred_reason is not None:
        return deferred_reason
    for node in ast.walk(fn_ast):
        if isinstance(node, ast.Nonlocal):
            # A nested def's ``nonlocal`` rebinds an ENCLOSING frame —
            # possibly this function's locals — behind the
            # straight-line-locals premise's back (``t = escape(s);
            # def f(): nonlocal t; t = s; f(); return t``), so it
            # poisons the summary from ANY nesting depth. The
            # function's own declaration poisons as before.
            kind = "nonlocal"
            return f"declares {kind} {', '.join(node.names)}"
        if isinstance(node, ast.Global):
            if _inside_nested_function(node, fn_ast):
                # A nested def's ``global`` binds the MODULE frame —
                # it cannot rewrite this function's locals (module
                # identities are poisoned separately via
                # rebound_names / distrusted_roots).
                continue
            return f"declares global {', '.join(node.names)}"
        if not isinstance(node, ast.Call):
            continue
        # Skip calls inside nested function definitions — those will
        # have their own summary entries.
        if _inside_nested_function(node, fn_ast):
            continue
        callee_name = _attribute_chain_str(node.func)
        if callee_name in _UNKNOWN_CALLABLES:
            return f"calls {callee_name}"
        for kw in node.keywords:
            if kw.arg is None:
                # ``**expr`` — opaque expansion
                return "forwards **kwargs"
    if isinstance(fn_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
        frame_bindings: frozenset[str] | None = None
        for definition, returned in zip(fn_ast.body, fn_ast.body[1:]):
            if (not isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef))
                    or definition.decorator_list or getattr(definition, "type_params", ())
                    or not isinstance(returned, ast.Return)):
                continue
            value = returned.value
            direct_call = False
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
                direct_call = True
                value = value.func
            if not isinstance(value, ast.Name) or value.id != definition.name:
                continue
            # Adjacency and no decorator avoid an intervening binding rewrite
            # or wrapper. Keep direct-base detection even when another part of
            # the expression lies outside the scope-free grammar.
            body = definition.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]
            if len(body) == 1 and isinstance(body[0], ast.Return):
                names = _scope_free_expression_loads(body[0].value)
                names |= _scoped_expression_loads(body[0].value)
                cell_read = body[0].value
                if isinstance(cell_read, ast.Lambda):
                    args = cell_read.args
                    parameters = {
                        arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
                    }
                    parameters.update(
                        arg.arg for arg in (args.vararg, args.kwarg) if arg is not None
                    )
                    # Defaults belong to this frame; only body reads are
                    # shadowed by the lambda's arguments. The bounded grammar
                    # still excludes additional binders and nested scopes.
                    for default in (*args.defaults, *args.kw_defaults):
                        names |= _scope_free_expression_loads(default)
                    names |= _scope_free_expression_loads(cell_read.body) - parameters
                if (isinstance(cell_read, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
                        and cell_read.generators):
                    # The first iterable evaluates in this function's frame,
                    # before comprehension targets bind in their own scope.
                    names |= _scope_free_expression_loads(cell_read.generators[0].iter)
                    target_scopes = [
                        _comprehension_target_scope(gen.target) for gen in cell_read.generators
                    ]
                    if all(scope is not None for scope in target_scopes):
                        targets = {
                            name for scope in target_scopes if scope is not None for name in scope[0]
                        }
                        for scope in target_scopes:
                            if scope is not None:
                                names |= scope[1] - targets
                        parts = ([cell_read.key, cell_read.value]
                                 if isinstance(cell_read, ast.DictComp) else [cell_read.elt])
                        for index, gen in enumerate(cell_read.generators):
                            parts.extend(gen.ifs)
                            if index:
                                parts.append(gen.iter)
                        # All targets bind throughout the comprehension scope,
                        # including reads preceding a later generator target.
                        for part in parts:
                            names |= _scope_free_expression_loads(part) - targets
                if isinstance(cell_read, (ast.Attribute, ast.Subscript)):
                    cell_read = cell_read.value
                if isinstance(cell_read, ast.Name):
                    names = names | {cell_read.id}
            else:
                body_names = _bounded_body_expression_loads(body)
                if body_names is None or not body_names:
                    continue
                names = body_names
            if frame_bindings is None:
                frame_bindings = local_binding_names(fn_ast)
            if names & (frame_bindings - local_binding_names(definition)):
                if direct_call:
                    return "returned local call depends on an unmodelled enclosing cell"
                return "returned function retains an unmodelled enclosing cell"
    return None


# Decorators that provably preserve the decorated function's
# call/return semantics for the taint questions the summary answers.
# EVERY other decorator replaces the module-table binding with an
# arbitrary wrapper object (``@nullify`` returning ``str`` swaps a
# clean sanitizer for a raw pass-through at import time), so a
# decorated def's summary must degrade to unknown — the name-keyed
# joins would otherwise certify the BODY of a function the runtime
# name no longer points at. Seed set only (<= 9 names per the vocab
# doctrine); kept deliberately small because an over-wide allowlist
# reopens the forge. ``@property`` is deliberately absent: a property
# is consumed as an attribute read, never as a call-shaped join, so
# degrading it costs nothing. Entries are TRUSTED IDENTITIES, not
# spellings: bare ``staticmethod`` / ``classmethod`` are builtins;
# everything else is checked AFTER resolving the written name through
# the module's import map (``from functools import lru_cache`` →
# ``functools.lru_cache``), and a root the module itself rebinds
# (``def staticmethod``, ``import evil as functools``) never matches.
_SEMANTICS_PRESERVING_DECORATORS = frozenset({
    "staticmethod", "classmethod",
    "abc.abstractmethod",
    "functools.wraps", "functools.lru_cache", "functools.cache",
    "typing.override",
})


def _poisoning_decorator(
    fn_ast: ast.AST,
    import_map: dict[str, str],
    distrusted_roots: frozenset[str],
) -> str | None:
    """Name of the first decorator that voids the summary's identity
    premise, or None when every decorator is a trusted
    semantics-preserving identity.

    The written name only counts when its root is not repo-rebound
    (``distrusted_roots``) and its import-resolved form is in the
    allowlist — trusting spellings let a repo define its own
    ``staticmethod`` (or ``import evil as functools``) and keep a
    swapped-out def certified."""
    for dec in getattr(fn_ast, "decorator_list", ()) or ():
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = _attribute_chain_str(target)
        if name is None:
            return "<complex decorator>"
        root = name.split(".", 1)[0]
        if root in distrusted_roots:
            return name
        resolved = name
        mapped = import_map.get(root)
        if mapped is not None:
            resolved = mapped + name[len(root):]
        if resolved not in _SEMANTICS_PRESERVING_DECORATORS:
            return name
    return None


def _inside_nested_function(
    target: ast.AST, root: ast.AST,
) -> bool:
    """True iff ``target`` lives inside a function def nested under
    ``root`` (and ``root`` itself is a function). Used to scope
    dynamic-dispatch detection to one function at a time."""
    # ast.walk yields a flat sequence — we need to find the path
    # from root to target. The easiest way is a recursive descent
    # tracking enclosing function defs.
    def _walk(node, depth):
        if node is target:
            return depth > 0
        is_fn = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.Lambda))
        new_depth = depth + 1 if is_fn and node is not root else depth
        for child in ast.iter_child_nodes(node):
            r = _walk(child, new_depth)
            if r is not None:
                return r
        return None
    found = _walk(root, 0)
    return bool(found)


def _attribute_chain_str(node: ast.AST) -> str | None:
    """Return the dotted name for an attribute chain over ``ast.Name``.
    Used for matching against the ``_UNKNOWN_CALLABLES`` set."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return None


# ---------------------------------------------------------------------------
# Per-function CFG-driven propagation
# ---------------------------------------------------------------------------


# TaintAtom: one contributing param + the chain of (callable,
# arg_idx) effects its taint has passed through so far. Effects are
# stored as a frozenset because order doesn't matter for Phase 14's
# "is this a sanitizer for CWE X" check — only presence does.
TaintAtom = tuple[int, frozenset[tuple[str, int]]]
# Per-symbol taint state at a CFG node IN: a frozenset of atoms.
TaintState = frozenset[TaintAtom]


def _empty_state() -> TaintState:
    return frozenset()


def _merge_states(a: TaintState, b: TaintState) -> TaintState:
    """Element-wise union. Non-empty effect chains of atoms sharing a
    param_idx merge into one union chain (over-approximation — Phase
    14 requires EVERY chain callable to be a catalog sanitizer, so a
    larger union can only make the consumer refuse, never suppress).

    The EMPTY chain is different: it is the direct-return sentinel
    ("this param reached here without passing through any callable"),
    and the consumer's soundness rests on it. Unioning it into a
    non-empty chain destroys it — ``return escape(x) + x`` would
    collapse the raw pass-through atom ``(0, {})`` into the sanitized
    atom ``(0, {(escape, 0)})``, minting a false clean-sanitizer
    wrapper that the enforced sanitizer-cut then consumes to suppress
    real findings. The empty chain is therefore ABSORBING: whenever
    any contributing atom for a param has an empty chain, the merged
    state keeps a distinct empty-chain atom for that param alongside
    the unioned non-empty chain.
    """
    if not a:
        return b
    if not b:
        return a
    by_param: dict[int, set[tuple[str, int]]] = {}
    direct: set[int] = set()
    for atom in a:
        if atom[1]:
            by_param.setdefault(atom[0], set()).update(atom[1])
        else:
            direct.add(atom[0])
    for atom in b:
        if atom[1]:
            by_param.setdefault(atom[0], set()).update(atom[1])
        else:
            direct.add(atom[0])
    merged: set[TaintAtom] = {
        (pi, frozenset(effects)) for pi, effects in by_param.items()
    }
    merged.update((pi, frozenset()) for pi in direct)
    return frozenset(merged)


def _add_effect(state: TaintState, callable_name: str, arg_idx: int) -> TaintState:
    """Append ``(callable_name, arg_idx)`` to every atom's effect chain.
    Used when symbol ``y`` is assigned from ``f(arg)`` and ``arg`` was
    tainted — every atom contributing taint to ``arg`` records that
    it passed through ``(f, arg_idx)``."""
    if not state:
        return state
    new_effect = (callable_name, arg_idx)
    return frozenset(
        (pi, effects | {new_effect}) for pi, effects in state
    )


def _expr_taint(
    expr: ast.AST | None,
    cfg_node: PyCFGNode,
    in_state_fn,
    summaries: dict[str, TaintSummary],
    local_bindings: frozenset[str] = frozenset(),
    distrusted_roots: frozenset[str] = frozenset(),
) -> TaintState:
    """Compute the :data:`TaintState` produced by evaluating an
    arbitrary expression at ``cfg_node``'s IN.

    ``local_bindings`` is the enclosing function's own bound-name set
    (:func:`core.analysis.python_module_callgraph.local_binding_names`).
    The Call arm refuses the name-keyed summary join whenever the
    callable's root name has ANY local definition — ``esc = str``
    before (or after: flow-insensitive) ``y = esc(x)`` makes the
    runtime callee the local binding, not the module table's ``esc``,
    so joining would copy a summary the call provably may not reach
    (a hostile repo mints a clean-sanitizer wrapper from exactly this
    collision). Refused joins stamp a ``<shadowed:…>`` callable at
    :data:`_OPAQUE_ARG`: the marker can never match a catalog
    sanitizer name, so the consumer refuses rather than suppresses.

    AST shapes handled:

    * ``Name`` — use the in-state of the bare symbol.
    * ``Attribute`` — base name's in-state (over-approximation;
      field-level distinctions aren't tracked).
    * ``Call`` — recursive walk on each arg (positional, keyword,
      and ``*``-starred), then map through the callee's summary if
      available (in-module) or stamp the callable's effect on each
      tainted arg (external). Positional ordering is taken from
      ``expr.args`` directly so ``helper(b, a)`` maps callee param
      0 → b, callee param 1 → a (the legacy ``sorted(arg_names)``
      convention was unreliable when actual positions disagree with
      lexicographic order). Keyword args map to the callee param of
      the same name when the summary is known; anything unmappable
      (``*`` unpacking shifts every later position, a keyword with
      no matching param) is stamped at :data:`_OPAQUE_ARG` so the
      taint survives with the callable on its chain instead of
      silently vanishing — a dropped atom reads as "param does not
      flow", which the sanitizer-cut consumer can turn into a false
      clean-wrapper binding that suppresses a real finding. A
      method call's RECEIVER (``recv.m(...)``) contributes its own
      taint the same way, stamped at :data:`_OPAQUE_ARG` — the
      receiver's value feeds the result exactly like an argument
      (``a.strip()`` carries ``a``'s taint), and the stamped
      callable is never a catalog sanitizer, so the consumer
      refuses rather than suppresses.
    * ``JoinedStr`` / ``FormattedValue`` — union of the interpolated
      expressions' taint (an f-string carries its inputs' taint).
    * ``BinOp`` / ``BoolOp`` / ``IfExp`` / ``UnaryOp`` —
      element-wise union (taint flows through arithmetic / boolean
      composition into the result).
    * ``Subscript`` / ``Starred`` / container literals (``List`` /
      ``Tuple`` / ``Set`` / ``Dict``) / comprehensions — union of
      the contained expressions' taint. Returning empty here erased
      real flows: ``return escape(a) + a[0]`` read as "a only
      reaches the return through escape", minting a false
      clean-sanitizer binding the enforced sanitizer-cut consumed
      to suppress real findings (the JoinedStr hazard restated on
      the element/container shapes).
    * Literals — return empty. Lambda objects retain default-value
      taint without evaluating their bodies or modelling live closure cells.
    """
    if expr is None:
        return _empty_state()
    if isinstance(expr, ast.Name):
        return in_state_fn(cfg_node, expr.id)
    if isinstance(expr, ast.Attribute):
        chain = _attribute_chain_str(expr)
        if chain is None:
            # Non-Name-rooted chain (``a[0].b``, ``f().b``): the base
            # expression's taint still flows into the attribute read —
            # returning empty dropped it (false clean-wrapper hazard).
            return _expr_taint(expr.value, cfg_node, in_state_fn,
                               summaries, local_bindings, distrusted_roots)
        base = chain.split(".", 1)[0]
        return in_state_fn(cfg_node, base)
    if isinstance(expr, ast.Call):
        callable_name = _attribute_chain_str(expr.func) or ""
        # Shadow guard: a local binding of the chain's ROOT name means
        # the runtime callee is the local object, not the module-table
        # (or catalog) entry the dotted name suggests. The summary
        # join below is refused and every stamp carries a
        # ``<shadowed:…>`` marker instead of the written name — a
        # marker can never match a catalog sanitizer, so downstream
        # certification refuses rather than suppresses.
        base_name = callable_name.split(".", 1)[0] if callable_name else ""
        shadowed = bool(base_name) and base_name in local_bindings
        # Module-scope distrust poisons the STAMP only (the written
        # name must never match a catalog identity — ``import fakelib
        # as html`` makes ``html.escape`` the repo's callable), never
        # the summary JOIN: an in-module helper's own def name is
        # distrusted by definition, and its join is guarded by the
        # rebound/unknown poisons instead.
        distrusted = bool(base_name) and base_name in distrusted_roots
        stamp_name = (
            f"<shadowed:{callable_name}>" if (shadowed or distrusted)
            else callable_name
        )
        # ``g(*xs)`` makes every later positional index unknowable —
        # taint still flows, but positions can't be trusted.
        has_starred = any(isinstance(a, ast.Starred) for a in expr.args)
        # Per-positional-arg taint states (a Starred contributes the
        # taint of its unpacked iterable).
        arg_states: list[TaintState] = [
            _expr_taint(
                a.value if isinstance(a, ast.Starred) else a,
                cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots,
            )
            for a in expr.args
        ]
        # Keyword args (``**expr`` expansion never reaches here — it
        # marks the whole function ``summary_unknown`` upstream).
        kw_states: list[tuple[str | None, TaintState]] = [
            (kw.arg, _expr_taint(kw.value, cfg_node, in_state_fn,
                                 summaries, local_bindings, distrusted_roots))
            for kw in expr.keywords
        ]
        # Method-call receiver: ``recv.m(...)`` evaluates ``recv`` and
        # its value feeds the result exactly like an argument.
        # Dropping it read ``return escape(a) + a.strip()`` as "a only
        # reaches the return through escape" — a false clean-sanitizer
        # binding on the enforced path. Stamp at _OPAQUE_ARG: the
        # stamped callable (``a.strip``, or the bare method name when
        # the chain doesn't bottom out at a Name) is never a catalog
        # sanitizer, so the consumer refuses rather than suppresses.
        recv_state = _empty_state()
        recv_stamp = stamp_name
        if isinstance(expr.func, ast.Name) and shadowed:
            # A local callable can carry input through its own value,
            # independently of explicit call arguments or method receivers.
            recv_state = in_state_fn(cfg_node, expr.func.id)
        if isinstance(expr.func, ast.Lambda):
            # IIFE: the lambda body evaluates NOW over enclosing-scope
            # names (``(lambda: a)()``), and parameter DEFAULTS
            # evaluate in the enclosing scope too (``(lambda z=a:
            # z)()`` carries a's taint through z). Unstamped direct
            # atoms — the consumer refuses, never suppresses.
            recv_state = _contained_name_states(
                expr.func.body, cfg_node, in_state_fn,
            )
            for dflt in (*expr.func.args.defaults,
                         *expr.func.args.kw_defaults):
                if dflt is not None:
                    recv_state = _merge_states(
                        recv_state, _contained_name_states(
                            dflt, cfg_node, in_state_fn,
                        ),
                    )
            recv_stamp = "<lambda>"
        if isinstance(expr.func, ast.Attribute):
            recv_state = _expr_taint(
                expr.func.value, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots,
            )
            recv_stamp = stamp_name or expr.func.attr
        elif not isinstance(expr.func, (ast.Name, ast.Lambda)):
            # Calling a computed value consumes that value, even with no
            # explicit arguments. Its written shape grants no catalogue identity.
            recv_state = _expr_taint(
                expr.func, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots,
            )
            recv_stamp = "<callable>"

        def _with_receiver(state: TaintState) -> TaintState:
            if not recv_state:
                return state
            return _merge_states(
                state, _add_effect(recv_state, recv_stamp, _OPAQUE_ARG),
            )

        callee = None if shadowed else summaries.get(callable_name)
        if (callee is not None and not callee.summary_unknown
                and not callee.summary_unconverged
                and not has_starred):
            # In-module callee with a known summary. Positional args
            # map by index — but only below the callee's
            # positional-binding boundary: at or past the ``*vararg``
            # slot the index no longer names the receiving parameter
            # (the arg lands in the tuple; the NEXT index would name a
            # keyword-only param a positional can never reach), so
            # those args go opaque instead. Keyword args map to the
            # callee param of the same name when that name is
            # keyword-bindable.
            pos_limit = callee.positional_limit
            if pos_limit is None:
                pos_limit = len(callee.params)
            indexed: dict[int, TaintState] = {
                i: st for i, st in enumerate(arg_states) if i < pos_limit
            }
            opaque: list[TaintState] = [
                st for i, st in enumerate(arg_states) if i >= pos_limit
            ]
            for kw_name, kw_state in kw_states:
                kw_bindable = (
                    kw_name in callee.keyword_params
                    if callee.keyword_params is not None
                    else kw_name in callee.params
                )
                if kw_name is not None and kw_bindable:
                    idx = callee.params.index(kw_name)
                    indexed[idx] = _merge_states(
                        indexed.get(idx, _empty_state()), kw_state,
                    )
                else:
                    opaque.append(kw_state)
            result = _empty_state()
            for pi_callee, c_callee, a_callee in callee.return_effects:
                arg_state = indexed.get(pi_callee, _empty_state())
                if not arg_state:
                    continue
                if c_callee == _DIRECT_RETURN_CALLABLE:
                    # Direct return — passthrough; no new effect.
                    result = _merge_states(result, arg_state)
                else:
                    stamped = _add_effect(arg_state, c_callee, a_callee)
                    result = _merge_states(result, stamped)
            # A keyword with no matching (keyword-bindable) callee
            # param, or a positional at/past the vararg boundary: the
            # summary can't say whether it reaches the return, so keep
            # the taint alive with the callee on its chain (an
            # in-module name is never a catalog sanitizer — the
            # consumer refuses rather than suppresses).
            for kw_state in opaque:
                if kw_state:
                    result = _merge_states(
                        result,
                        _add_effect(kw_state, callable_name, _OPAQUE_ARG),
                    )
            return _with_receiver(result)
        # External or unknown callee (or unknowable positions after
        # ``*`` unpacking). Each tainted arg contributes via the call
        # with its position stamped — opaque when unknowable.
        result = _empty_state()
        for arg_idx, arg_state in enumerate(arg_states):
            if not arg_state:
                continue
            idx = (
                _OPAQUE_ARG if (has_starred or shadowed or distrusted)
                else arg_idx
            )
            stamped = _add_effect(arg_state, stamp_name, idx)
            result = _merge_states(result, stamped)
        for _kw_name, kw_state in kw_states:
            if not kw_state:
                continue
            stamped = _add_effect(kw_state, stamp_name, _OPAQUE_ARG)
            result = _merge_states(result, stamped)
        return _with_receiver(result)
    if isinstance(expr, ast.JoinedStr):
        # f-string: taint flows from every interpolated expression
        # into the result. Returning empty here erased the flow — a
        # wrapper ending in ``return escape(a) + f"<{b}>"`` read as
        # "b does not taint return", minting a false clean-sanitizer
        # binding for calls like ``helper(x, x)``.
        out = _empty_state()
        for v in expr.values:
            if isinstance(v, ast.FormattedValue):
                # Recurse on the FormattedValue NODE (not just its
                # value) so nested format specs contribute too.
                out = _merge_states(
                    out, _expr_taint(v, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
                )
        return out
    if isinstance(expr, ast.FormattedValue):
        out = _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots)
        if expr.format_spec is not None:
            # ``f"{v:{width}}"`` — the format spec's interpolations
            # carry their inputs' taint into the rendered result.
            out = _merge_states(out, _expr_taint(
                expr.format_spec, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots,
            ))
        return out
    if isinstance(expr, ast.BinOp):
        return _merge_states(
            _expr_taint(expr.left, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
            _expr_taint(expr.right, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
        )
    if isinstance(expr, ast.BoolOp):
        out = _empty_state()
        for v in expr.values:
            out = _merge_states(
                out, _expr_taint(v, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
            )
        return out
    if isinstance(expr, ast.IfExp):
        return _merge_states(
            _expr_taint(expr.body, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
            _expr_taint(expr.orelse, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
        )
    if isinstance(expr, ast.UnaryOp):
        return _expr_taint(expr.operand, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots)
    # Element/container shapes: the contained expressions' taint flows
    # into the result (an element carries its container's taint, a
    # container carries its elements'). Unstamped — same
    # over-approximation as the Attribute case above; a surviving
    # direct atom makes the consumer refuse, never suppress.
    if isinstance(expr, ast.Subscript):
        return _merge_states(
            _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
            _expr_taint(expr.slice, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
        )
    if isinstance(expr, ast.Starred):
        return _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots)
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        out = _empty_state()
        for e in expr.elts:
            out = _merge_states(
                out, _expr_taint(e, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
            )
        return out
    if isinstance(expr, ast.Dict):
        out = _empty_state()
        for e in (*expr.keys, *expr.values):  # type: ignore[assignment]
            if e is not None:  # None key = ``**expr`` expansion's slot
                out = _merge_states(
                    out, _expr_taint(e, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
                )
        return out
    if isinstance(expr, ast.NamedExpr):
        # ``(t := v)`` evaluates to v — keep v's chains intact so a
        # walrus-wrapped sanitizer stays clean.
        return _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots)
    if isinstance(expr, ast.Await):
        return _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots)
    if isinstance(
        expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp),
    ):
        # Union over the element expression(s), every generator's
        # iterable, and the filter conditions. Comprehension targets
        # are locals with empty in-state; their taint arrives through
        # the iterables, which are included directly.
        parts: list[ast.AST] = (
            [expr.key, expr.value] if isinstance(expr, ast.DictComp)
            else [expr.elt]
        )
        for gen in expr.generators:
            parts.append(gen.iter)
            parts.extend(gen.ifs)
        out = _empty_state()
        for e in parts:  # type: ignore[assignment]
            out = _merge_states(
                out, _expr_taint(e, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots),
            )
        return out
    if isinstance(expr, ast.Lambda):
        # The object retains evaluated defaults; its body remains deferred.
        # Free closure cells are not creation-time values and need a
        # separate transfer model for later writes.
        state = _empty_state()
        for default in (*expr.args.defaults, *expr.args.kw_defaults):
            if default is not None:
                state = _merge_states(state, _expr_taint(
                    default, cfg_node, in_state_fn, summaries, local_bindings, distrusted_roots,
                ))
        # A callable object is not a sanitised default value itself.
        return _add_effect(state, "<lambda>", _OPAQUE_ARG)
    if isinstance(expr, ast.Constant):
        return _empty_state()
    # Conservative fallback for every OTHER expression kind (Compare,
    # Slice bounds, and any future node): union the in-states of all
    # contained Names, unstamped. Returning empty here DROPS real
    # flows — the dirty atom vanishes and _param_cleanly_sanitized
    # mints a false clean-sanitizer binding the enforced
    # sanitizer-cut consumes (the JoinedStr hazard, generalised).
    # Unstamped direct atoms only ever make the consumer refuse.
    return _contained_name_states(expr, cfg_node, in_state_fn)


def _contained_name_states(
    expr: ast.AST,
    cfg_node: PyCFGNode,
    in_state_fn,
) -> TaintState:
    """Union of the in-states of every ``ast.Name`` under ``expr`` —
    the refusal-direction over-approximation for expression shapes
    :func:`_expr_taint` has no structural model for."""
    out = _empty_state()
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Name):
            out = _merge_states(out, in_state_fn(cfg_node, sub.id))
    return out


def _find_assignment_value_at(
    fn_ast: ast.AST, lineno: int, target_name: str,
) -> tuple[ast.AST, bool] | None:
    """Find an ``Assign`` / ``AugAssign`` / ``AnnAssign`` /
    ``NamedExpr`` at ``lineno`` whose target is ``target_name``, and
    return ``(value_expression, is_augmented)``. None if not found.

    ``is_augmented`` distinguishes ``q += rhs`` from ``q = rhs``: an
    augmented assignment READS the target too (``q = q ⊕ rhs``), so
    the caller must union the target's own pre-assignment state with
    the RHS taint. Treating the RHS as the whole story erased
    established taint — ``q = tainted; q += "x"`` read q as clean
    afterwards, and the missing flow could mint a false
    clean-sanitizer binding downstream."""
    for node in ast.walk(fn_ast):
        if not hasattr(node, "lineno") or node.lineno != lineno:
            continue
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == target_name:
                    return node.value, False
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == target_name:
                return node.value, True
        elif isinstance(node, ast.AnnAssign):
            if (isinstance(node.target, ast.Name)
                    and node.target.id == target_name
                    and node.value is not None):
                return node.value, False
        elif (isinstance(node, ast.NamedExpr)
                and isinstance(node.target, ast.Name)
                and node.target.id == target_name):
            return node.value, False
    return None


def _build_assignment_value_map(
    fn_ast: ast.AST,
) -> dict[tuple[int, str], list[tuple[ast.AST, bool]]]:
    """One-shot ``(lineno, target_name) → [(value_expr, is_augmented),
    …]`` map over the whole function AST, EVERY match in
    ``ast.walk`` order.

    Same node shapes as :func:`_find_assignment_value_at` (which
    returns the first match only), but built ONCE — the per-function
    taint fixed-point queries an assignment per (node, symbol) per
    iteration, and a full ``ast.walk`` per query made the loop
    O(iterations × nodes × defs × AST-size).

    ALL matches are kept, not just the first: two writes to one name
    on ONE physical line (``t = html.escape(s); t = s``, ``t =
    html.escape(s); t += s``) collide on the ``(lineno, name)`` key,
    and a first-match map resolved BOTH CFG defs to the first RHS —
    the killing raw rebind became invisible, the direct-return atom
    never entered ``return_effects``, and the enforced sanitizer-cut
    consumed the minted clean-sanitizer wrapper to drop a real
    finding from the SARIF. The consumer merges every colliding
    candidate conservatively (see :func:`_compute_one_summary`) so an
    ambiguous binding can only LOSE suppression power, never gain it.
    """
    out: dict[tuple[int, str], list[tuple[ast.AST, bool]]] = {}
    for node in ast.walk(fn_ast):
        lineno = getattr(node, "lineno", None)
        if lineno is None:
            continue
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    out.setdefault((lineno, tgt.id), []).append(
                        (node.value, False),
                    )
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                out.setdefault((lineno, node.target.id), []).append(
                    (node.value, True),
                )
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value is not None:
                out.setdefault((lineno, node.target.id), []).append(
                    (node.value, False),
                )
        elif (isinstance(node, ast.NamedExpr)
                and isinstance(node.target, ast.Name)):
            out.setdefault((lineno, node.target.id), []).append(
                (node.value, False),
            )
    return out


def _find_return_value_at(
    fn_ast: ast.AST, lineno: int,
) -> ast.AST | None:
    """Find a ``Return`` at ``lineno`` and return its value
    expression. None for bare ``return`` (value is None)."""
    for node in ast.walk(fn_ast):
        if isinstance(node, ast.Return) and node.lineno == lineno:
            return node.value
    return None


def _compute_one_summary(
    cg: PyModuleCallGraph,
    qualified_name: str,
    summaries_so_far: dict[str, TaintSummary],
) -> TaintSummary:
    """Compute a fresh summary for one function using the current
    state of in-module callees' summaries.

    Called repeatedly by the outer fixed-point in
    :func:`build_taint_summaries`. Each call recomputes the
    function's per-(node, symbol) taint state from scratch — we
    don't preserve intermediate state across iterations because the
    cost is small and the code stays simpler.
    """
    node = cg.find(qualified_name)
    if node is None:
        return TaintSummary(function=qualified_name, params=())
    # Dynamic namespace routes (star-import, exec/eval, sys.modules,
    # escaping globals()/vars()) void EVERY name's resolution in this
    # module — no summary may certify anything (the name-keyed joins
    # would trust identities the runtime namespace no longer proves).
    if cg.namespace_unprovable:
        return TaintSummary(
            function=qualified_name,
            params=node.params,
            summary_unknown=True,
            summary_unknown_reason=(
                "module namespace dynamically rebindable "
                "(star-import / exec / sys.modules / globals write)"
            ),
        )
    # Conditional redefinition: which body runs depends on
    # module-import-time state, and summaries are name-keyed — a
    # single-variant summary would silently stand in for both bodies
    # (the pre-variants graph analysed only the LAST def, a taint
    # false negative through the earlier one). Conservative unknown
    # is sound, and the construct is rare enough that the precision
    # loss is negligible.
    _variants = cg.find_all(qualified_name)
    if len(_variants) > 1:
        return TaintSummary(
            function=qualified_name,
            params=node.params,
            summary_unknown=True,
            summary_unknown_reason=(
                f"conditionally redefined ({len(_variants)} variants)"
                " — behaviour is variant-dependent"
            ),
        )
    # Rebound module identity: a non-def module-scope assignment to
    # this name's root (``esc = str`` beside ``def esc``), or a
    # ``global`` declaration of it anywhere in the module, means the
    # runtime binding may not be this body at all. The name-keyed
    # joins would certify a body the call provably may not reach —
    # degrade to unknown (refusal direction).
    root = qualified_name.split(".", 1)[0]
    if root in cg.rebound_names:
        return TaintSummary(
            function=qualified_name,
            params=node.params,
            summary_unknown=True,
            summary_unknown_reason=(
                f"module-scope rebind of {root!r} — runtime identity "
                "unprovable"
            ),
        )
    fn_ast = cg.function_ast(qualified_name)
    if fn_ast is None:
        return TaintSummary(
            function=qualified_name,
            params=node.params,
            summary_unknown=True,
            summary_unknown_reason="no AST available",
        )
    # Decorated def: the decorator replaces the module binding with
    # an arbitrary wrapper at import time — certifying the BODY would
    # forge a clean-sanitizer wrapper for a callable the name no
    # longer points at. Semantics-preserving decorators are exempt.
    poisoning = _poisoning_decorator(
        fn_ast, cg.import_map, cg.nonimport_distrusted_roots,
    )
    if poisoning is not None:
        return TaintSummary(
            function=qualified_name,
            params=node.params,
            summary_unknown=True,
            summary_unknown_reason=(
                f"decorated with @{poisoning} — runtime identity "
                "unprovable"
            ),
        )

    # Dynamic-dispatch check is one-shot per AST — re-checking each
    # iteration is wasteful but cheap, and it keeps the call graph's
    # responsibility narrow.
    unknown_reason = _detect_summary_unknown(fn_ast)
    if unknown_reason is not None:
        return TaintSummary(
            function=qualified_name,
            params=node.params,
            summary_unknown=True,
            summary_unknown_reason=unknown_reason,
        )

    # Build the function's intra-procedural CFG. Use the internal
    # builder directly so we can pass the AST node (the public
    # build_python_cfg matches by unqualified name, which collides
    # for methods of multiple classes).
    if not isinstance(fn_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # ``ast.Lambda`` and other shapes — we don't summarise yet.
        return TaintSummary(
            function=qualified_name,
            params=node.params,
            summary_unknown=True,
            summary_unknown_reason="not a function def",
        )
    cfg = _PythonCFGBuilder(qualified_name, cg.file_path).build(fn_ast)
    rd = reaching_defs(cfg)
    params = cfg.params

    # Initialise per-(node, symbol) taint OUT state. The fixed-point
    # iterates until no changes.
    # State key: (node, symbol) -> TaintState
    out_state: dict[tuple[PyCFGNode, str], TaintState] = {}

    # Seed: at entry, each param p_i has TaintState {(i, frozenset())}.
    for i, p in enumerate(params):
        out_state[(cfg.entry_node, p)] = frozenset(
            [(i, frozenset())]
        )

    # Per-node IN state — derived from reaching defs at each step.
    def _in_state_for(n: PyCFGNode, sym: str) -> TaintState:
        st = _empty_state()
        for d in rd.at(n, sym):
            st = _merge_states(st, out_state.get((d, sym), _empty_state()))
        return st

    # Fixed-point inside the function. Per-def taint state is
    # computed by walking the AST of the defining expression — that
    # gives us positional arg-index accuracy that the CallSite's
    # ``arg_names`` frozenset doesn't preserve.
    #
    # The assignment/value map is precomputed ONCE (one AST walk) and
    # the loop reads it per (node, symbol) — same lineno-map approach
    # the post-fixed-point collection loop below already uses.
    _assign_map = _build_assignment_value_map(fn_ast)
    # Locally bound names — the shadow guard for _expr_taint's
    # name-keyed callee join (see local_binding_names) — plus the
    # module-scope distrusted roots that poison external-identity
    # stamps (see module_distrusted_roots).
    _local_bindings = cg.binding_names(fn_ast)
    _distrusted_roots = cg.distrusted_roots
    max_inner = 4 * max(1, len(list(cfg.nodes())))
    inner_converged = False
    for _ in range(max_inner):
        changed = False
        for n in cfg.nodes():
            if n is cfg.entry_node:
                continue
            for sym in n.defs:
                found = _assign_map.get((n.lineno, sym))
                if found is not None:
                    # EVERY assignment to ``sym`` at this line
                    # contributes. When the line carries more than one
                    # (``t = html.escape(s); t = s``), the CFG def
                    # cannot be matched to its own RHS — merge every
                    # candidate's taint conservatively instead of
                    # letting the first RHS stand in for all of them.
                    # ``_merge_states`` keeps the direct-return atom
                    # absorbing, so the raw rebind's empty chain
                    # survives the union and the consumer refuses the
                    # clean-sanitizer certification (an ambiguous
                    # binding can only lose suppression power).
                    new_state = _empty_state()
                    for value_ast, is_augmented in found:
                        rhs_state = _expr_taint(
                            value_ast, n, _in_state_for, summaries_so_far, _local_bindings,
                            _distrusted_roots,
                        )
                        if is_augmented:
                            # ``q += rhs`` is ``q = q ⊕ rhs`` — the
                            # target's pre-assignment state carries
                            # into the result alongside the RHS taint.
                            rhs_state = _merge_states(
                                rhs_state, _in_state_for(n, sym),
                            )
                        new_state = _merge_states(new_state, rhs_state)
                else:
                    # No explicit assignment AST found — fall back to
                    # merging the uses' states. Covers cases like
                    # ``for x in xs:`` where the def of x doesn't fit
                    # the Assign/AugAssign shape.
                    new_state = _empty_state()
                    for u in n.uses:
                        new_state = _merge_states(
                            new_state, _in_state_for(n, u),
                        )
                key = (n, sym)
                prev = out_state.get(key, _empty_state())
                merged = _merge_states(prev, new_state)
                if merged != prev:
                    out_state[key] = merged
                    changed = True
        if not changed:
            inner_converged = True
            break

    # Pre-compute return-node line numbers and call-site AST nodes by
    # line so the collection loop below does O(1) lookups instead of
    # walking the full function AST at every CFG node.
    _return_linenos: set[int] = set()
    _calls_by_line: dict[int, list[ast.Call]] = {}
    for ast_n in ast.walk(fn_ast):
        if isinstance(ast_n, ast.Return) and hasattr(ast_n, "lineno"):
            _return_linenos.add(ast_n.lineno)
        elif isinstance(ast_n, ast.Call) and hasattr(ast_n, "lineno"):
            _calls_by_line.setdefault(ast_n.lineno, []).append(ast_n)

    # Collect return_effects and call_arg_taint.
    return_effects: set[tuple[int, str, int]] = set()
    call_arg_taint: set[tuple[str, int, int]] = set()

    for n in cfg.nodes():
        # Returns: walk the return value's AST and produce its
        # TaintState; the contributing atoms feed return_effects.
        if n.kind == "stmt" and n.lineno in _return_linenos:
            return_value = _find_return_value_at(fn_ast, n.lineno)
            if return_value is None:
                # bare ``return`` (None) — no contribution
                pass
            else:
                state = _expr_taint(
                    return_value, n, _in_state_for, summaries_so_far, _local_bindings,
                            _distrusted_roots,
                )
                for pi, effects in state:
                    if not effects:
                        return_effects.add(
                            (pi, _DIRECT_RETURN_CALLABLE,
                             _DIRECT_RETURN_ARG)
                        )
                    else:
                        for callable_name, arg_idx in effects:
                            return_effects.add(
                                (pi, callable_name, arg_idx)
                            )
        # Call sites: walk each ``ast.Call`` at this line and record
        # positional args' contributions.
        if n.call_sites:
            for ast_n in _calls_by_line.get(n.lineno, ()):
                callable_name = _attribute_chain_str(ast_n.func)  # type: ignore[no-redef,assignment]
                if callable_name is None:
                    continue
                for arg_idx, arg_ast in enumerate(ast_n.args):
                    arg_state = _expr_taint(
                        arg_ast, n, _in_state_for, summaries_so_far, _local_bindings,
                            _distrusted_roots,
                    )
                    for pi, _ in arg_state:
                        call_arg_taint.add((callable_name, arg_idx, pi))

    if isinstance(fn_ast, ast.AsyncFunctionDef):
        # Calling an async function returns a coroutine retaining its frame
        # arguments, even when its eventual body result ignores them. Await
        # currently shares these effects and remains conservative too.
        return_effects.update((pi, "", -1) for pi in range(len(params)))

    # Binding-shape facts for callers' positional/keyword mapping
    # (params lists vararg/kwonly/kwarg names as ordinary entries).
    fn_args = fn_ast.args
    positional_limit = len(fn_args.posonlyargs) + len(fn_args.args)
    keyword_params = frozenset(
        a.arg for a in (*fn_args.args, *fn_args.kwonlyargs)
    )

    return TaintSummary(
        function=qualified_name,
        params=params,
        return_effects=frozenset(return_effects),
        call_arg_taint=frozenset(call_arg_taint),
        summary_unconverged=not inner_converged,
        positional_limit=positional_limit,
        keyword_params=keyword_params,
    )


# ---------------------------------------------------------------------------
# Outer fixed-point — call-graph iteration
# ---------------------------------------------------------------------------

# Outer fixed-point recomputation budget = N seeding computations +
# max(FLOOR, PER_FN * N) change-driven ones, N being the number of
# in-module functions. The worklist below recomputes a function ONLY
# when a summary it joins has changed, so a dependency chain of depth
# d costs ~2d pops instead of the old Jacobi sweep's d full passes ×
# N computations (O(N²) full CFG rebuilds — a planted file of ~3000
# chained one-line defs wedged the default-on postpass for
# minutes per finding × candidate). The floor keeps tiny modules from
# under-converging (N=2 mutual recursion needs more than 6 pops to
# settle a real sanitizer chain — Review #5's hazard restated for the
# worklist form).
_TAINT_SUMMARY_OUTER_ITER_FLOOR = 10
_TAINT_SUMMARY_OUTER_ITER_PER_FN = 3


def build_taint_summaries(
    cg: PyModuleCallGraph,
    source: str | Path,
) -> dict[str, TaintSummary]:
    """Compute taint summaries for every function in ``cg``.

    ``source`` is unused — every AST and file path comes from ``cg``.
    The parameter is kept for call-site compatibility only.

    Returns a dict keyed by qualified function name. The synthetic
    ``<module>`` entry node has no summary. Each summary's
    ``params`` matches the corresponding CFG's ``params`` — both
    derive from the same AST.

    Convergence: reverse-dependency worklist. Every function is
    computed once, then re-computed only when a summary its body
    joins (a call chain naming another summary key — exactly
    ``_expr_taint``'s join criterion, over-approximated by walking
    the whole function AST) has changed. When the recomputation
    budget (see :data:`_TAINT_SUMMARY_OUTER_ITER_FLOOR`) is exhausted
    before the queue drains, EVERY non-unknown summary is marked
    ``summary_unconverged`` — an under-iterated summary can be
    missing the direct-return atoms whose absence certifies a clean
    wrapper, so a partial result must degrade wholesale rather than
    stand (Phase 14 refuses unconverged summaries). In practice
    non-pathological codebases drain the queue with ~2 pops per
    function.
    """
    target_nodes = [
        n for n in cg.nodes()
        if not n.is_module_entry
    ]
    # Skip lambdas — they don't expose a FunctionDef AST and Phase
    # 13 doesn't try to summarise them. They'll get an empty summary
    # with summary_unknown="not a function def".
    summaries: dict[str, TaintSummary] = {
        node.name: TaintSummary(function=node.name, params=node.params)
        for node in target_nodes
    }
    all_names = set(summaries)

    # name → summary keys whose change requires recomputing name.
    # Derived from the written call chains in the function's AST —
    # the same name vocabulary ``_expr_taint`` joins on (walking
    # nested defs' bodies too only over-approximates: extra deps cost
    # pops, never correctness).
    dependents: dict[str, set[str]] = {}
    for node in target_nodes:
        fn_ast = cg.function_ast(node.name)
        if fn_ast is None:
            continue
        for sub in ast.walk(fn_ast):
            if not isinstance(sub, ast.Call):
                continue
            callee_name = _attribute_chain_str(sub.func)
            if callee_name and callee_name in all_names:
                dependents.setdefault(callee_name, set()).add(node.name)

    queue: deque[str] = deque(node.name for node in target_nodes)
    queued: set[str] = set(queue)
    pop_budget = len(target_nodes) + max(
        _TAINT_SUMMARY_OUTER_ITER_FLOOR,
        _TAINT_SUMMARY_OUTER_ITER_PER_FN * len(target_nodes),
    )
    pops = 0
    while queue and pops < pop_budget:
        name = queue.popleft()
        queued.discard(name)
        pops += 1
        if summaries[name].summary_unknown:
            # Computed once already (dynamic dispatch / poisoned
            # identity) — never revisited.
            continue
        new_summary = _compute_one_summary(cg, name, summaries)
        if new_summary != summaries[name]:
            summaries[name] = new_summary
            for dep in dependents.get(name, ()):
                if dep not in queued:
                    queue.append(dep)
                    queued.add(dep)
    if not queue:
        return summaries

    # Budget exhausted with recomputations pending — mark EVERY
    # non-unknown summary unconverged (a stale summary may certify a
    # clean wrapper the fixed point would refuse; degrading only the
    # queued names would let its already-computed consumers stand on
    # the stale input).
    for name in list(summaries.keys()):
        s = summaries[name]
        if not s.summary_unknown:
            summaries[name] = replace(s, summary_unconverged=True)
    return summaries


__all__ = [
    "TaintSummary",
    "build_taint_summaries",
]

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
* Outer fixed-point over the call graph for mutual recursion.
  Cycle bail at ``max(10, 3 × N)`` iterations, where ``N`` is the
  number of in-module functions; survivors get
  ``summary_unconverged=True``.
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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import (
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from core.inventory.cfg_builder import (
    PyCFGNode,
    _PythonCFGBuilder,
)
from core.inventory.dataflow import reaching_defs
from core.inventory.callgraph import (
    PyModuleCallGraph,
)


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


# Direct-return marker used in ``return_effects`` to denote "param
# taints return without passing through any callable" — distinct
# from "param doesn't taint return at all" (absence from the set).
_DIRECT_RETURN_CALLABLE = ""
_DIRECT_RETURN_ARG = -1


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

    ``summary_unconverged`` is True when the call-graph fixed-point
    bailed out before reaching a fixed point. Treated like
    ``summary_unknown`` by Phase 14.
    """
    function: str
    params: Tuple[str, ...]
    return_effects: FrozenSet[Tuple[int, str, int]] = frozenset()
    call_arg_taint: FrozenSet[Tuple[str, int, int]] = frozenset()
    summary_unknown: bool = False
    summary_unknown_reason: str = ""
    summary_unconverged: bool = False

    # ----- query helpers -----

    def param_taints_return(self, param_idx: int) -> bool:
        """True iff param at index ``param_idx`` taints the return."""
        return any(eff[0] == param_idx for eff in self.return_effects)

    def return_sanitizers_for_param(
        self, param_idx: int,
    ) -> FrozenSet[Tuple[str, int]]:
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
    ) -> FrozenSet[int]:
        """Param indices whose taint reaches the ``arg_idx``
        argument of any call to ``callee`` inside this function."""
        return frozenset(
            pi for c, ai, pi in self.call_arg_taint
            if c == callee and ai == arg_idx
        )


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


def _detect_summary_unknown(fn_ast: ast.AST) -> Optional[str]:
    """Return a short reason string if the function should be marked
    ``summary_unknown``, otherwise None.

    Triggers:

    * Direct call to a name in :data:`_UNKNOWN_CALLABLES` (e.g.
      ``getattr(o, name)(...)``).
    * ``**kwargs`` forwarding — any call whose keyword args list
      contains a ``**`` expansion (``g(**kwargs)``). The expanded
      content can't be statically resolved.

    Only the FUNCTION's own body is checked — nested function
    definitions are summarised separately so their dynamic dispatch
    doesn't poison the outer summary.
    """
    for node in ast.walk(fn_ast):
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


def _attribute_chain_str(node: ast.AST) -> Optional[str]:
    """Return the dotted name for an attribute chain over ``ast.Name``.
    Used for matching against the ``_UNKNOWN_CALLABLES`` set."""
    parts: List[str] = []
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
TaintAtom = Tuple[int, FrozenSet[Tuple[str, int]]]
# Per-symbol taint state at a CFG node IN: a frozenset of atoms.
TaintState = FrozenSet[TaintAtom]


def _empty_state() -> TaintState:
    return frozenset()


def _merge_states(a: TaintState, b: TaintState) -> TaintState:
    """Element-wise union; atoms with the same param_idx merge
    their effect-chain sets together (over-approximation — Phase
    14 only checks set membership, so unioning is sound)."""
    if not a:
        return b
    if not b:
        return a
    by_param: Dict[int, Set[Tuple[str, int]]] = {}
    for atom in a:
        by_param.setdefault(atom[0], set()).update(atom[1])
    for atom in b:
        by_param.setdefault(atom[0], set()).update(atom[1])
    return frozenset(
        (pi, frozenset(effects)) for pi, effects in by_param.items()
    )


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
    expr: Optional[ast.AST],
    cfg_node: PyCFGNode,
    in_state_fn,
    summaries: Dict[str, TaintSummary],
) -> TaintState:
    """Compute the :data:`TaintState` produced by evaluating an
    arbitrary expression at ``cfg_node``'s IN.

    AST shapes handled:

    * ``Name`` — use the in-state of the bare symbol.
    * ``Attribute`` — base name's in-state (over-approximation;
      field-level distinctions aren't tracked).
    * ``Call`` — recursive walk on each positional arg, then map
      through the callee's summary if available (in-module) or
      stamp the callable's effect on each tainted arg (external).
      Positional ordering is taken from ``expr.args`` directly so
      ``helper(b, a)`` maps callee param 0 → b, callee param 1 → a
      (the legacy ``sorted(arg_names)`` convention was unreliable
      when actual positions disagree with lexicographic order).
    * ``BinOp`` / ``BoolOp`` / ``IfExp`` / ``UnaryOp`` —
      element-wise union (taint flows through arithmetic / boolean
      composition into the result).
    * Literals, comprehensions, lambdas, subscripts — return empty
      (conservative under-approximation: their taint contribution
      is unknown; Phase 14 will refuse to suppress when this
      matters).
    """
    if expr is None:
        return _empty_state()
    if isinstance(expr, ast.Name):
        return in_state_fn(cfg_node, expr.id)
    if isinstance(expr, ast.Attribute):
        chain = _attribute_chain_str(expr)
        if chain is None:
            return _empty_state()
        base = chain.split(".", 1)[0]
        return in_state_fn(cfg_node, base)
    if isinstance(expr, ast.Call):
        callable_name = _attribute_chain_str(expr.func) or ""
        # Per-positional-arg taint states.
        arg_states: List[TaintState] = [
            _expr_taint(a, cfg_node, in_state_fn, summaries)
            for a in expr.args
        ]
        callee = summaries.get(callable_name)
        if callee is not None and not callee.summary_unknown:
            # In-module callee with a known summary. Map each
            # return-contributing param to the matching positional arg.
            result = _empty_state()
            for pi_callee, c_callee, a_callee in callee.return_effects:
                if pi_callee >= len(arg_states):
                    continue
                arg_state = arg_states[pi_callee]
                if not arg_state:
                    continue
                if c_callee == _DIRECT_RETURN_CALLABLE:
                    # Direct return — passthrough; no new effect.
                    result = _merge_states(result, arg_state)
                else:
                    stamped = _add_effect(arg_state, c_callee, a_callee)
                    result = _merge_states(result, stamped)
            return result
        # External or unknown callee. Each tainted positional arg
        # contributes via the call with its index stamped.
        result = _empty_state()
        for arg_idx, arg_state in enumerate(arg_states):
            if not arg_state:
                continue
            stamped = _add_effect(arg_state, callable_name, arg_idx)
            result = _merge_states(result, stamped)
        return result
    if isinstance(expr, ast.BinOp):
        return _merge_states(
            _expr_taint(expr.left, cfg_node, in_state_fn, summaries),
            _expr_taint(expr.right, cfg_node, in_state_fn, summaries),
        )
    if isinstance(expr, ast.BoolOp):
        out = _empty_state()
        for v in expr.values:
            out = _merge_states(
                out, _expr_taint(v, cfg_node, in_state_fn, summaries),
            )
        return out
    if isinstance(expr, ast.IfExp):
        return _merge_states(
            _expr_taint(expr.body, cfg_node, in_state_fn, summaries),
            _expr_taint(expr.orelse, cfg_node, in_state_fn, summaries),
        )
    if isinstance(expr, ast.UnaryOp):
        return _expr_taint(expr.operand, cfg_node, in_state_fn, summaries)
    return _empty_state()


def _find_assignment_value_at(
    fn_ast: ast.AST, lineno: int, target_name: str,
) -> Optional[ast.AST]:
    """Find an ``Assign`` / ``AugAssign`` / ``AnnAssign`` /
    ``NamedExpr`` at ``lineno`` whose target is ``target_name``, and
    return the value expression. None if not found."""
    for node in ast.walk(fn_ast):
        if not hasattr(node, "lineno") or node.lineno != lineno:
            continue
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == target_name:
                    return node.value
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == target_name:
                return node.value
        elif isinstance(node, ast.AnnAssign):
            if (isinstance(node.target, ast.Name)
                    and node.target.id == target_name
                    and node.value is not None):
                return node.value
        elif isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name) and node.target.id == target_name:
                return node.value
    return None


def _find_return_value_at(
    fn_ast: ast.AST, lineno: int,
) -> Optional[ast.AST]:
    """Find a ``Return`` at ``lineno`` and return its value
    expression. None for bare ``return`` (value is None)."""
    for node in ast.walk(fn_ast):
        if isinstance(node, ast.Return) and node.lineno == lineno:
            return node.value
    return None


def _compute_one_summary(
    cg: PyModuleCallGraph,
    source_text: str,
    qualified_name: str,
    summaries_so_far: Dict[str, TaintSummary],
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
    fn_ast = cg.function_ast(qualified_name)
    if fn_ast is None:
        return TaintSummary(
            function=qualified_name,
            params=node.params,
            summary_unknown=True,
            summary_unknown_reason="no AST available",
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
    out_state: Dict[Tuple[PyCFGNode, str], TaintState] = {}

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
    max_inner = 4 * max(1, len(list(cfg.nodes())))
    for _ in range(max_inner):
        changed = False
        for n in cfg.nodes():
            if n is cfg.entry_node:
                continue
            for sym in n.defs:
                value_ast = _find_assignment_value_at(fn_ast, n.lineno, sym)
                if value_ast is not None:
                    new_state = _expr_taint(
                        value_ast, n, _in_state_for, summaries_so_far,
                    )
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
            break

    # Collect return_effects and call_arg_taint.
    return_effects: Set[Tuple[int, str, int]] = set()
    call_arg_taint: Set[Tuple[str, int, int]] = set()

    for n in cfg.nodes():
        # Returns: walk the return value's AST and produce its
        # TaintState; the contributing atoms feed return_effects.
        if _is_return_node(n, fn_ast):
            return_value = _find_return_value_at(fn_ast, n.lineno)
            if return_value is None:
                # bare ``return`` (None) — no contribution
                pass
            else:
                state = _expr_taint(
                    return_value, n, _in_state_for, summaries_so_far,
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
            for ast_n in ast.walk(fn_ast):
                if not isinstance(ast_n, ast.Call):
                    continue
                if getattr(ast_n, "lineno", 0) != n.lineno:
                    continue
                callable_name = _attribute_chain_str(ast_n.func)
                if callable_name is None:
                    continue
                for arg_idx, arg_ast in enumerate(ast_n.args):
                    arg_state = _expr_taint(
                        arg_ast, n, _in_state_for, summaries_so_far,
                    )
                    for pi, _ in arg_state:
                        call_arg_taint.add((callable_name, arg_idx, pi))

    return TaintSummary(
        function=qualified_name,
        params=params,
        return_effects=frozenset(return_effects),
        call_arg_taint=frozenset(call_arg_taint),
    )


def _is_return_node(node: PyCFGNode, fn_ast: ast.AST) -> bool:
    """True iff ``node`` corresponds to a ``return`` statement in
    ``fn_ast``. Detection is by lineno + the AST containing a
    Return at that line — cheap and good enough.

    Falls back to ``False`` for fall-through "implicit returns"
    (Python returns None at end of body); those don't carry taint
    from any param to the return so omitting them is sound.
    """
    if node.kind != "stmt":
        return False
    for ast_n in ast.walk(fn_ast):
        if isinstance(ast_n, ast.Return) and ast_n.lineno == node.lineno:
            return True
    return False


# ---------------------------------------------------------------------------
# Outer fixed-point — call-graph iteration
# ---------------------------------------------------------------------------

# Outer fixed-point iteration budget = max(FLOOR, PER_FN * N), N being
# the number of in-module functions. The 3*N term bounds worst-case
# taint propagation depth through the call graph; the floor keeps tiny
# modules from under-converging. Review #5: a bare 3*N starves small
# modules — N=2 mutually recursive functions get only 6 passes, not
# enough to settle a real sanitizer chain, so the summaries bail as
# `summary_unconverged` and a genuine suppression is lost. Floor at 10.
_TAINT_SUMMARY_OUTER_ITER_FLOOR = 10
_TAINT_SUMMARY_OUTER_ITER_PER_FN = 3


def build_taint_summaries(
    cg: PyModuleCallGraph,
    source: Union[str, Path],
) -> Dict[str, TaintSummary]:
    """Compute taint summaries for every function in ``cg``.

    Returns a dict keyed by qualified function name. The synthetic
    ``<module>`` entry node has no summary. Each summary's
    ``params`` matches the corresponding CFG's ``params`` — both
    derive from the same AST.

    Convergence: outer fixed-point bails after
    ``max(10, 3 × N)`` iterations where ``N`` is the number of
    in-module functions (see
    :data:`_TAINT_SUMMARY_OUTER_ITER_FLOOR`). Unconverged summaries
    get ``summary_unconverged=True``
    so Phase 14 can downgrade. In practice non-pathological codebases
    converge in 2–3 passes.
    """
    if isinstance(source, Path):
        source_text = source.read_text(encoding="utf-8")
    else:
        source_text = source

    target_nodes = [
        n for n in cg.nodes()
        if not n.is_module_entry
    ]
    # Skip lambdas — they don't expose a FunctionDef AST and Phase
    # 13 doesn't try to summarise them. They'll get an empty summary
    # with summary_unknown="not a function def".
    summaries: Dict[str, TaintSummary] = {
        node.name: TaintSummary(function=node.name, params=node.params)
        for node in target_nodes
    }
    max_iters = max(
        _TAINT_SUMMARY_OUTER_ITER_FLOOR,
        _TAINT_SUMMARY_OUTER_ITER_PER_FN * len(target_nodes),
    )
    for _ in range(max_iters):
        changed = False
        for node in target_nodes:
            if summaries[node.name].summary_unknown:
                # Compute once to detect dynamic-dispatch even on the
                # first pass; after that, leave it alone.
                continue
            new_summary = _compute_one_summary(
                cg, source_text, node.name, summaries,
            )
            old = summaries[node.name]
            if new_summary != old:
                summaries[node.name] = new_summary
                changed = True
        if not changed:
            return summaries

    # Bail out — mark unconverged.
    for name in list(summaries.keys()):
        s = summaries[name]
        if not s.summary_unknown:
            summaries[name] = replace(s, summary_unconverged=True)
    return summaries


__all__ = [
    "TaintSummary",
    "build_taint_summaries",
]

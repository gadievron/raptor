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


def _detect_summary_unknown(fn_ast: ast.AST) -> str | None:
    """Return a short reason string if the function should be marked
    ``summary_unknown``, otherwise None.

    Triggers:

    * Direct call to a name in :data:`_UNKNOWN_CALLABLES` (e.g.
      ``getattr(o, name)(...)``).
    * ``**kwargs`` forwarding — any call whose keyword args list
      contains a ``**`` expansion (``g(**kwargs)``). The expanded
      content can't be statically resolved.
    * A ``global`` / ``nonlocal`` declaration — a name bound outside
      the local frame is not a local: any call between the tracked
      assignment and the return can rewrite it (module slot /
      enclosing closure), so the straight-line-locals premise the
      propagation runs on is void for the whole function.

    Only the FUNCTION's own body is checked — nested function
    definitions are summarised separately so their dynamic dispatch
    doesn't poison the outer summary.
    """
    for node in ast.walk(fn_ast):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            if _inside_nested_function(node, fn_ast):
                continue
            kind = "global" if isinstance(node, ast.Global) else "nonlocal"
            return f"declares {kind} {', '.join(node.names)}"
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


# Decorators that provably preserve the decorated function's
# call/return semantics for the taint questions the summary answers.
# EVERY other decorator replaces the module-table binding with an
# arbitrary wrapper object (``@nullify`` returning ``str`` swaps a
# clean sanitizer for a raw pass-through at import time), so a
# decorated def's summary must degrade to unknown — the name-keyed
# joins would otherwise certify the BODY of a function the runtime
# name no longer points at. Seed set only; kept deliberately small
# because an over-wide allowlist reopens the forge.
_SEMANTICS_PRESERVING_DECORATORS = frozenset({
    "staticmethod", "classmethod", "property",
    "abstractmethod", "abc.abstractmethod",
    "functools.wraps", "functools.lru_cache", "functools.cache",
    "override", "typing.override",
})


def _poisoning_decorator(fn_ast: ast.AST) -> str | None:
    """Name of the first decorator that voids the summary's identity
    premise, or None when every decorator is semantics-preserving."""
    for dec in getattr(fn_ast, "decorator_list", ()) or ():
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = _attribute_chain_str(target)
        if name is None or name not in _SEMANTICS_PRESERVING_DECORATORS:
            return name or "<complex decorator>"
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
    * Literals, lambdas — return empty (a literal carries no param
      taint; a lambda OBJECT doesn't evaluate its body here).
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
                               summaries)
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
        stamp_name = (
            f"<shadowed:{callable_name}>" if shadowed else callable_name
        )
        # ``g(*xs)`` makes every later positional index unknowable —
        # taint still flows, but positions can't be trusted.
        has_starred = any(isinstance(a, ast.Starred) for a in expr.args)
        # Per-positional-arg taint states (a Starred contributes the
        # taint of its unpacked iterable).
        arg_states: list[TaintState] = [
            _expr_taint(
                a.value if isinstance(a, ast.Starred) else a,
                cfg_node, in_state_fn, summaries, local_bindings,
            )
            for a in expr.args
        ]
        # Keyword args (``**expr`` expansion never reaches here — it
        # marks the whole function ``summary_unknown`` upstream).
        kw_states: list[tuple[str | None, TaintState]] = [
            (kw.arg, _expr_taint(kw.value, cfg_node, in_state_fn,
                                 summaries, local_bindings))
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
                expr.func.value, cfg_node, in_state_fn, summaries, local_bindings,
            )
            recv_stamp = stamp_name or expr.func.attr

        def _with_receiver(state: TaintState) -> TaintState:
            if not recv_state:
                return state
            return _merge_states(
                state, _add_effect(recv_state, recv_stamp, _OPAQUE_ARG),
            )

        callee = None if shadowed else summaries.get(callable_name)
        if (callee is not None and not callee.summary_unknown
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
            idx = _OPAQUE_ARG if (has_starred or shadowed) else arg_idx
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
                    out, _expr_taint(v, cfg_node, in_state_fn, summaries, local_bindings),
                )
        return out
    if isinstance(expr, ast.FormattedValue):
        out = _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings)
        if expr.format_spec is not None:
            # ``f"{v:{width}}"`` — the format spec's interpolations
            # carry their inputs' taint into the rendered result.
            out = _merge_states(out, _expr_taint(
                expr.format_spec, cfg_node, in_state_fn, summaries, local_bindings,
            ))
        return out
    if isinstance(expr, ast.BinOp):
        return _merge_states(
            _expr_taint(expr.left, cfg_node, in_state_fn, summaries, local_bindings),
            _expr_taint(expr.right, cfg_node, in_state_fn, summaries, local_bindings),
        )
    if isinstance(expr, ast.BoolOp):
        out = _empty_state()
        for v in expr.values:
            out = _merge_states(
                out, _expr_taint(v, cfg_node, in_state_fn, summaries, local_bindings),
            )
        return out
    if isinstance(expr, ast.IfExp):
        return _merge_states(
            _expr_taint(expr.body, cfg_node, in_state_fn, summaries, local_bindings),
            _expr_taint(expr.orelse, cfg_node, in_state_fn, summaries, local_bindings),
        )
    if isinstance(expr, ast.UnaryOp):
        return _expr_taint(expr.operand, cfg_node, in_state_fn, summaries, local_bindings)
    # Element/container shapes: the contained expressions' taint flows
    # into the result (an element carries its container's taint, a
    # container carries its elements'). Unstamped — same
    # over-approximation as the Attribute case above; a surviving
    # direct atom makes the consumer refuse, never suppress.
    if isinstance(expr, ast.Subscript):
        return _merge_states(
            _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings),
            _expr_taint(expr.slice, cfg_node, in_state_fn, summaries, local_bindings),
        )
    if isinstance(expr, ast.Starred):
        return _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings)
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        out = _empty_state()
        for e in expr.elts:
            out = _merge_states(
                out, _expr_taint(e, cfg_node, in_state_fn, summaries, local_bindings),
            )
        return out
    if isinstance(expr, ast.Dict):
        out = _empty_state()
        for e in (*expr.keys, *expr.values):
            if e is not None:  # None key = ``**expr`` expansion's slot
                out = _merge_states(
                    out, _expr_taint(e, cfg_node, in_state_fn, summaries, local_bindings),
                )
        return out
    if isinstance(expr, ast.NamedExpr):
        # ``(t := v)`` evaluates to v — keep v's chains intact so a
        # walrus-wrapped sanitizer stays clean.
        return _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings)
    if isinstance(expr, ast.Await):
        return _expr_taint(expr.value, cfg_node, in_state_fn, summaries, local_bindings)
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
        for e in parts:
            out = _merge_states(
                out, _expr_taint(e, cfg_node, in_state_fn, summaries, local_bindings),
            )
        return out
    if isinstance(expr, (ast.Constant, ast.Lambda)):
        # A literal carries no param taint; a lambda OBJECT does not
        # evaluate its body here (calling it does — see the IIFE arm).
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
    poisoning = _poisoning_decorator(fn_ast)
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
    # name-keyed callee join (see local_binding_names).
    _local_bindings = local_binding_names(fn_ast)
    max_inner = 4 * max(1, len(list(cfg.nodes())))
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
                callable_name = _attribute_chain_str(ast_n.func)
                if callable_name is None:
                    continue
                for arg_idx, arg_ast in enumerate(ast_n.args):
                    arg_state = _expr_taint(
                        arg_ast, n, _in_state_for, summaries_so_far, _local_bindings,
                    )
                    for pi, _ in arg_state:
                        call_arg_taint.add((callable_name, arg_idx, pi))

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

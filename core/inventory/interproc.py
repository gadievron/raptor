"""Inter-procedural synthetic sanitizer bindings — Phase 14 of the
sanitizer-cut arc.

Sub-arc C's payoff. When the analysed function calls an in-module
helper whose Phase 13 taint summary shows it *cleanly sanitizes* a
parameter for the finding's CWE, we synthesise a
:class:`core.dataflow.sanitizer_catalog.SanitizerBinding` at that
call site. The synthetic binding carries real ``input_symbols`` (the
call's args at the sanitized parameter positions) and
``output_symbols`` (the names the call's return flows into), so the
existing Phase 4 four-condition gate treats it exactly like a direct
sanitizer call — no gate changes needed.

This is the rescue for the ``sanitizer_in_helper.py`` corpus case:

    def _sanitize(s):
        return html.escape(s)
    def handle(x):
        y = _sanitize(x)     # <- synthetic binding here
        render(y)

Intra-procedurally, ``handle``'s CFG has no ``html.escape`` call, so
``match_sanitizers_in_cfg`` finds nothing and the verdict is
``no_suppress``. With the inter-procedural binding, the value-bound
cut holds and the verdict flips to ``suppress``.

Soundness — a synthetic binding is emitted for parameter position
``i`` of a helper call **only if**:

* the callee resolves to an in-module function with a *known*,
  *converged* summary (``summary_unknown`` / ``summary_unconverged``
  → no binding; the caller stays conservative);
* parameter ``i`` taints the return;
* parameter ``i`` NEVER reaches the return directly (no ``("", -1)``
  effect) — a helper that returns its arg unchanged on some path
  doesn't sanitize;
* EVERY callable in parameter ``i``'s return effect chain is a
  catalog sanitizer for this CWE — a chain through an unrecognised
  callable (``wrap(html.escape(x))`` where ``wrap`` is unknown)
  can't be proven clean.

These rules make "sanitizer-only-on-some-branches-of-helper" and
"bypass via callee that doesn't sanitize" produce no binding, so the
gate correctly declines to suppress. Recursive / transitive
sanitization works automatically because Phase 13's summaries are
transitive (a helper that returns another in-module sanitizer's
result carries that callable in its own effect chain).

Deferred (documented, not bugs):

* Cross-module helpers — a callee not in the module call graph has
  no summary, so no synthetic binding. Full cross-module resolution
  (``importlib.util.find_spec``) is a future-arc concern. Direct
  cross-module calls to a *catalog* sanitizer name (``html.escape``
  imported from a module) already work through the intra-procedural
  ``match_sanitizers_in_cfg`` path and don't need this layer.
* ``self.method`` / ``cls.method`` callee resolution — best-effort:
  resolved only when the dotted ``CallSite.name`` happens to match a
  summary key. Method-receiver class binding is left to a future
  refinement.

Public surface:

* :func:`synthetic_sanitizer_bindings(cfg, fn_ast, summaries, cwe,
  language) -> FrozenSet[SanitizerBinding]`
"""
from __future__ import annotations

import ast
from typing import (
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
)

from core.dataflow.sanitizer_catalog import (
    SanitizerBinding,
    sanitizer_callables_for_cwe,
)
from core.inventory.taint_summaries import TaintSummary


# Sentinel matching taint_summaries._DIRECT_RETURN_CALLABLE —
# duplicated here rather than imported to avoid coupling to a private
# name; the value ("" empty string) is part of the TaintSummary
# contract documented on return_effects.
_DIRECT_RETURN_CALLABLE = ""


def _chain_str(node: ast.AST) -> Optional[str]:
    """Dotted name for an attribute chain over ``ast.Name``.
    ``foo.bar`` → ``"foo.bar"``, ``f`` → ``"f"``. None otherwise."""
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


def _param_cleanly_sanitized(
    summary: TaintSummary,
    param_idx: int,
    sanitizer_names: Set[str],
) -> bool:
    """True iff tainting ``param_idx`` of ``summary``'s function
    yields a return value provably sanitized for the CWE whose
    catalog callables are ``sanitizer_names``.

    See the module docstring for the four conditions. The check is
    deliberately conservative — any uncertainty returns False so the
    gate declines to suppress rather than risk a false suppression.
    """
    if summary.summary_unknown or summary.summary_unconverged:
        return False
    if not summary.param_taints_return(param_idx):
        return False
    # A direct-return path means the param can reach the return
    # unsanitized.
    for pi, callable_name, _ in summary.return_effects:
        if pi == param_idx and callable_name == _DIRECT_RETURN_CALLABLE:
            return False
    sanitizers = summary.return_sanitizers_for_param(param_idx)
    if not sanitizers:
        return False
    # Every callable the taint passed through must be a recognised
    # sanitizer for this CWE. A chain through an unrecognised callable
    # can't be proven to preserve the sanitization.
    return all(
        callable_name in sanitizer_names
        for callable_name, _ in sanitizers
    )


def _positional_arg_names(
    fn_ast: ast.AST, lineno: int, col_offset: int, callee_chain: str,
) -> Optional[List[Optional[str]]]:
    """Positional argument bare-names for the call to ``callee_chain``
    at ``(lineno, col_offset)``. Each entry is the arg's identifier
    (``ast.Name``) or None for non-name args (literals, nested calls,
    subscripts). None if no matching call is found.

    Matching on the exact ``(lineno, col_offset)`` pair — not lineno
    alone — uniquely identifies the call node even when two calls
    share a source line (``f(a) if g(b) else None``). ``ast.walk``
    order is implementation-defined, so lineno-only matching could
    grab the wrong call's argument list; the column pin removes that
    ambiguity (CallSite carries ``col_offset`` straight from the AST).
    """
    for node in ast.walk(fn_ast):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node, "lineno", 0) != lineno:
            continue
        if getattr(node, "col_offset", 0) != col_offset:
            continue
        if _chain_str(node.func) != callee_chain:
            continue
        out: List[Optional[str]] = []
        for arg in node.args:
            out.append(arg.id if isinstance(arg, ast.Name) else None)
        return out
    return None


def synthetic_sanitizer_bindings(
    cfg,
    fn_ast: ast.AST,
    summaries: Dict[str, TaintSummary],
    cwe: str,
    language: str,
) -> FrozenSet[SanitizerBinding]:
    """Build synthetic sanitizer bindings for inter-procedural
    sanitization in ``cfg``'s function.

    ``cfg`` is the intra-procedural CFG of the analysed function
    (a :class:`core.inventory.cfg_builder.PythonCFG`). ``fn_ast`` is
    that function's AST node — used to recover positional argument
    names that the CFG's frozenset ``arg_names`` can't order.
    ``summaries`` maps qualified function name → :class:`TaintSummary`
    (from :func:`core.inventory.taint_summaries.build_taint_summaries`).

    Returns an empty frozenset when the CWE has no catalog sanitizers,
    when no in-module helper call cleanly sanitizes, or when
    ``summaries`` is empty. The result is meant to be unioned into
    ``evaluate_finding``'s ``extra_bindings``.
    """
    sanitizer_names = sanitizer_callables_for_cwe(cwe, language)
    if not sanitizer_names or not summaries:
        return frozenset()

    bindings: List[SanitizerBinding] = []
    for node in cfg.nodes():
        call_sites = getattr(node, "call_sites", ()) or ()
        for cs in call_sites:
            # cs.name is the dotted callee as written. A bare helper
            # name matches its summary key directly; ``A.m`` matches a
            # static-style method summary key. ``self.m`` typically
            # won't match (summary key is ``Class.m``) — best-effort.
            summary = summaries.get(cs.name)
            if summary is None:
                continue
            sanitized_positions = [
                i for i in range(len(summary.params))
                if _param_cleanly_sanitized(summary, i, sanitizer_names)
            ]
            if not sanitized_positions:
                continue
            arg_names = _positional_arg_names(
                fn_ast, cs.lineno, cs.col_offset, cs.name,
            )
            if arg_names is None:
                continue
            sanitized_set = set(sanitized_positions)
            # Review #1: a symbol passed at a position that taints the
            # return but is NOT cleanly sanitized reaches the sink
            # unsanitized through that position — so the helper does not
            # clean it, even if it also passes through a sanitized
            # position. For ``helper(a, b): return html.escape(a) + b``
            # called as ``helper(x, x)``, x flows clean through ``a``
            # AND dirty through ``b``; the synthetic binding must not
            # claim x is sanitized. Exclude any such symbol so the gate
            # declines to suppress (stays conservative).
            unsanitized_symbols: Set[str] = set()
            for i, name in enumerate(arg_names):
                if name is None or i in sanitized_set:
                    continue
                if i < len(summary.params) and summary.param_taints_return(i):
                    unsanitized_symbols.add(name)
            input_symbols: Set[str] = set()
            for i in sanitized_positions:
                if i < len(arg_names) and arg_names[i] is not None:
                    name = arg_names[i]
                    if name in unsanitized_symbols:
                        continue
                    input_symbols.add(name)  # type: ignore[arg-type]
            if not input_symbols:
                # The sanitized parameter wasn't passed a bare-name
                # argument (e.g. a literal or nested expression), or the
                # only candidate symbol also flows in unsanitized —
                # nothing for condition 2 to bind safely against.
                continue
            bindings.append(SanitizerBinding(
                node=node,
                callable=cs.name,
                input_symbols=frozenset(input_symbols),
                output_symbols=cs.assigned_names,
                lineno=cs.lineno,
            ))
    return frozenset(bindings)


__all__ = [
    "synthetic_sanitizer_bindings",
]

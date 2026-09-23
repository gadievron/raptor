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

from core.dataflow.sanitizer_catalog import (
    SanitizerBinding,
    repo_shadows_module_root,
    sanitizer_callables_for_cwe,
)
from core.analysis.python_module_callgraph import local_binding_names
from core.analysis.taint_summaries import TaintSummary


# Sentinel matching taint_summaries._DIRECT_RETURN_CALLABLE —
# duplicated here rather than imported to avoid coupling to a private
# name; the value ("" empty string) is part of the TaintSummary
# contract documented on return_effects.
_DIRECT_RETURN_CALLABLE = ""


def _chain_str(node: ast.AST) -> str | None:
    """Dotted name for an attribute chain over ``ast.Name``.
    ``foo.bar`` → ``"foo.bar"``, ``f`` → ``"f"``. None otherwise."""
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


def _param_cleanly_sanitized(
    summary: TaintSummary,
    param_idx: int,
    sanitizer_names: set[str],
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


class _ConstArg:
    """Sentinel argument entry: a literal (``ast.Constant``) — it
    carries no symbol and cannot carry taint, so it is exempt from
    the dirty-flow exclusion below. Everything else that is not a
    bare ``ast.Name`` stays ``None`` (opaque): a nested call,
    subscript, attribute, or binop can carry taint the bare-name
    model cannot see, so an opaque value at a return-tainting
    position must decline the whole binding."""

    __slots__ = ()


_CONST_ARG = _ConstArg()


def _arg_entry(node: ast.AST) -> str | _ConstArg | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return _CONST_ARG
    return None


def _call_arg_names(
    fn_ast: ast.AST, lineno: int, col_offset: int, callee_chain: str,
) -> tuple[
    list[str | _ConstArg | None],
    list[tuple[str | None, str | _ConstArg | None]],
] | None:
    """Argument entries for the call to ``callee_chain`` at
    ``(lineno, col_offset)``. Returns ``(positional, keywords)``:
    ``positional`` has one entry per positional arg — the arg's
    identifier (``ast.Name``), :data:`_CONST_ARG` for a literal, or
    None for opaque expressions (nested calls, subscripts, binops);
    ``keywords`` has one ``(keyword_name, value_entry)`` entry per
    keyword arg, where ``keyword_name`` is None for ``**kwargs``
    expansion and ``value_entry`` follows the positional encoding.
    None if no matching call is found.

    Keyword args matter for soundness, not just coverage: a symbol
    passed BOTH positionally into a sanitized parameter AND by keyword
    into an unsanitized one (``helper(x, b=x)``) reaches the sink dirty
    through the keyword path, so the caller must see the keyword flow
    to decline the binding.

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
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            # ``helper(*rest, x)`` — the unpack shifts every later
            # runtime position by len(rest), so index-based mapping
            # would bind x to the wrong parameter (possibly a
            # cleanly-sanitized one). Uncertainty → decline the
            # binding (the docstring contract).
            return None
        out: list[str | _ConstArg | None] = [
            _arg_entry(arg) for arg in node.args
        ]
        kw_out: list[tuple[str | None, str | _ConstArg | None]] = [
            (kw.arg, _arg_entry(kw.value)) for kw in node.keywords
        ]
        return out, kw_out
    return None


def synthetic_sanitizer_bindings(
    cfg,
    fn_ast: ast.AST,
    summaries: dict[str, TaintSummary],
    cwe: str,
    language: str,
    repo_root: str | None = None,
) -> frozenset[SanitizerBinding]:
    """Build synthetic sanitizer bindings for inter-procedural
    sanitization in ``cfg``'s function.

    ``cfg`` is the intra-procedural CFG of the analysed function
    (a :class:`core.analysis.cfg_builder.PythonCFG`). ``fn_ast`` is
    that function's AST node — used to recover positional argument
    names that the CFG's frozenset ``arg_names`` can't order.
    ``summaries`` maps qualified function name → :class:`TaintSummary`
    (from :func:`core.analysis.taint_summaries.build_taint_summaries`).

    Returns an empty frozenset when the CWE has no catalog sanitizers,
    when no in-module helper call cleanly sanitizes, or when
    ``summaries`` is empty. The result is meant to be unioned into
    ``evaluate_finding``'s ``extra_bindings``.
    """
    sanitizer_names = sanitizer_callables_for_cwe(cwe, language)
    # Unbound-root refusal (mirrors the evaluate_finding catalog
    # guard): a dotted catalog identity certifies a helper chain only
    # when the module self-imports its root — an unbound root
    # resolves through repo-writable builtins at runtime.
    trusted_roots = getattr(cfg, "trusted_import_roots", None)
    if trusted_roots is not None:
        def _root_trusted(name: str) -> bool:
            if "." not in name:
                return True
            root = name.split(".", 1)[0]
            if root not in trusted_roots:
                return False
            # Origin resolution: a repo shipping its own
            # ``<root>.py`` / ``<root>/__init__.py`` makes the
            # self-import resolve to the REPO's module — the chain
            # identity is the repo's object.
            return not (repo_root and repo_shadows_module_root(
                repo_root, root,
            ))
        sanitizer_names = {
            n for n in sanitizer_names if _root_trusted(n)
        }
    if not sanitizer_names or not summaries:
        return frozenset()

    # Shadow guard: the summary join below is keyed by NAME. When the
    # analysed function's own scope binds the callee chain's root name
    # (``esc = str``, a param named ``esc``, a nested ``def esc``, a
    # walrus), the runtime callee is the local binding — joining the
    # module-table summary would certify a helper the call provably
    # may not reach, and the enforced sanitizer-cut would consume the
    # forged clean-wrapper binding. Any local definition refuses the
    # join (an ambiguous binding only ever loses suppression power).
    local_bindings = local_binding_names(fn_ast)

    bindings: list[SanitizerBinding] = []
    for node in cfg.nodes():
        call_sites = getattr(node, "call_sites", ()) or ()
        for cs in call_sites:
            # cs.name is the dotted callee as written. A bare helper
            # name matches its summary key directly; ``A.m`` matches a
            # static-style method summary key. ``self.m`` typically
            # won't match (summary key is ``Class.m``) — best-effort.
            if cs.name.split(".", 1)[0] in local_bindings:
                continue
            summary = summaries.get(cs.name)
            if summary is None:
                continue
            sanitized_positions = [
                i for i in range(len(summary.params))
                if _param_cleanly_sanitized(summary, i, sanitizer_names)
            ]
            if not sanitized_positions:
                continue
            resolved = _call_arg_names(
                fn_ast, cs.lineno, cs.col_offset, cs.name,
            )
            if resolved is None:
                continue
            arg_names, kw_args = resolved
            sanitized_set = set(sanitized_positions)
            if len(arg_names) > len(summary.params):
                # More positional args than the summary has params:
                # the extras have no parameter mapping (a vararg
                # helper, or an ill-formed call) — index-based flow
                # reasoning is meaningless past the end. Uncertainty
                # → decline the binding (the docstring contract).
                continue
            if (summary.positional_limit is not None
                    and len(arg_names) > summary.positional_limit):
                # Positional args at/past the ``*vararg`` slot:
                # ``params`` lists the vararg and keyword-only names
                # as ordinary entries, so the length check above
                # passes for an exact-length call to a vararg helper
                # while index-based mapping walks THROUGH those slots
                # (the arg after the vararg maps onto a keyword-only
                # param it can never reach). Same uncertainty →
                # decline.
                continue
            # Review #1: a symbol passed at a position that taints the
            # return but is NOT cleanly sanitized reaches the sink
            # unsanitized through that position — so the helper does not
            # clean it, even if it also passes through a sanitized
            # position. For ``helper(a, b): return html.escape(a) + b``
            # called as ``helper(x, x)``, x flows clean through ``a``
            # AND dirty through ``b``; the synthetic binding must not
            # claim x is sanitized. Exclude any such symbol so the gate
            # declines to suppress (stays conservative). The exclusion
            # must cover NON-NAME values too: ``helper(x, g(x))``
            # taints the return through position 1 just as surely,
            # but carries no bare name to exclude — an opaque value
            # at a return-tainting unsanitized position therefore
            # declines the WHOLE binding (a literal is exempt: it
            # cannot carry taint).
            binding_ok = True
            unsanitized_symbols: set[str] = set()
            for i, entry in enumerate(arg_names):
                if i in sanitized_set or entry is _CONST_ARG:
                    continue
                if not summary.param_taints_return(i):
                    continue
                if entry is None:
                    binding_ok = False
                    break
                unsanitized_symbols.add(entry)  # type: ignore[arg-type]
            if not binding_ok:
                continue
            # Keyword-passed flows of the same symbol are just as
            # dirty as positional ones: ``helper(x, b=x)`` sends x
            # into the unsanitized ``b`` no matter how ``a`` cleans
            # it. Map keyword name → parameter position and apply the
            # same rule. Anything unresolvable is uncertainty — the
            # docstring's contract is to decline to suppress: a
            # ``**kwargs`` expansion can route taint through its
            # VALUES into any parameter (excluding the mapping's own
            # name is not enough), an unknown keyword name has no
            # position to reason about, and an opaque value at a
            # return-tainting position is the keyword twin of the
            # positional case above — all three decline the binding.
            # Literal values stay exempt.
            for kw_name, val_entry in kw_args:
                if val_entry is _CONST_ARG:
                    continue
                if (kw_name is None or kw_name not in summary.params
                        or (summary.keyword_params is not None
                            and kw_name not in summary.keyword_params)):
                    # Unknown keyword, or a name that isn't
                    # keyword-BINDABLE (the vararg/kwarg slot names,
                    # posonly params): no trustworthy position to
                    # reason about — decline.
                    binding_ok = False
                    break
                idx = summary.params.index(kw_name)
                if idx in sanitized_set:
                    continue
                if not summary.param_taints_return(idx):
                    continue
                if val_entry is None:
                    binding_ok = False
                    break
                unsanitized_symbols.add(val_entry)  # type: ignore[arg-type]
            if not binding_ok:
                continue
            input_symbols: set[str] = set()
            for i in sanitized_positions:
                if i < len(arg_names) and isinstance(arg_names[i], str):
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

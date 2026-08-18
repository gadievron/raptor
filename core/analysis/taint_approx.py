"""Lightweight intra-procedural taint approximation for C/C++.

AST-structural only — no CFG, no fixed point. Walks tree-sitter parse
trees to find direct parameter-to-callee-argument flows. Deliberately
conservative: false negatives (misses flows through assignments) but
not false positives (doesn't claim a flow that doesn't exist).

For Python, core/inventory/taint_summaries.py provides full CFG-based
analysis. This module covers the C/C++ gap until Joern (tier 3) or
CodeQL (tier 4) is available.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core.inventory.sink_discovery import _is_dangerous

logger = logging.getLogger(__name__)

MEMORY_SINKS: frozenset = frozenset({
    "memcpy", "memmove", "memset", "memcmp",
    "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "printf", "fprintf", "syslog",
    "fread", "fwrite",
    "read", "write", "recv", "send",
    "gets", "fgets",
    "malloc", "calloc", "realloc", "free",
    "alloca",
})

_FUNCTION_DEFINITION = "function_definition"
_CALL_EXPRESSION = "call_expression"
_IDENTIFIER = "identifier"
_FIELD_IDENTIFIER = "field_identifier"
_FIELD_EXPRESSION = "field_expression"
_POINTER_EXPRESSION = "pointer_expression"
_PARENTHESIZED_EXPRESSION = "parenthesized_expression"
_FUNCTION_DECLARATOR = "function_declarator"
_POINTER_DECLARATOR = "pointer_declarator"
_PARAMETER_LIST = "parameter_list"
_PARAMETER_DECLARATION = "parameter_declaration"
_ARGUMENT_LIST = "argument_list"
_ASSIGNMENT_EXPRESSION = "assignment_expression"
_INIT_DECLARATOR = "init_declarator"
_COMPOUND_STATEMENT = "compound_statement"


@dataclass
class CTaintApprox:
    """Taint approximation result for a single C/C++ function."""

    function: str
    params: List[str]
    direct_flows: Dict[int, List[Tuple[str, int]]] = field(default_factory=dict)
    dangerous_flows: Dict[int, List[Tuple[str, int]]] = field(default_factory=dict)
    has_opaque_flow: bool = False

    def has_dangerous_param(self, param_idx: int) -> bool:
        return param_idx in self.dangerous_flows and len(self.dangerous_flows[param_idx]) > 0

    def has_any_dangerous(self) -> bool:
        return any(len(v) > 0 for v in self.dangerous_flows.values())

    def to_dict(self) -> dict:
        return {
            "function": self.function,
            "params": self.params,
            "direct_flows": {
                str(k): [(c, i) for c, i in v]
                for k, v in self.direct_flows.items()
            },
            "dangerous_flows": {
                str(k): [(c, i) for c, i in v]
                for k, v in self.dangerous_flows.items()
            },
            "has_opaque_flow": self.has_opaque_flow,
        }


def extract_taint_approx_c(content: str) -> Dict[str, CTaintApprox]:
    """Extract taint approximations for all functions in C source.

    Returns a dict keyed by function name. Each value is a CTaintApprox
    describing direct parameter-to-callee-argument flows.

    Returns empty dict when tree-sitter C grammar is not installed.
    """
    try:
        import tree_sitter_c as ts_c
    except ImportError:
        logger.debug("taint_approx: tree-sitter C grammar not installed")
        return {}

    try:
        from core.inventory.call_graph import _get_ts_parser
        parser = _get_ts_parser(ts_c.language)
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        logger.debug("taint_approx: C parse failed")
        return {}

    results: Dict[str, CTaintApprox] = {}
    _walk_top_level(tree.root_node, results)
    return results


def extract_taint_approx_cpp(content: str) -> Dict[str, CTaintApprox]:
    """Extract taint approximations for all functions in C++ source."""
    try:
        import tree_sitter_cpp as ts_cpp
    except ImportError:
        logger.debug("taint_approx: tree-sitter C++ grammar not installed")
        return {}

    try:
        from core.inventory.call_graph import _get_ts_parser
        parser = _get_ts_parser(ts_cpp.language)
        tree = parser.parse(content.encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        logger.debug("taint_approx: C++ parse failed")
        return {}

    results: Dict[str, CTaintApprox] = {}
    _walk_top_level(tree.root_node, results)
    return results


def _walk_top_level(
    node,
    results: Dict[str, CTaintApprox],
) -> None:
    """Walk top-level nodes looking for function definitions.

    Iterative (explicit stack) — the walk runs on target-controlled
    parse trees, so recursion depth must not scale with nesting depth
    (a crafted deeply-nested file would otherwise abort the whole
    multi-file prep pass with RecursionError).
    """
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == _FUNCTION_DEFINITION:
            approx = _analyze_function(cur)
            if approx is not None:
                results[approx.function] = approx
            continue
        stack.extend(reversed(cur.children))


def _analyze_function(fn_node) -> Optional[CTaintApprox]:
    """Analyze a single function definition for taint flows."""
    name = _function_name(fn_node)
    if name is None:
        return None

    params = _extract_params(fn_node)
    if not params:
        return CTaintApprox(function=name, params=[])

    param_set: Set[str] = set(params)
    param_index: Dict[str, int] = {p: i for i, p in enumerate(params)}

    approx = CTaintApprox(function=name, params=params)

    body = _find_body(fn_node)
    if body is None:
        return approx

    _scan_calls(body, param_set, param_index, approx)
    _scan_opaque_assignments(body, param_set, approx)

    return approx


def _function_name(fn_def_node) -> Optional[str]:
    """Extract the function name from a function_definition node."""
    for c in fn_def_node.children:
        if not c.is_named:
            continue
        if c.type == _FUNCTION_DECLARATOR:
            return _declarator_name(c)
        if c.type == _POINTER_DECLARATOR:
            inner = _find_function_declarator(c)
            if inner is not None:
                return _declarator_name(inner)
    return None


def _declarator_name(fn_declarator_node) -> Optional[str]:
    """Get the identifier from a function_declarator."""
    for c in fn_declarator_node.children:
        if c.is_named and c.type == _IDENTIFIER:
            return c.text.decode("utf-8", errors="replace")
    return None


def _find_function_declarator(node) -> Optional[object]:
    """Find the first function_declarator under pointer/paren wrappers
    (pre-order, iterative — depth is target-controlled)."""
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == _FUNCTION_DECLARATOR:
            return cur
        stack.extend(
            c for c in reversed(cur.children) if c.is_named
        )
    return None


def _extract_params(fn_node) -> List[str]:
    """Extract parameter names from a function definition."""
    decl = None
    for c in fn_node.children:
        if c.type in (_FUNCTION_DECLARATOR, _POINTER_DECLARATOR):
            decl = c
            break
    if decl is None:
        return []

    if decl.type == _POINTER_DECLARATOR:
        inner = _find_function_declarator(decl)
        if inner is None:
            return []
        decl = inner

    params: List[str] = []
    for c in decl.children:
        if c.type == _PARAMETER_LIST:
            for pc in c.children:
                if pc.type == _PARAMETER_DECLARATION:
                    name = _param_name(pc)
                    if name:
                        params.append(name)
    return params


def _param_name(param_decl) -> Optional[str]:
    """Extract the parameter name from a parameter_declaration.

    Handles: int x, const char *buf, struct foo *ptr, etc.
    The name is the last identifier (or the identifier inside a
    pointer_declarator).
    """
    last_id = None
    for c in param_decl.children:
        if c.type == _IDENTIFIER:
            last_id = c.text.decode("utf-8", errors="replace")
        elif c.type == _POINTER_DECLARATOR:
            inner_id = _find_identifier(c)
            if inner_id is not None:
                last_id = inner_id
        elif c.type == _FUNCTION_DECLARATOR:
            inner_id = _declarator_name(c)
            if inner_id is not None:
                last_id = inner_id
    return last_id


def _find_identifier(node) -> Optional[str]:
    """Find the first identifier leaf in a subtree (pre-order,
    iterative — depth is target-controlled)."""
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == _IDENTIFIER:
            return cur.text.decode("utf-8", errors="replace")
        stack.extend(reversed(cur.children))
    return None


def _find_body(fn_node) -> Optional[object]:
    """Find the compound_statement (function body) in a function_definition."""
    for c in fn_node.children:
        if c.type == _COMPOUND_STATEMENT:
            return c
    return None


def _scan_calls(
    node,
    param_set: Set[str],
    param_index: Dict[str, int],
    approx: CTaintApprox,
) -> None:
    """Scan for call_expressions, checking if any argument is a direct
    use of a function parameter (pre-order, iterative — depth is
    target-controlled)."""
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == _CALL_EXPRESSION:
            callee_chain = _callee_chain(cur)
            if callee_chain is not None:
                _check_arguments(
                    cur, callee_chain, param_set, param_index, approx,
                )
        stack.extend(reversed(cur.children))


def _check_arguments(
    call_node,
    callee_chain: List[str],
    param_set: Set[str],
    param_index: Dict[str, int],
    approx: CTaintApprox,
) -> None:
    """Check each argument of a call for direct parameter usage."""
    callee_name = ".".join(callee_chain)
    dangerous = _is_dangerous(callee_chain) or (
        len(callee_chain) == 1 and callee_chain[0] in MEMORY_SINKS
    )

    for child in call_node.children:
        if child.type == _ARGUMENT_LIST:
            arg_idx = 0
            for arg in child.children:
                if not arg.is_named:
                    continue
                param_name = _argument_is_param(arg, param_set)
                if param_name is not None:
                    pidx = param_index[param_name]
                    approx.direct_flows.setdefault(pidx, []).append(
                        (callee_name, arg_idx)
                    )
                    if dangerous:
                        approx.dangerous_flows.setdefault(pidx, []).append(
                            (callee_name, arg_idx)
                        )
                arg_idx += 1


def _argument_is_param(
    arg_node,
    param_set: Set[str],
) -> Optional[str]:
    """Check if an argument node is a direct reference to a parameter.

    Returns the parameter name if it is, None otherwise.
    Only matches plain identifiers — not &param, *param, param[i],
    param.field, (type)param, etc. Those are opaque flows.
    """
    if arg_node.type == _IDENTIFIER:
        name = arg_node.text.decode("utf-8", errors="replace")
        if name in param_set:
            return name
    return None


def _callee_chain(call_node) -> Optional[List[str]]:
    """Resolve the callee of a call_expression to a name chain."""
    callee = None
    for c in call_node.children:
        if c.is_named and c.type != _ARGUMENT_LIST:
            callee = c
            break
    if callee is None:
        return None
    return _resolve_callee(callee)


def _resolve_callee(node) -> Optional[List[str]]:
    """Resolve an expression node to a dotted name chain.

    Paren / pointer wrappers are unwrapped with a loop (not
    recursion) — nesting depth is target-controlled.
    """
    while node.type in (_PARENTHESIZED_EXPRESSION, _POINTER_EXPRESSION):
        inner = None
        for c in node.children:
            if c.is_named:
                inner = c
                break
        if inner is None:
            return None
        node = inner

    if node.type == _IDENTIFIER:
        return [node.text.decode("utf-8", errors="replace")]

    if node.type == _FIELD_EXPRESSION:
        parts: List[str] = []
        cur = node
        while cur is not None and cur.type == _FIELD_EXPRESSION:
            field_node = None
            operand = None
            for c in cur.children:
                if c.type == _FIELD_IDENTIFIER:
                    field_node = c
                elif c.is_named and c.type != _FIELD_IDENTIFIER:
                    operand = c
            if field_node is None:
                return None
            parts.append(field_node.text.decode("utf-8", errors="replace"))
            cur = operand
        if cur is not None and cur.type == _IDENTIFIER:
            parts.append(cur.text.decode("utf-8", errors="replace"))
            return list(reversed(parts))
        return None

    return None


def _scan_opaque_assignments(
    node,
    param_set: Set[str],
    approx: CTaintApprox,
) -> None:
    """Scan for assignments where a parameter flows through a non-trivial
    LHS (pointer deref, struct member, cast). Sets has_opaque_flow.

    Iterative (explicit stack) — depth is target-controlled."""
    stack = [node]
    while stack:
        if approx.has_opaque_flow:
            return
        cur = stack.pop()

        if cur.type == _ASSIGNMENT_EXPRESSION:
            rhs = None
            children = list(cur.children)
            for c in children:
                if not c.is_named:
                    continue
                if c.text and c.text.decode("utf-8", errors="replace") == "=":
                    continue
                rhs = c

            if rhs is not None and rhs.type == _IDENTIFIER:
                name = rhs.text.decode("utf-8", errors="replace")
                if name in param_set:
                    lhs = None
                    for c in children:
                        if c.is_named and c != rhs:
                            lhs = c
                            break
                    if lhs is not None and lhs.type != _IDENTIFIER:
                        approx.has_opaque_flow = True
                        return

        if cur.type == _INIT_DECLARATOR:
            for c in cur.children:
                if c.is_named and c.type == _IDENTIFIER:
                    continue
                if c.is_named and c.type == _POINTER_DECLARATOR:
                    for sc in cur.children:
                        if sc.is_named and sc.type == _IDENTIFIER:
                            name = sc.text.decode("utf-8", errors="replace")
                            if name in param_set:
                                approx.has_opaque_flow = True
                                return

        stack.extend(reversed(cur.children))


# ---------------------------------------------------------------------------
# Transitive (cross-function) taint tracking
# ---------------------------------------------------------------------------


@dataclass
class TaintPath:
    """A single path from a parameter through intermediates to a dangerous sink."""

    hops: List[str]       # [caller, intermediate, ..., sink]
    sink_name: str        # the dangerous function at the end
    sink_arg: int         # which argument position at the sink


@dataclass
class TransitiveTaint:
    """Transitive taint result for a single function."""

    function: str
    param_sinks: Dict[int, List[TaintPath]]  # param_idx → paths to sinks


def compute_transitive_taint(
    per_function: Dict[str, CTaintApprox],
    call_edges: Optional[List[Dict[str, str]]] = None,
    max_depth: int = 5,
) -> Dict[str, TransitiveTaint]:
    """Follow taint across function boundaries to find transitive sink paths.

    Builds on per-function ``CTaintApprox`` results: for each function *F*
    with parameter *P* flowing to callee *C* at argument *A*, if *C* has
    its own ``CTaintApprox`` and *C*'s param *A* flows further, the chain
    is extended until it reaches a dangerous sink or ``max_depth`` is hit.

    *call_edges* (optional) provides supplementary caller→callee edges
    (e.g. from ``context-map.json``) to bridge functions whose
    ``direct_flows`` only cover intra-file relationships.

    Returns a dict keyed by function name mapping to ``TransitiveTaint``.
    Only functions with at least one reachable sink path are included.
    """

    # -- Build a supplementary adjacency set from call_edges ----------------
    # Maps caller → set of callees (bare names) so we can discover
    # cross-file edges that the intra-file direct_flows missed.
    extra_edges: Dict[str, Set[str]] = {}
    if call_edges:
        for edge in call_edges:
            caller = edge.get("caller", "")
            callee = edge.get("callee", "")
            if caller and callee:
                extra_edges.setdefault(caller, set()).add(callee)

    results: Dict[str, TransitiveTaint] = {}

    for func_name, approx in per_function.items():
        param_sinks: Dict[int, List[TaintPath]] = {}

        for param_idx, flows in approx.direct_flows.items():
            paths: List[TaintPath] = []
            for callee_name, arg_idx in flows:
                _follow_taint(
                    callee_name,
                    arg_idx,
                    per_function,
                    extra_edges,
                    visited=frozenset({func_name}),
                    hops_so_far=[func_name],
                    max_depth=max_depth,
                    out_paths=paths,
                )
            if paths:
                param_sinks[param_idx] = paths

        if param_sinks:
            results[func_name] = TransitiveTaint(
                function=func_name,
                param_sinks=param_sinks,
            )

    return results


def _follow_taint(
    callee: str,
    arg_idx: int,
    per_function: Dict[str, CTaintApprox],
    extra_edges: Dict[str, Set[str]],
    visited: frozenset,
    hops_so_far: List[str],
    max_depth: int,
    out_paths: List[TaintPath],
) -> None:
    """Recursive DFS following taint from *callee* param *arg_idx* to sinks.

    A path is "complete" (appended to *out_paths*) when:
    - *callee* is in ``MEMORY_SINKS`` or ``_is_dangerous`` matches, or
    - *callee* has ``dangerous_flows`` for *arg_idx*.

    Otherwise, if *callee* has a ``CTaintApprox`` entry and its param
    *arg_idx* has ``direct_flows``, the search continues along those edges.
    """

    # -- Depth / cycle guard ------------------------------------------------
    if len(hops_so_far) >= max_depth:
        return
    if callee in visited:
        return

    current_hops = hops_so_far + [callee]

    # -- Terminal: callee is itself a dangerous sink ------------------------
    callee_parts = callee.split(".")
    is_sink = (
        callee in MEMORY_SINKS
        or _is_dangerous(callee_parts) is not None
    )
    if is_sink:
        out_paths.append(TaintPath(
            hops=list(current_hops),
            sink_name=callee,
            sink_arg=arg_idx,
        ))
        return

    # -- Check if callee has its own per-function taint info ----------------
    callee_approx = per_function.get(callee)

    if callee_approx is not None:
        # Terminal: callee marks this arg position as dangerous
        if callee_approx.has_dangerous_param(arg_idx):
            for sink_callee, sink_arg in callee_approx.dangerous_flows[arg_idx]:
                out_paths.append(TaintPath(
                    hops=list(current_hops) + [sink_callee],
                    sink_name=sink_callee,
                    sink_arg=sink_arg,
                ))

        # Continue: follow callee's direct_flows for this arg position
        if arg_idx in callee_approx.direct_flows:
            new_visited = visited | {callee}
            for next_callee, next_arg in callee_approx.direct_flows[arg_idx]:
                _follow_taint(
                    next_callee,
                    next_arg,
                    per_function,
                    extra_edges,
                    visited=new_visited,
                    hops_so_far=current_hops,
                    max_depth=max_depth,
                    out_paths=out_paths,
                )
        return

    # -- Callee not in per_function: try extra_edges to bridge the gap ------
    if callee in extra_edges:
        new_visited = visited | {callee}
        for bridged_callee in extra_edges[callee]:
            bridged_approx = per_function.get(bridged_callee)
            if bridged_approx is not None:
                # Bridge: treat arg_idx as flowing through to the same
                # position in the bridged callee (best-effort heuristic
                # when we lack precise parameter mapping).
                if arg_idx in bridged_approx.direct_flows:
                    for next_callee, next_arg in bridged_approx.direct_flows[arg_idx]:
                        _follow_taint(
                            next_callee,
                            next_arg,
                            per_function,
                            extra_edges,
                            visited=new_visited,
                            hops_so_far=current_hops + [bridged_callee],
                            max_depth=max_depth,
                            out_paths=out_paths,
                        )
                if bridged_approx.has_dangerous_param(arg_idx):
                    for sink_callee, sink_arg in bridged_approx.dangerous_flows[arg_idx]:
                        out_paths.append(TaintPath(
                            hops=list(current_hops) + [bridged_callee, sink_callee],
                            sink_name=sink_callee,
                            sink_arg=sink_arg,
                        ))
            else:
                # Bridged callee also has no taint info — check if it is
                # itself a dangerous sink.
                bridged_parts = bridged_callee.split(".")
                if (
                    bridged_callee in MEMORY_SINKS
                    or _is_dangerous(bridged_parts) is not None
                ):
                    out_paths.append(TaintPath(
                        hops=list(current_hops) + [bridged_callee],
                        sink_name=bridged_callee,
                        sink_arg=arg_idx,
                    ))


def format_transitive_taint(tt: TransitiveTaint) -> str:
    """Render a ``TransitiveTaint`` as prose suitable for an LLM prompt.

    Example output::

        Function `parse_header`:
        - param index 0 reaches dangerous sink `memcpy` via: \
parse_header -> copy_data -> memcpy (arg 0)
    """
    lines: List[str] = [f"Function `{tt.function}`:"]
    for param_idx in sorted(tt.param_sinks):
        for path in tt.param_sinks[param_idx]:
            chain = " -> ".join(path.hops)
            lines.append(
                f"- param index {param_idx} reaches dangerous sink "
                f"`{path.sink_name}` via: {chain} (arg {path.sink_arg})"
            )
    return "\n".join(lines)

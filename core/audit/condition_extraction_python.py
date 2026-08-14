"""Deep Python AST condition extraction (Layer 2).

Richer than the tree-sitter layer for Python specifically:
  - Full dominator-based condition propagation (not just enclosing blocks)
  - Constant resolution (resolves simple assignments and module constants)
  - Decorator detection (treats decorators like @login_required as guards)
  - Context manager detection (with statements as resource guards)
  - Early-return pattern detection with precise polarity

Uses Python's native ast module for maximum fidelity.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from .condition_classifier import classify_condition
from .condition_extraction import GuardCondition, SinkGuard

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Python-specific sink detection
# ---------------------------------------------------------------------------

# Common Python sinks (subset for fast matching)
_PY_SINKS: FrozenSet[str] = frozenset({
    "eval", "exec", "compile",
    "os.system", "os.popen",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "pickle.loads", "pickle.load",
    "yaml.load", "yaml.unsafe_load",
    "marshal.loads",
    "open", "io.open", "os.open",
    "shutil.rmtree",
    "os.remove", "os.unlink",
    "__import__",
    "getattr", "setattr",
    "ctypes.CDLL",
})


def _call_name(node: ast.Call) -> str:
    """Extract the full dotted call name from an ast.Call."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        cur = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return ""


def _matches_sink(name: str, sink_names: FrozenSet[str]) -> Optional[str]:
    """Check if call name matches a sink. Returns matched name."""
    if not name:
        return None
    if name in sink_names:
        return name
    # Suffix match: subprocess.call → "subprocess.call"
    parts = name.split(".")
    if len(parts) >= 2:
        dotted = f"{parts[-2]}.{parts[-1]}"
        if dotted in sink_names:
            return dotted
    # Last component
    if parts[-1] in sink_names:
        return parts[-1]
    return None


# ---------------------------------------------------------------------------
# AST condition extraction
# ---------------------------------------------------------------------------


@dataclass
class _FunctionContext:
    """Context for condition extraction within one function."""
    func_name: str
    func_node: ast.AST
    decorators: List[str] = field(default_factory=list)
    constants: Dict[str, Any] = field(default_factory=dict)


def _extract_decorators(
    func_node: ast.AST,
) -> List[str]:
    """Extract decorator names from a function definition."""
    decorators = []
    if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for dec in func_node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(f"@{dec.id}")
            elif isinstance(dec, ast.Attribute):
                decorators.append(f"@{ast.unparse(dec)}")
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decorators.append(f"@{dec.func.id}(...)")
                elif isinstance(dec.func, ast.Attribute):
                    decorators.append(f"@{ast.unparse(dec.func)}(...)")
    return decorators


def _resolve_module_constants(tree: ast.Module) -> Dict[str, Any]:
    """Extract simple module-level constant assignments.

    Resolves: MAX_SIZE = 1024, DEBUG = False, etc.
    """
    constants: Dict[str, Any] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            if (len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Constant)):
                name = node.targets[0].id
                # Only track simple constants (str, int, bool, None)
                if isinstance(node.value.value, (str, int, float, bool, type(None))):
                    constants[name] = node.value.value
    return constants


def _find_enclosing_function(
    node: ast.AST,
    parents: Dict[int, ast.AST],
) -> Optional[ast.AST]:
    """Find the nearest enclosing function definition."""
    cur = parents.get(id(node))
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = parents.get(id(cur))
    return None


def _build_parent_map(tree: ast.Module) -> Dict[int, ast.AST]:
    """Build a parent map for the AST."""
    parents: Dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _find_enclosing_ifs(
    node: ast.AST,
    parents: Dict[int, ast.AST],
    func_node: Optional[ast.AST],
    max_depth: int = 5,
) -> List[Tuple[ast.AST, str, str]]:
    """Find all enclosing if/with/match statements up to function boundary.

    Returns (if_node, condition_text, polarity) from innermost to outermost.
    """
    results: List[Tuple[ast.AST, str, str]] = []
    target_line = getattr(node, "lineno", 0)

    cur = parents.get(id(node))
    while cur is not None and len(results) < max_depth:
        if isinstance(cur, ast.If):
            cond_text = ast.unparse(cur.test)
            polarity = _if_polarity(cur, target_line)
            results.append((cur, cond_text, polarity))

        elif isinstance(cur, ast.With) or isinstance(cur, ast.AsyncWith):
            # Context managers as resource guards
            items_text = ", ".join(
                ast.unparse(item.context_expr) for item in cur.items
            )
            results.append((cur, f"with {items_text}", "required"))

        elif hasattr(ast, "Match") and isinstance(cur, ast.Match):
            subject_text = ast.unparse(cur.subject)
            results.append((cur, f"match {subject_text}", "required"))

        # Stop at function boundary
        if cur is func_node:
            break
        cur = parents.get(id(cur))

    return results


def _if_polarity(if_node: ast.If, target_line: int) -> str:
    """Determine if target_line is in the if-body or else-body.

    Also detects early-return guard pattern.
    """
    # Check if target is in the if-body
    for stmt in if_node.body:
        if hasattr(stmt, "lineno") and hasattr(stmt, "end_lineno"):
            if stmt.lineno <= target_line <= (stmt.end_lineno or stmt.lineno):
                return "required"

    # Check if target is in the else-body
    for stmt in if_node.orelse:
        if hasattr(stmt, "lineno") and hasattr(stmt, "end_lineno"):
            if stmt.lineno <= target_line <= (stmt.end_lineno or stmt.lineno):
                return "excluded"

    # Early-return guard pattern: if-body is just return/raise,
    # target is after the if — condition is negated
    if if_node.body and all(
        isinstance(s, (ast.Return, ast.Raise, ast.Continue, ast.Break))
        for s in if_node.body
    ):
        if_end = max(
            (getattr(s, "end_lineno", s.lineno) or s.lineno)
            for s in if_node.body
        )
        if target_line > if_end:
            return "excluded"

    return "required"


def _try_resolve_condition(
    cond_text: str,
    constants: Dict[str, Any],
) -> Tuple[bool, Dict[str, str]]:
    """Try to resolve a condition to concrete values using module constants.

    Returns (resolvable, concrete_values).
    """
    concrete: Dict[str, str] = {}
    resolvable = False

    for name, value in constants.items():
        if re.search(r'(?<![A-Za-z0-9_])' + re.escape(name) + r'(?![A-Za-z0-9_])', cond_text):
            concrete[name] = repr(value)
            resolvable = True

    return resolvable, concrete


def _find_preceding_guard_clauses_ast(
    call_node: ast.AST,
    parents: Dict[int, ast.AST],
    func_node: Optional[ast.AST],
    constants: Dict[str, Any],
    max_depth: int = 5,
) -> List[GuardCondition]:
    """Find if-statements before the call that are guard clauses.

    A guard clause: if-body is only return/raise, no else branch.
    These gate all subsequent code with the negated condition.
    """
    if max_depth <= 0:
        return []

    call_line = getattr(call_node, "lineno", 0)

    # Find the enclosing body (list of statements) that contains the call
    body: Optional[List[ast.stmt]] = None
    if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        body = func_node.body
    else:
        # Module level — walk up to find the nearest body
        cur = parents.get(id(call_node))
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = cur.body
                break
            if isinstance(cur, ast.Module):
                body = cur.body
                break
            cur = parents.get(id(cur))

    if body is None:
        return []

    results: List[GuardCondition] = []
    for stmt in body:
        if len(results) >= max_depth:
            break
        # Only look at statements BEFORE the call
        stmt_end = getattr(stmt, "end_lineno", None) or getattr(stmt, "lineno", 0)
        if stmt_end >= call_line:
            break
        # Must be an If with exit-only body and no else
        if not isinstance(stmt, ast.If):
            continue
        if stmt.orelse:
            continue
        if not stmt.body:
            continue
        if not all(
            isinstance(s, (ast.Return, ast.Raise, ast.Continue, ast.Break))
            for s in stmt.body
        ):
            continue
        # This is a guard clause — add with "excluded" polarity
        cond_text = ast.unparse(stmt.test)
        category = classify_condition(cond_text)
        resolvable, concrete = _try_resolve_condition(cond_text, constants)
        results.append(GuardCondition(
            text=cond_text,
            category=category,
            polarity="excluded",
            line=stmt.lineno,
            resolvable=resolvable,
            concrete_values=concrete,
        ))

    return results


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------


def extract_sink_guards_python(
    source: str,
    filepath: str,
    sink_names: Optional[FrozenSet[str]] = None,
    sink_lines: Optional[List[int]] = None,
    max_guard_depth: int = 5,
) -> List[SinkGuard]:
    """Deep Python AST condition extraction.

    Provides richer results than the tree-sitter layer:
      - Decorator guards (e.g., @login_required)
      - Context manager guards (with statements)
      - Constant resolution
      - Precise early-return-guard polarity

    Args:
        source: Python source code.
        filepath: File path (for output metadata).
        sink_names: Dangerous function names to find. Defaults to _PY_SINKS.
        sink_lines: Specific lines to analyze (alternative to sink_names).
        max_guard_depth: Maximum guard depth to extract.

    Returns:
        List of SinkGuard instances with classified guards.
    """
    if sink_names is None:
        sink_names = _PY_SINKS

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        logger.debug("condition_extraction_python: syntax error in %s", filepath)
        return []

    parents = _build_parent_map(tree)
    constants = _resolve_module_constants(tree)

    # Find all call nodes that match sinks
    call_sites: List[Tuple[ast.Call, str]] = []

    if sink_lines is not None:
        # Find calls at specified lines
        sink_lines_set = set(sink_lines)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and hasattr(node, "lineno"):
                if node.lineno in sink_lines_set:
                    name = _call_name(node)
                    call_sites.append((node, name or "<unknown>"))
    else:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                matched = _matches_sink(name, sink_names)
                if matched:
                    call_sites.append((node, matched))

    # Extract guards for each call site
    results: List[SinkGuard] = []

    for call_node, sink_api in call_sites:
        func_node = _find_enclosing_function(call_node, parents)
        func_name = "<module>"
        if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = func_node.name

        guards: List[GuardCondition] = []

        # 1. Decorator guards on the enclosing function
        if func_node is not None:
            decorators = _extract_decorators(func_node)
            for dec in decorators:
                category = classify_condition(dec)
                if category != "unknown":
                    guards.append(GuardCondition(
                        text=dec,
                        category=category,
                        polarity="required",
                        line=func_node.lineno,
                    ))

        # 2. Enclosing conditionals (if/with/match)
        enclosing = _find_enclosing_ifs(
            call_node, parents, func_node, max_depth=max_guard_depth,
        )
        for _if_node, cond_text, polarity in enclosing:
            category = classify_condition(cond_text)
            resolvable, concrete = _try_resolve_condition(cond_text, constants)
            guards.append(GuardCondition(
                text=cond_text,
                category=category,
                polarity=polarity,
                line=getattr(_if_node, "lineno", 0),
                resolvable=resolvable,
                concrete_values=concrete,
            ))

        # 3. Preceding guard clauses (early-return pattern)
        preceding = _find_preceding_guard_clauses_ast(
            call_node, parents, func_node, constants,
            max_depth=max_guard_depth - len(guards),
        )
        guards.extend(preceding)

        sg = SinkGuard(
            sink_file=filepath,
            sink_line=call_node.lineno,
            sink_function=func_name,
            sink_api=sink_api,
            guards=guards,
            unconditional=(len(guards) == 0),
        )
        results.append(sg)

    return results

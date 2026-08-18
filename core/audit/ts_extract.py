"""Tree-sitter extraction layer for bugshape detectors.

Provides structured extraction of return semantics, call chains,
string literals, dispatch tables, loop caps, and function bodies
across all languages tree-sitter supports.  Each function degrades
gracefully to ``None`` when tree-sitter is unavailable.

Consumers: sentinel_collapse, transform_sequence, fail_open_detector,
value_space_checker, dispatch_completeness, sibling_analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tree-sitter availability (reuse condition_extraction infrastructure)
# ---------------------------------------------------------------------------

try:
    from .condition_extraction import (
        _FUNCTION_TYPES,
        _get_parser,
        language_for_file,
    )
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False

    def _get_parser(lang: str):  # type: ignore[misc]
        return None

    def language_for_file(filepath: str) -> str | None:  # type: ignore[misc]
        return None

    _FUNCTION_TYPES: dict[str, tuple] = {}  # type: ignore[no-redef]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ReturnInfo:
    """One return statement's semantics."""

    value_type: str       # "none"/"null"/"empty_dict"/"empty_list"/"zero"/"other"
    is_error_path: bool
    line: int


@dataclass
class FunctionReturns:
    """Return-path semantics for one function."""

    function: str
    file: str
    returns: list[ReturnInfo] = field(default_factory=list)

    @property
    def sentinel_ambiguous(self) -> bool:
        error_types = {r.value_type for r in self.returns if r.is_error_path}
        success_types = {r.value_type for r in self.returns if not r.is_error_path}
        return bool(error_types & (success_types - {"other"}))

    @property
    def ambiguous_value(self) -> str:
        error_types = {r.value_type for r in self.returns if r.is_error_path}
        success_types = {r.value_type for r in self.returns if not r.is_error_path}
        overlap = error_types & (success_types - {"other"})
        if overlap:
            return ", ".join(sorted(overlap))
        return "unknown"


@dataclass
class CallStep:
    """One step in a call chain."""

    call_name: str
    line: int
    first_arg: str = ""


@dataclass
class CallChain:
    """Ordered transform sequence on one variable."""

    file: str
    function: str
    variable: str
    steps: list[CallStep] = field(default_factory=list)


@dataclass
class StringLiteralSite:
    """A string literal with its role context."""

    value: str
    function: str
    file: str
    line: int
    context: str  # "dict_key"/"comparison"/"return"/"assignment"/"switch_case"/"argument"
    is_template: bool = False


@dataclass
class DispatchTable:
    """A switch/case or dict dispatch table."""

    function: str
    file: str
    line: int
    keys: list[str] = field(default_factory=list)
    table_type: str = "switch"  # "switch"/"dict"/"if_chain"/"match"


@dataclass
class LoopCap:
    """A loop with a break-at-limit pattern."""

    function: str
    file: str
    line: int
    signals_truncation: bool = False


# ---------------------------------------------------------------------------
# Node type tables
# ---------------------------------------------------------------------------

_CALL_TYPES: dict[str, tuple[str, ...]] = {
    "c": ("call_expression",),
    "cpp": ("call_expression",),
    "python": ("call",),
    "go": ("call_expression",),
    "rust": ("call_expression", "method_call_expression"),
    "java": ("method_invocation",),
    "javascript": ("call_expression",),
    "typescript": ("call_expression",),
    "tsx": ("call_expression",),
    "ruby": ("call", "method_call"),
    "php": ("function_call_expression", "member_call_expression"),
    "csharp": ("invocation_expression",),
}

_ASSIGNMENT_TYPES: dict[str, tuple[str, ...]] = {
    "c": ("assignment_expression",),
    "cpp": ("assignment_expression",),
    "python": ("assignment",),
    "go": ("assignment_statement", "short_var_declaration"),
    "rust": ("assignment_expression", "let_declaration"),
    "java": ("assignment_expression",),
    "javascript": ("assignment_expression", "variable_declarator", "augmented_assignment_expression"),
    "typescript": ("assignment_expression", "variable_declarator", "augmented_assignment_expression"),
    "tsx": ("assignment_expression", "variable_declarator", "augmented_assignment_expression"),
    "ruby": ("assignment",),
    "php": ("assignment_expression",),
    "csharp": ("assignment_expression",),
}

_RETURN_TYPES: dict[str, tuple[str, ...]] = {
    "c": ("return_statement",),
    "cpp": ("return_statement",),
    "python": ("return_statement",),
    "go": ("return_statement",),
    "rust": ("return_expression",),
    "java": ("return_statement",),
    "javascript": ("return_statement",),
    "typescript": ("return_statement",),
    "tsx": ("return_statement",),
    "ruby": ("return",),
    "php": ("return_statement",),
    "csharp": ("return_statement",),
}

_ERROR_HANDLER_TYPES: dict[str, tuple[str, ...]] = {
    "c": (),
    "cpp": ("catch_clause",),
    "python": ("except_clause",),
    "go": (),  # handled specially: if err != nil
    "rust": (),
    "java": ("catch_clause",),
    "javascript": ("catch_clause",),
    "typescript": ("catch_clause",),
    "tsx": ("catch_clause",),
    "ruby": ("rescue",),
    "php": ("catch_clause",),
    "csharp": ("catch_clause",),
}

_SWITCH_TYPES: dict[str, tuple[str, ...]] = {
    "c": ("switch_statement",),
    "cpp": ("switch_statement",),
    "python": ("match_statement",),
    "go": ("expression_switch_statement",),
    "rust": ("match_expression",),
    "java": ("switch_expression", "switch_statement"),
    "javascript": ("switch_statement",),
    "typescript": ("switch_statement",),
    "tsx": ("switch_statement",),
    "ruby": ("case",),
    "php": ("switch_statement", "match_expression"),
    "csharp": ("switch_statement", "switch_expression"),
}

_CASE_TYPES: dict[str, tuple[str, ...]] = {
    "c": ("case_statement",),
    "cpp": ("case_statement",),
    "python": ("case_clause",),
    "go": ("expression_case",),
    "rust": ("match_arm",),
    "java": ("switch_block_statement_group", "switch_rule"),
    "javascript": ("switch_case",),
    "typescript": ("switch_case",),
    "tsx": ("switch_case",),
    "ruby": ("when",),
    "php": ("case_statement", "match_condition_list"),
    "csharp": ("switch_section",),
}

_STRING_TYPES: dict[str, tuple[str, ...]] = {
    "c": ("string_literal",),
    "cpp": ("string_literal", "raw_string_literal"),
    "python": ("string",),
    "go": ("interpreted_string_literal", "raw_string_literal"),
    "rust": ("string_literal", "raw_string_literal"),
    "java": ("string_literal",),
    "javascript": ("string", "template_string"),
    "typescript": ("string", "template_string"),
    "tsx": ("string", "template_string"),
    "ruby": ("string",),
    "php": ("string", "encapsed_string"),
    "csharp": ("string_literal", "verbatim_string_literal", "interpolated_string_expression"),
}

_NULL_TYPES: dict[str, tuple[str, ...]] = {
    "c": ("null",),
    "cpp": ("null", "nullptr"),
    "python": ("none",),
    "go": ("nil",),
    "rust": ("none",),  # Option::None
    "java": ("null_literal",),
    "javascript": ("null", "undefined"),
    "typescript": ("null", "undefined"),
    "tsx": ("null", "undefined"),
    "ruby": ("nil",),
    "php": ("null",),
    "csharp": ("null_literal",),
}

_LOOP_TYPES: dict[str, tuple[str, ...]] = {
    "c": ("for_statement", "while_statement", "do_statement"),
    "cpp": ("for_statement", "while_statement", "do_statement", "for_range_loop"),
    "python": ("for_statement", "while_statement"),
    "go": ("for_statement",),
    "rust": ("for_expression", "while_expression", "loop_expression"),
    "java": ("for_statement", "enhanced_for_statement", "while_statement", "do_statement"),
    "javascript": ("for_statement", "for_in_statement", "for_of_statement", "while_statement", "do_statement"),
    "typescript": ("for_statement", "for_in_statement", "for_of_statement", "while_statement", "do_statement"),
    "tsx": ("for_statement", "for_in_statement", "for_of_statement", "while_statement", "do_statement"),
    "ruby": ("for", "while", "until"),
    "php": ("for_statement", "foreach_statement", "while_statement"),
    "csharp": ("for_statement", "foreach_statement", "while_statement", "do_statement"),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _node_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _node_line(node) -> int:
    return node.start_point[0] + 1


def _walk_descendants(node):
    """Yield all descendants of a node in pre-order."""
    for child in node.children:
        yield child
        yield from _walk_descendants(child)


def _same_node(a, b) -> bool:
    """Compare two tree-sitter nodes by position (identity varies across traversals)."""
    if a is b:
        return True
    if a is None or b is None:
        return False
    return (a.type == b.type
            and a.start_byte == b.start_byte
            and a.end_byte == b.end_byte)



def _is_inside_error_handler_with_src(node, lang: str, src: bytes) -> bool:
    """Check if a node is inside an error-handling block (source-aware)."""
    handler_types = _ERROR_HANDLER_TYPES.get(lang, ())
    cur = node.parent
    while cur is not None:
        if cur.type in handler_types:
            return True
        if lang == "go" and cur.type == "if_statement":
            cond = cur.child_by_field_name("condition")
            if cond:
                cond_text = _node_text(cond, src)
                if "err" in cond_text and "!=" in cond_text and "nil" in cond_text:
                    return True
        cur = cur.parent
    return False


def _find_enclosing_function(node, lang: str):
    """Walk up to find enclosing function node."""
    func_types = _FUNCTION_TYPES.get(lang, ())
    cur = node.parent
    while cur is not None:
        if cur.type in func_types:
            return cur
        cur = cur.parent
    return None


def _get_func_name(func_node, lang: str, src: bytes) -> str:
    """Extract function name from a function definition node."""
    if func_node is None:
        return "<module>"
    for child in func_node.children:
        if child.type in ("identifier", "name"):
            return _node_text(child, src)
        if child.type in ("function_declarator", "declarator"):
            for sub in child.children:
                if sub.type in ("identifier", "field_identifier"):
                    return _node_text(sub, src)
                if sub.type == "pointer_declarator":
                    for psub in sub.children:
                        if psub.type in ("identifier", "field_identifier"):
                            return _node_text(psub, src)
        if child.type == "field_identifier":
            return _node_text(child, src)
    return "<unknown>"


def _get_func_body(func_node, lang: str):
    """Get the body/block node of a function."""
    body = func_node.child_by_field_name("body")
    if body is not None:
        return body
    for child in func_node.children:
        if child.type in ("block", "statement_block", "compound_statement"):
            return child
    return func_node


def _classify_return_value(node, lang: str, src: bytes) -> str:
    """Classify a return statement's value."""
    null_types = _NULL_TYPES.get(lang, ())

    children = [c for c in node.children
                if c.type not in ("return", ";", "comment")]
    if not children:
        return "none"

    val = children[0]

    # Multi-value returns (Go expression_list, etc.) — classify the primary
    # (first) value; secondary values are typically error/ok flags.
    if val.type == "expression_list":
        items = [c for c in val.children if c.type != ","]
        if not items:
            return "none"
        val = items[0]

    if val.type in null_types:
        return "null" if lang != "python" else "none"

    text = _node_text(val, src).strip()

    if text in ("None",):
        return "none"
    if text in ("nil", "null", "nullptr", "NULL", "undefined"):
        return "null"
    if text in ("{}", "dict()", "map[string]interface{}{}"):
        return "empty_dict"
    if text in ("[]", "list()", "make([]string, 0)"):
        return "empty_list"
    if text in ("0", "0.0", "false", "False", "FALSE"):
        return "zero"
    if text in ('""', "''", '``'):
        return "empty_string"

    # Empty array/dict literals
    if val.type in ("dictionary", "dict") and not any(
        c.type not in ("{", "}", "comment") for c in val.children
    ):
        return "empty_dict"
    if val.type in ("list", "array", "tuple") and not any(
        c.type not in ("[", "]", "(", ")", "comment") for c in val.children
    ):
        return "empty_list"

    return "other"


def _parse_file(file_path: str, source: str):
    """Parse a file with tree-sitter. Returns (tree, lang, src_bytes) or None."""
    lang = language_for_file(file_path)
    if lang is None:
        return None
    # Python: use stdlib ast (more precise). Only fall through for
    # non-Python or when callers explicitly request tree-sitter.
    parser = _get_parser(lang)
    if parser is None:
        return None
    src = source.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(src)
    except Exception:  # noqa: BLE001 — unparseable source: no extraction
        return None
    return tree, lang, src


def _iter_functions(tree, lang: str, src: bytes, file_path: str):
    """Iterate over (func_node, func_name, body_node) in a parse tree."""
    func_types = _FUNCTION_TYPES.get(lang, ())
    for node in _walk_descendants(tree.root_node):
        if node.type in func_types:
            name = _get_func_name(node, lang, src)
            body = _get_func_body(node, lang)
            yield node, name, body


# ---------------------------------------------------------------------------
# 1. Return semantics extraction
# ---------------------------------------------------------------------------

def extract_function_returns(
    file_path: str,
    source: str,
) -> list[FunctionReturns] | None:
    """Extract return-path semantics for each function.

    Returns None if tree-sitter is unavailable for this file type.
    """
    parsed = _parse_file(file_path, source)
    if parsed is None:
        return None
    tree, lang, src = parsed

    results: list[FunctionReturns] = []
    return_types = _RETURN_TYPES.get(lang, ())

    for func_node, func_name, body in _iter_functions(tree, lang, src, file_path):
        fr = FunctionReturns(function=func_name, file=file_path)

        for desc in _walk_descendants(body):
            if desc.type not in return_types:
                continue
            # Don't count returns from nested functions
            enclosing = _find_enclosing_function(desc, lang)
            if enclosing is not None and not _same_node(enclosing, func_node):
                continue

            is_error = _is_inside_error_handler_with_src(desc, lang, src)
            value_type = _classify_return_value(desc, lang, src)
            fr.returns.append(ReturnInfo(
                value_type=value_type,
                is_error_path=is_error,
                line=_node_line(desc),
            ))

        if fr.returns:
            results.append(fr)

    return results


# ---------------------------------------------------------------------------
# 2. Call chain extraction
# ---------------------------------------------------------------------------

def extract_call_chains(
    file_path: str,
    source: str,
) -> list[CallChain] | None:
    """Extract ordered transform sequences (same-variable reassignment and method chains).

    Returns None if tree-sitter is unavailable for this file type.
    """
    parsed = _parse_file(file_path, source)
    if parsed is None:
        return None
    tree, lang, src = parsed

    assign_types = _ASSIGNMENT_TYPES.get(lang, ())
    call_types = _CALL_TYPES.get(lang, ())
    results: list[CallChain] = []

    for func_node, func_name, body in _iter_functions(tree, lang, src, file_path):
        # Track reassignment chains: var → [steps]
        var_chains: dict[str, list[CallStep]] = {}

        for desc in _walk_descendants(body):
            if desc.type not in assign_types:
                continue

            lhs, rhs = _extract_assignment_parts(desc, lang, src)
            if not lhs or not rhs:
                continue

            call_name = _extract_call_name(rhs, lang, src, call_types)
            if not call_name:
                continue

            first_arg = _extract_first_arg(rhs, lang, src, call_types)

            chain = var_chains.setdefault(lhs, [])
            chain.append(CallStep(
                call_name=call_name,
                line=_node_line(desc),
                first_arg=first_arg,
            ))

        # Also extract method chains from expressions
        for desc in _walk_descendants(body):
            chain = _extract_method_chain(desc, lang, src, call_types)
            if chain and len(chain.steps) >= 2:
                chain.file = file_path
                chain.function = func_name
                results.append(chain)

        for var, steps in var_chains.items():
            if len(steps) >= 2:
                results.append(CallChain(
                    file=file_path,
                    function=func_name,
                    variable=var,
                    steps=steps,
                ))

    return results


def _extract_assignment_parts(
    node, lang: str, src: bytes,
) -> tuple[str, Any]:
    """Extract (lhs_name, rhs_node) from an assignment."""
    if lang == "go":
        # assignment_statement: expr_list = expr_list
        # short_var_declaration: identifier_list := expr_list
        lhs_list = rhs_list = None
        found_eq = False
        for child in node.children:
            if child.type in ("=", ":="):
                found_eq = True
            elif not found_eq:
                lhs_list = child
            else:
                rhs_list = child
        if lhs_list is None or rhs_list is None:
            return "", None

        # Get first identifier from LHS
        lhs_name = ""
        for c in (lhs_list.children if lhs_list.children else [lhs_list]):
            if c.type == "identifier":
                lhs_name = _node_text(c, src)
                break

        # Get first expression from RHS
        rhs = None
        for c in (rhs_list.children if rhs_list.children else [rhs_list]):
            if c.type != ",":
                rhs = c
                break

        return lhs_name, rhs

    # variable_declarator: identifier = expr
    if (lang in ("javascript", "typescript", "tsx")
            and node.type == "variable_declarator"):
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node and value_node:
            return _node_text(name_node, src), value_node
        return "", None

    # General: assignment_expression: lhs = rhs
    children = node.children
    lhs_name = ""
    rhs = None
    found_eq = False
    for child in children:
        if child.type in ("=", ":="):
            found_eq = True
        elif not found_eq:
            if child.type == "identifier":
                lhs_name = _node_text(child, src)
            elif child.type == "expression_list":
                for sub in child.children:
                    if sub.type == "identifier":
                        lhs_name = _node_text(sub, src)
                        break
        else:
            if rhs is None:
                rhs = child

    return lhs_name, rhs


def _extract_call_name(
    node, lang: str, src: bytes, call_types: tuple[str, ...],
) -> str:
    """Extract the call name from an expression that may be a call."""
    # Java method_invocation uses "name"/"object" fields, not "function"
    if node.type == "method_invocation":
        name_node = node.child_by_field_name("name")
        obj_node = node.child_by_field_name("object")
        if name_node:
            name = _node_text(name_node, src)
            if obj_node:
                return f"{_node_text(obj_node, src)}.{name}"
            return name
    if node.type in call_types:
        func_node = node.child_by_field_name("function")
        if func_node is None:
            for child in node.children:
                if child.type not in ("arguments", "argument_list", "(", ")", ","):
                    func_node = child
                    break
        if func_node is None:
            return ""
        return _node_text(func_node, src)
    return ""


def _extract_first_arg(
    node, lang: str, src: bytes, call_types: tuple[str, ...],
) -> str:
    """Extract the first argument's text from a call."""
    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        for child in node.children:
            if child.type in ("arguments", "argument_list"):
                args_node = child
                break
    if args_node is None:
        return ""
    for child in args_node.children:
        if child.type in ("(", ")", ","):
            continue
        text = _node_text(child, src)
        return text[:60] if len(text) > 60 else text
    return ""


def _extract_method_chain(
    node, lang: str, src: bytes, call_types: tuple[str, ...],
) -> CallChain | None:
    """Extract a method chain like x.strip().lower().replace(...)."""
    if node.type not in call_types:
        return None

    steps: list[CallStep] = []
    var_name = ""
    current = node

    while current.type in call_types:
        func_node = current.child_by_field_name("function")
        if func_node is None:
            for child in current.children:
                if child.type not in ("arguments", "argument_list", "(", ")"):
                    func_node = child
                    break
        if func_node is None:
            break

        if func_node.type in ("member_expression", "field_expression"):
            prop = func_node.child_by_field_name("property")
            if prop:
                steps.append(CallStep(
                    call_name=f".{_node_text(prop, src)}",
                    line=_node_line(current),
                    first_arg=_extract_first_arg(current, lang, src, call_types),
                ))
            obj = func_node.child_by_field_name("object")
            if obj and obj.type in call_types:
                current = obj
                continue
            elif obj and obj.type == "identifier":
                var_name = _node_text(obj, src)
            break
        else:
            break

    if len(steps) < 2:
        return None

    steps.reverse()
    return CallChain(
        file="", function="",
        variable=var_name,
        steps=steps,
    )


# ---------------------------------------------------------------------------
# 3. String literal extraction
# ---------------------------------------------------------------------------

def extract_string_literals(
    file_path: str,
    source: str,
) -> list[StringLiteralSite] | None:
    """Extract string literals with their context role.

    Returns None if tree-sitter is unavailable for this file type.
    """
    parsed = _parse_file(file_path, source)
    if parsed is None:
        return None
    tree, lang, src = parsed

    string_types = _STRING_TYPES.get(lang, ())
    results: list[StringLiteralSite] = []

    for node in _walk_descendants(tree.root_node):
        if node.type not in string_types:
            continue

        text = _node_text(node, src)
        value = _strip_string_delimiters(text, lang)
        if not value:
            continue

        is_template = node.type in ("template_string", "interpolated_string_expression")
        # Python f-strings are "string" type but contain interpolation
        if lang == "python" and "{" in value and "}" in value:
            is_template = True

        func_node = _find_enclosing_function(node, lang)
        func_name = _get_func_name(func_node, lang, src) if func_node else "<module>"
        context = _classify_string_context(node, lang)

        results.append(StringLiteralSite(
            value=value,
            function=func_name,
            file=file_path,
            line=_node_line(node),
            context=context,
            is_template=is_template,
        ))

    return results


def _strip_string_delimiters(text: str, lang: str) -> str:
    """Remove quotes (and language prefixes like r/b/f/u) from a string literal."""
    if len(text) < 2:
        return ""
    # Strip language-specific prefixes (Python rb/br/fr, C++ u8/U/L, C# @/$, etc.)
    s = text
    while s and s[0] in "rRbBuUfFL@$" and len(s) > 1:
        if s[0] in "uU" and len(s) > 2 and s[1] == "8" and s[2] in "'\"":
            s = s[2:]
            break
        if s[1] in "rRbBuUfFL@$'\"":
            s = s[1:]
        else:
            break
    if len(s) < 2:
        return ""
    if s.startswith(('"""', "'''")):
        return s[3:-3] if len(s) >= 6 else ""
    if s.startswith('`'):
        return s[1:-1] if s.endswith('`') else s[1:]
    for q in ('"', "'"):
        if s.startswith(q) and s.endswith(q):
            return s[1:-1]
    return text


def _classify_string_context(node, lang: str) -> str:
    """Determine the role of a string literal from its parent context."""
    parent = node.parent
    if parent is None:
        return "other"

    _CASE_CONTEXT_TYPES = frozenset({
        "switch_case", "case_statement", "switch_block_statement_group",
        "switch_label", "case_clause", "expression_case", "when",
        "match_arm", "case",
    })

    # Switch case label (check parent and grandparent — some grammars wrap in expression_list)
    if parent.type in _CASE_CONTEXT_TYPES:
        return "switch_case"
    grandparent = parent.parent
    if grandparent is not None and grandparent.type in _CASE_CONTEXT_TYPES:
        return "switch_case"

    # Dict key
    if parent.type in ("pair", "dictionary", "object", "map_literal"):
        children = [c for c in parent.children if c.type not in (":", ",", "{", "}")]
        if children and _same_node(children[0], node):
            return "dict_key"

    # Comparison
    if parent.type in ("comparison_operator", "binary_expression"):
        for child in parent.children:
            if child.type in ("==", "!=", "===", "!==", "is", "eq", "ne"):
                return "comparison"

    # Return (some grammars wrap in expression_list)
    _RETURN_CONTEXT = ("return_statement", "return", "return_expression")
    if parent.type in _RETURN_CONTEXT:
        return "return"
    if (grandparent is not None and grandparent.type in _RETURN_CONTEXT
            and parent.type == "expression_list"):
        return "return"

    # Assignment RHS (some grammars wrap in expression_list)
    _ASSIGN_CONTEXT = (
        "assignment_expression", "assignment_statement",
        "assignment", "variable_declarator",
        "short_var_declaration",
    )
    if parent.type in _ASSIGN_CONTEXT:
        return "assignment"
    if (grandparent is not None and grandparent.type in _ASSIGN_CONTEXT
            and parent.type == "expression_list"):
        return "assignment"

    # Argument to a call
    if parent.type in ("arguments", "argument_list"):
        return "argument"

    return "other"


# ---------------------------------------------------------------------------
# 4. Dispatch table extraction
# ---------------------------------------------------------------------------

def extract_dispatch_tables(
    file_path: str,
    source: str,
) -> list[DispatchTable] | None:
    """Extract switch/case and dict-literal dispatch tables.

    Returns None if tree-sitter is unavailable for this file type.
    """
    parsed = _parse_file(file_path, source)
    if parsed is None:
        return None
    tree, lang, src = parsed

    switch_types = _SWITCH_TYPES.get(lang, ())
    case_types = _CASE_TYPES.get(lang, ())
    string_types = _STRING_TYPES.get(lang, ())
    results: list[DispatchTable] = []

    for node in _walk_descendants(tree.root_node):
        if node.type not in switch_types:
            continue

        func_node = _find_enclosing_function(node, lang)
        func_name = _get_func_name(func_node, lang, src) if func_node else "<module>"

        keys: list[str] = []
        for desc in _walk_descendants(node):
            if desc.type in case_types:
                # Skip case nodes belonging to a nested switch
                ancestor = desc.parent
                while ancestor is not None and not _same_node(ancestor, node):
                    if ancestor.type in switch_types:
                        break
                    ancestor = ancestor.parent
                if not _same_node(ancestor, node):
                    continue

                for child in _walk_descendants(desc):
                    if child.type in string_types:
                        val = _strip_string_delimiters(_node_text(child, src), lang)
                        if val:
                            keys.append(val)
                            break

        if len(keys) >= 2:
            results.append(DispatchTable(
                function=func_name,
                file=file_path,
                line=_node_line(node),
                keys=keys,
                table_type="switch" if "switch" in node.type else "match",
            ))

    return results


# ---------------------------------------------------------------------------
# 5. Loop cap extraction
# ---------------------------------------------------------------------------

_TRUNCATION_KEYWORDS = frozenset({
    "truncat", "capped", "incomplete", "partial", "overflow",
})


def extract_loop_caps(
    file_path: str,
    source: str,
) -> list[LoopCap] | None:
    """Extract loops with break-at-limit patterns.

    Returns None if tree-sitter is unavailable for this file type.
    """
    parsed = _parse_file(file_path, source)
    if parsed is None:
        return None
    tree, lang, src = parsed

    loop_types = _LOOP_TYPES.get(lang, ())
    results: list[LoopCap] = []

    for node in _walk_descendants(tree.root_node):
        if node.type not in loop_types:
            continue

        func_node = _find_enclosing_function(node, lang)
        func_name = _get_func_name(func_node, lang, src) if func_node else "<module>"

        has_cap_break = False
        for desc in _walk_descendants(node):
            if desc.type in ("if_statement", "if_expression"):
                # Skip if inside a nested loop (not directly in *this* loop)
                ancestor = desc.parent
                while ancestor is not None and not _same_node(ancestor, node):
                    if ancestor.type in loop_types:
                        break
                    ancestor = ancestor.parent
                if not _same_node(ancestor, node):
                    continue

                if_text = _node_text(desc, src)
                has_comparison = any(
                    op in if_text for op in (">=", ">", "==", "len(", ".length", ".size()")
                )
                has_break = any(
                    desc_child.type in ("break_statement", "return_statement", "break", "return")
                    for desc_child in _walk_descendants(desc)
                )
                if has_comparison and has_break:
                    has_cap_break = True
                    break

        if not has_cap_break:
            continue

        # Check if enclosing function signals truncation
        func_body = _node_text(func_node, src) if func_node else ""
        func_lower = func_body.lower()
        signals = any(kw in func_lower for kw in _TRUNCATION_KEYWORDS)

        results.append(LoopCap(
            function=func_name,
            file=file_path,
            line=_node_line(node),
            signals_truncation=signals,
        ))

    return results


# ---------------------------------------------------------------------------
# 6. Function body extraction
# ---------------------------------------------------------------------------

_FUNC_BODY_MAX = 50_000


def extract_function_body(
    file_path: str,
    source: str,
    func_name: str,
) -> str | None:
    """Extract the source text of a named function.

    Returns None if tree-sitter is unavailable for this file type.
    Returns "" (empty string) if the function is not found — callers
    can distinguish "ts unavailable" (None) from "name not found" ("").
    """
    parsed = _parse_file(file_path, source)
    if parsed is None:
        return None
    tree, lang, src = parsed

    for func_node, name, body in _iter_functions(tree, lang, src, file_path):
        if name == func_name:
            text = _node_text(func_node, src)
            if len(text) > _FUNC_BODY_MAX:
                text = text[:_FUNC_BODY_MAX]
            return text

    return ""


# ---------------------------------------------------------------------------
# Convenience: file-level batch extraction
# ---------------------------------------------------------------------------


def extract_all_string_literals(
    source_text: dict[str, str],
) -> dict[str, list[StringLiteralSite]]:
    """Batch extract string literals for all non-Python files."""
    results: dict[str, list[StringLiteralSite]] = {}
    for fp, src in source_text.items():
        if fp.endswith(".py"):
            continue
        lits = extract_string_literals(fp, src)
        if lits:
            results[fp] = lits
    return results


def extract_all_dispatch_tables(
    source_text: dict[str, str],
) -> dict[str, list[DispatchTable]]:
    """Batch extract dispatch tables for all non-Python files."""
    results: dict[str, list[DispatchTable]] = {}
    for fp, src in source_text.items():
        if fp.endswith(".py"):
            continue
        tables = extract_dispatch_tables(fp, src)
        if tables:
            results[fp] = tables
    return results

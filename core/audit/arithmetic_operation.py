"""Bind a proposed arithmetic query to one source operation.

This establishes syntax and occurrence identity only. It does not prove
operand types, reachability, guard dominance, or the absence of mutation.
Callers must supply source already restricted to the requested function.
"""

import logging
from dataclasses import dataclass

from .condition_extraction import _get_parser

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ArithmeticOperation:
    status: str
    line: int = 0
    column: int = 0


def _unwrap(node):
    while node is not None and node.type == "parenthesized_expression":
        children = [child for child in node.named_children if child.type != "comment"]
        if len(children) != 1:
            break
        node = children[0]
    return node


def bind_arithmetic_operation(source, operands, operator, *, language):
    """Select a unique atomic binary operation or decline the query.

    C/C++ parenthesized identifiers preserve operand identity. Casts,
    fields, calls, and compound operands require a richer model and do not
    match. Addition and multiplication may reverse the two operands;
    subtraction must retain source order.
    """
    if language not in {"c", "cpp"}:
        return ArithmeticOperation("unavailable")
    if len(operands) != 2 or operator not in {"+", "-", "*"}:
        return ArithmeticOperation("unbound")
    try:
        parser = _get_parser(language)
        if parser is None:
            return ArithmeticOperation("unavailable")
        data = source.encode("utf-8")
        root = parser.parse(data).root_node
        if root.has_error:
            return ArithmeticOperation("unavailable")
    except Exception:
        # Optional parser setup and bounded-parse failures decline source credit.
        logger.debug("arithmetic operation parse unavailable", exc_info=True)
        return ArithmeticOperation("unavailable")

    def text(node):
        return data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    bodies = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            body = node.child_by_field_name("body")
            if body is not None:
                bodies.append(body)
            continue
        stack.extend(node.named_children)
    if len(bodies) != 1:
        return ArithmeticOperation("unbound" if not bodies else "ambiguous")

    matches = []
    stack = [bodies[0]]
    while stack:
        node = stack.pop()
        if node.type in {"function_definition", "lambda_expression"}:
            continue  # another callable does not execute in this function's body
        if node.type == "generic_expression" or node.type.startswith("preproc_"):
            return ArithmeticOperation("unavailable")  # selected arms are not modeled
        if node.type == "if_statement" and any(
            child.type in {"constexpr", "consteval"} for child in node.children
        ):
            return ArithmeticOperation("unavailable")
        if node.type == "sizeof_expression":
            pending = list(node.named_children)
            while pending:
                item = pending.pop()
                if item.type in {"array_declarator", "abstract_array_declarator"}:
                    return ArithmeticOperation("unavailable")  # VLA extents may execute
                pending.extend(item.named_children)
        # These recognized forms do not evaluate the arithmetic operand.
        if node.type in {
            "sizeof_expression", "alignof_expression", "decltype", "noexcept_expression",
            "requires_expression", "static_assert_declaration", "enum_specifier",
        }:
            continue
        # The pinned C++ grammar represents the noexcept operator as a call.
        if language == "cpp" and node.type == "call_expression" and text(
            node.child_by_field_name("function")
        ) == "noexcept":
            continue
        if node.type == "binary_expression" and text(node.child_by_field_name("operator")) == operator:
            left = _unwrap(node.child_by_field_name("left"))
            right = _unwrap(node.child_by_field_name("right"))
            if left is not None and right is not None and left.type == right.type == "identifier":
                pair = (text(left), text(right))
                wanted = tuple(operands)
                if pair == wanted or (operator in {"+", "*"} and pair == wanted[::-1]):
                    matches.append(node)
                    if len(matches) > 1:
                        return ArithmeticOperation("ambiguous")
        stack.extend(node.named_children)
    if not matches:
        return ArithmeticOperation("unbound")
    row, column = matches[0].start_point
    return ArithmeticOperation("bound", row + 1, column + 1)

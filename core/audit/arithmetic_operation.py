"""Bind a proposed arithmetic query to one source operation.

This binds syntax, occurrence identity, and predicates from supported
structured paths, plus supported operand types under an explicit target ABI.
It does not establish complete source reachability. Callers supply source
restricted to the requested function.
"""

import logging
import re
from dataclasses import dataclass

from .condition_extraction import _get_parser
from .arithmetic_evaluation import unevaluated_context
from .function_execution_frame import ordinary_function_frame

logger = logging.getLogger(__name__)
_INTEGER_LITERAL_RE = re.compile(r"(?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)")
_MAX_SOURCE_CHARS = 65536
_MAX_NODES = 2048


@dataclass(frozen=True)
class ArithmeticOperation:
    status: str
    line: int = 0
    column: int = 0
    guard_status: str = "unavailable"
    premises: tuple[str, ...] = ()
    type_status: str = "unavailable"
    profile: str = ""
    kind: str = ""
    domains: tuple[str, ...] = ()
    types: tuple[tuple[str, str], ...] = ()


def _unwrap(node):
    while node is not None and node.type == "parenthesized_expression":
        children = [child for child in node.named_children if child.type != "comment"]
        if len(children) != 1:
            break
        node = children[0]
    return node


def _select_arithmetic_site(source, operands, operator, *, language):
    return _select_atomic_site(source, operands, operator, language=language,
                               operators={"+", "-", "*", "/", "%", "<<", ">>"},
                               negative_literals=operator in {"/", "%", "<<", ">>"})


def _select_comparison_site(source, operands, operator, *, language):
    return _select_atomic_site(source, operands, operator, language=language,
                               operators={"<", "<=", ">", ">=", "==", "!="}, negative_literals=True)


def _select_atomic_site(source, operands, operator, *, language, operators, negative_literals):
    """Select a unique atomic binary operation or decline the query.

    C/C++ parenthesized identifiers preserve operand identity. Casts,
    fields, calls, and compound operands require a richer model and do not
    match. Addition and multiplication may reverse the two operands;
    subtraction must retain source order.
    """
    if language not in {"c", "cpp"}:
        return "unavailable", b"", None, None
    if len(source) > _MAX_SOURCE_CHARS:
        return "unavailable", b"", None, None
    if len(operands) != 2 or operator not in operators:
        return "unbound", b"", None, None
    try:
        parser = _get_parser(language)
        if parser is None:
            return "unavailable", b"", None, None
        data = source.encode("utf-8")
        root = parser.parse(data).root_node
        if root.has_error:
            return "unavailable", b"", None, None
    except Exception:
        # Optional parser setup and bounded-parse failures decline source credit.
        logger.debug("arithmetic operation parse unavailable", exc_info=True)
        return "unavailable", b"", None, None

    def text(node):
        return data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    bodies = []
    stack = [root]
    visited = 0
    while stack:
        visited += 1
        if visited > _MAX_NODES:
            return "unavailable", b"", None, None
        node = stack.pop()
        if node.type == "function_definition":
            if not ordinary_function_frame(node, data, language):
                return "unavailable", b"", None, None
            body = node.child_by_field_name("body")
            if body is not None:
                bodies.append(body)
            continue
        stack.extend(node.named_children)
    if len(bodies) != 1:
        return ("unbound" if not bodies else "ambiguous"), b"", None, None

    matches = []
    stack = [bodies[0]]
    while stack:
        visited += 1
        if visited > _MAX_NODES:
            return "unavailable", b"", None, None
        node = stack.pop()
        if node.type in {"function_definition", "lambda_expression"}:
            continue  # another callable does not execute in this function's body
        if node.type == "generic_expression" or node.type.startswith("preproc_"):
            return "unavailable", b"", None, None  # selected arms are not modeled
        if node.type == "if_statement" and any(
            child.type in {"constexpr", "consteval"} for child in node.children
        ):
            return "unavailable", b"", None, None
        if node.type == "sizeof_expression":
            pending = list(node.named_children)
            while pending:
                item = pending.pop()
                if item.type in {"array_declarator", "abstract_array_declarator"}:
                    return "unavailable", b"", None, None  # VLA extents may execute
                pending.extend(item.named_children)
        # The sizeof VLA check above must run before skipping operands.
        if unevaluated_context(node, data, language):
            continue
        if node.type == "binary_expression" and text(node.child_by_field_name("operator")) == operator:
            left = _unwrap(node.child_by_field_name("left"))
            right = _unwrap(node.child_by_field_name("right"))
            def atom(item):
                if item is None:
                    return None
                if item.type == "identifier":
                    return text(item)
                if negative_literals:
                    from .integer_literals import source_integer_atom
                    return source_integer_atom(item, data)
                return text(item) if item.type == "number_literal" and _INTEGER_LITERAL_RE.fullmatch(text(item)) else None

            pair = (atom(left), atom(right))
            if None not in pair:
                wanted = tuple(operands)
                if pair == wanted or (operator in {"+", "*"} and pair == wanted[::-1]):
                    matches.append(node)
                    if len(matches) > 1:
                        return "ambiguous", b"", None, None
        stack.extend(node.named_children)
    if not matches:
        return "unbound", b"", None, None
    return "bound", data, bodies[0], matches[0]


def bind_arithmetic_operation(source, operands, operator, *, language, integer_abi=None):
    """Bind the existing common-type arithmetic fragment to one source site."""
    if language not in {"c", "cpp"} or len(source) > _MAX_SOURCE_CHARS:
        return ArithmeticOperation("unavailable")
    if len(operands) != 2 or operator not in {"+", "-", "*", "/", "%"}:
        return ArithmeticOperation("unbound")
    status, data, body, target = _select_arithmetic_site(source, operands, operator, language=language)
    if status != "bound":
        return ArithmeticOperation(status)
    from .arithmetic_guards import guards_for_operation
    guards = guards_for_operation(body, target, data, operands,
                                  language=language, integer_abi=integer_abi)
    from .arithmetic_types import ArithmeticModel, model_for_operation
    # An incomplete execution frame has no complete integer model. Do not
    # silently rebuild a typed query from the now-empty guard tuple.
    model = (ArithmeticModel("unavailable") if guards.status == "unavailable"
             else model_for_operation(target, data, operands, operator, guards.premises, integer_abi, language=language))
    row, column = target.start_point
    return ArithmeticOperation(
        "bound", row + 1, column + 1, guards.status, guards.premises,
        model.status, model.profile, model.kind, model.domains, model.types,
    )

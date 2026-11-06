"""Bounded, canonical C integer atoms without guessed widths or suffixes."""

import re

_SIGNED_LITERAL = re.compile(r"-?(?:0[xX][0-9a-fA-F]+|0|[1-9][0-9]*)")


def integer_literal_value(text):
    """Parse syntax only; callers must establish target type and value range."""
    if not isinstance(text, str) or len(text) > 23 or not _SIGNED_LITERAL.fullmatch(text):
        return None
    magnitude = text.removeprefix("-")
    value = int(magnitude, 16 if magnitude.lower().startswith("0x") else 10)
    return -value if text.startswith("-") else value


def source_integer_atom(node, data):
    """An atomic literal, including grammar-level unary minus on a number.

    Normalize negative hex and spaced minus to decimal so all encoders see
    one signed atom. Negating an identifier, expression, or negative literal
    requires a separate evaluation/type model and is not admitted here.
    """
    from .arithmetic_operation import _unwrap
    node = _unwrap(node)
    if node is None:
        return None
    negative = False
    if node.type == "unary_expression":
        op = node.child_by_field_name("operator")
        if op is None or data[op.start_byte:op.end_byte] != b"-":
            return None
        negative = True
        node = _unwrap(node.child_by_field_name("argument"))
    if node is None or node.type != "number_literal":
        return None
    text = data[node.start_byte:node.end_byte].decode("utf-8")
    if negative and text.startswith("-"):
        return None
    value = integer_literal_value(text)
    if value is None:
        return None
    if negative:
        value = -value
    return str(value) if negative or text.startswith("-") else text

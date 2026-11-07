"""Builtin integer storage sizes under an explicitly resolved integer ABI."""

from core.smt_solver.integer_abi import resolve_integer_abi
from core.smt_solver.sizeof_model import builtin_integer_sizeof


def resolved_sizeof_values(expressions, integer_abi):
    """Resolve supported builtin types in target C bytes, never host bytes.

    Pointer, aggregate, alias and boolean storage sizes are not present in
    IntegerABI. Value-bit widths for booleans are not storage widths.
    """
    from .invariant_expression import validate_expression

    abi = resolve_integer_abi(integer_abi)
    if abi is None:
        return {}
    sizes = {}
    for expression in expressions:
        for symbol, kind in validate_expression(expression).items():
            if kind != "sizeof":
                continue
            operand = symbol[len("sizeof(") : -1]
            value = builtin_integer_sizeof(operand, abi)
            if value is not None:
                sizes[symbol] = value
    return sizes

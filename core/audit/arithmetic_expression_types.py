"""Conservative promoted types for pure prefix expressions, never source guesses."""

from .arithmetic_operation import _unwrap
from .arithmetic_evaluation import unevaluated_context
from .arithmetic_types import IntegerType, common_integer_type, integer_type
from .integer_literals import source_integer_atom, integer_literal_value

MAX_PREFIX_DEPTH = 64
_ARITHMETIC = frozenset({'+', '-', '*', '/', '%', '<<', '>>', '&', '|', '^'})
_COMPARISONS = frozenset({'<', '<=', '>', '>=', '==', '!=', '&&', '||'})


def promoted(kind):
    """Arithmetic operators consume integer promotions, not storage widths."""
    return IntegerType(kind.promoted_width, kind.promoted_signed, kind.promoted_width, kind.promoted_signed)


def expression_kind(model, node, depth=0):
    """Resolve a bounded builtin expression without erasing intermediate types.

    Mixed promoted signedness still declines except for the existing safe
    nonnegative int-literal conversion into an unsigned expression frame.
    sizeof storage and aliases have no guessed arithmetic type here.
    """
    node = _unwrap(node)
    if node is None or model.abi is None or depth > MAX_PREFIX_DEPTH:
        return None
    key = node.start_byte, node.end_byte
    if key in model._kinds:
        return model._kinds[key]
    result = None
    if node.type == 'identifier':
        result = model.kind_for_name(node)
    elif node.type == 'cast_expression':
        result = model.cast_kind(node)
    elif (atom := source_integer_atom(node, model.data)) is not None:
        result = common_integer_type([atom], (), model.abi)
    elif node.type in {'true', 'false'} or (
        node.type in {'call_expression', 'noexcept_expression'} and unevaluated_context(node, model.data, model.language)
    ):
        result = integer_type('bool' if model.language == 'cpp' else 'int', model.abi)
    elif node.type == 'unary_expression':
        child = expression_kind(model, node.child_by_field_name('argument'), depth + 1)
        operator = model.text(node.child_by_field_name('operator'))
        if child is not None and operator in {'+', '-', '~', '!'}:
            result = (integer_type('bool' if model.language == 'cpp' else 'int', model.abi)
                      if operator == '!' else promoted(child))
    elif node.type == 'binary_expression':
        left, right = (_unwrap(node.child_by_field_name(field)) for field in ('left', 'right'))
        a, b = (expression_kind(model, item, depth + 1) for item in (left, right))
        operator = model.text(node.child_by_field_name('operator'))
        if a is not None and b is not None:
            a, b = promoted(a), promoted(b)
            if operator in _COMPARISONS:
                result = integer_type('bool' if model.language == 'cpp' else 'int', model.abi)
            elif operator in {'<<', '>>'}:
                result = a
            elif operator in _ARITHMETIC:
                if a.signed == b.signed:
                    width = max(a.width, b.width)
                    result = IntegerType(width, a.signed, width, a.signed)
                else:
                    signed_node, signed_kind, unsigned_kind = (left, a, b) if a.signed else (right, b, a)
                    atom = source_integer_atom(signed_node, model.data)
                    value = integer_literal_value(atom) if atom is not None else None
                    if type(value) is int and value >= 0 and unsigned_kind.width >= signed_kind.width:
                        result = unsigned_kind
    model._kinds[key] = result
    return result

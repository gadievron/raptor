"""Bounded adjusted/remainder/mask index syntax and independent builtin integer replay."""

from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type
from .condition_extraction import _get_parser
from .integer_literals import integer_literal_value, source_integer_atom


def source_index(node, data):
    """One parameter with an optional small adjustment or positive remainder divisor."""
    node = _unwrap(node)
    if node is None:
        return None

    def text(item):
        return data[item.start_byte:item.end_byte].decode() if item is not None else ''

    if node.type == 'identifier':
        return text(node), '', 0
    if node.type != 'binary_expression':
        return None
    op = text(node.child_by_field_name('operator'))
    left, right = (_unwrap(node.child_by_field_name(field)) for field in ('left', 'right'))
    offset = integer_literal_value(source_integer_atom(right, data))
    if (op not in {'+', '-', '%', '&'} or left is None or left.type != 'identifier'
            or offset is None or offset < 0 or (op == '%' and offset == 0)):
        return None
    return text(left), op, offset


def pointer_dereference_shape(node, data):
    """One admitted `*(Array + Index)`-family dereference with its arithmetic kind.

    Returns (array_node, index_name, operator, offset, semantics, value_node).
    semantics is 'promoted' when the whole addend is the index's own integer
    arithmetic (`*(Array + (Index % 8))` computes the addend in the index's
    promoted type, exactly like a subscript) and 'pointer' when a literal
    displacement applies after the index has joined the pointer
    (`*(Array + Index + 1)`, `*(&Array[Index] - 1)`): that displacement is
    mathematical pointer arithmetic and never wraps in the index's type.
    """
    def text(item):
        return data[item.start_byte:item.end_byte].decode() if item is not None else ''

    node = _unwrap(node)
    if node is None or node.type != 'pointer_expression' or text(node.child_by_field_name('operator')) != '*':
        return None
    inner = _unwrap(node.child_by_field_name('argument'))
    if inner is None or inner.type != 'binary_expression':
        return None
    op = text(inner.child_by_field_name('operator'))
    left = _unwrap(inner.child_by_field_name('left'))
    right = _unwrap(inner.child_by_field_name('right'))
    if left is None or right is None:
        return None
    if op == '+' and left.type == 'identifier':
        # One pointer-arithmetic step: the complete addend is one integer
        # value in its own promoted type (C precedence also routes
        # `*(Array + Index % 8)` here, which is equally integer-valued).
        shape = source_index(right, data)
        if shape is None:
            return None
        return left, shape[0], shape[1], shape[2], 'promoted', right
    if op not in {'+', '-'}:
        return None
    offset = integer_literal_value(source_integer_atom(right, data))
    if offset is None or offset < 0:
        return None
    if left.type == 'binary_expression':
        # `*(Array + Index ± K)` binds left-to-right: the index joins the
        # pointer first, so the trailing literal is a pointer displacement.
        base = _unwrap(left.child_by_field_name('left'))
        index = _unwrap(left.child_by_field_name('right'))
        if (text(left.child_by_field_name('operator')) != '+' or base is None or index is None
                or base.type != 'identifier' or index.type != 'identifier'):
            return None
        return base, text(index), op, offset, 'pointer', index
    if left.type == 'pointer_expression' and text(left.child_by_field_name('operator')) == '&':
        # `*(&Array[Index] ± K)`: C defines &Array[Index] as Array + Index
        # without evaluating the element, so this is the same displacement.
        element = _unwrap(left.child_by_field_name('argument'))
        if element is None or element.type != 'subscript_expression':
            return None
        base = _unwrap(element.child_by_field_name('argument'))
        index = element.child_by_field_name('indices')
        if index is not None:
            named = [item for item in index.named_children if item.type != 'comment']
            index = named[0] if len(named) == 1 else None
        else:
            index = element.child_by_field_name('index')
        index = _unwrap(index)
        if base is None or index is None or base.type != 'identifier' or index.type != 'identifier':
            return None
        return base, text(index), op, offset, 'pointer', index
    return None


def pointer_access_claim(hypothesis):
    """Read a complete quoted pointer dereference without inventing a goal."""
    if not isinstance(hypothesis, str) or len(hypothesis) > 8192:
        return None
    pieces = hypothesis.split('`')
    if len(pieces) != 3 or len(pieces[1]) > 512 or '*' not in pieces[1]:
        return None
    try:
        data = ('int Query(void){return ' + pieces[1] + ';}').encode('utf-8')
    except UnicodeError:
        return None
    for language in ('c', 'cpp'):
        try:
            parser = _get_parser(language)
            if parser is None:
                continue
            root = parser.parse(data).root_node
        except Exception:
            continue
        functions = [node for node in root.named_children if node.type != 'comment']
        if root.has_error or len(functions) != 1 or functions[0].type != 'function_definition':
            return None
        body = functions[0].child_by_field_name('body')
        statements = [node for node in body.named_children if node.type != 'comment']
        if len(statements) != 1 or statements[0].type != 'return_statement':
            return None
        values = [node for node in statements[0].named_children if node.type != 'comment']
        shape = pointer_dereference_shape(values[0], data) if len(values) == 1 else None
        if shape is None:
            return None
        array, index, operator, offset, semantics, _ = shape
        return data[array.start_byte:array.end_byte].decode(), index, operator, offset, semantics
    return None


def affine_access_claim(hypothesis):
    """Read a complete quoted adjusted/remainder subscript without inventing a goal."""
    if not isinstance(hypothesis, str) or len(hypothesis) > 8192:
        return None
    pieces = hypothesis.split('`')
    if len(pieces) != 3 or len(pieces[1]) > 512:
        return None
    if not any(op in pieces[1] for op in ('+', '-', '%', '&')):
        return None
    try:
        data = ('int Query(void){return ' + pieces[1] + ';}').encode('utf-8')
    except UnicodeError:
        return None
    for language in ('c', 'cpp'):
        try:
            parser = _get_parser(language)
            if parser is None:
                continue
            root = parser.parse(data).root_node
        except Exception:
            continue
        functions = [node for node in root.named_children if node.type != 'comment']
        if root.has_error or len(functions) != 1 or functions[0].type != 'function_definition':
            return None
        body = functions[0].child_by_field_name('body')
        statements = [node for node in body.named_children if node.type != 'comment']
        if len(statements) != 1 or statements[0].type != 'return_statement':
            return None
        values = [node for node in statements[0].named_children if node.type != 'comment']
        access = _unwrap(values[0]) if len(values) == 1 else None
        if access is None or access.type != 'subscript_expression':
            return None
        array = _unwrap(access.child_by_field_name('argument'))
        index = access.child_by_field_name('index')
        if language == 'cpp':
            indices = access.child_by_field_name('indices')
            index = indices.named_children[0] if indices is not None and len(indices.named_children) == 1 else None
        shape = source_index(index, data)
        if array is None or array.type != 'identifier' or shape is None or not shape[1]:
            return None
        return data[array.start_byte:array.end_byte].decode(), *shape
    return None


def evaluate_array_index(access, values, integer_abi):
    """Replay the promoted operation; undefined signed arithmetic declines."""
    op, offset = access.index_operator, access.index_offset
    value = values.get(access.index)
    if (type(value) is not int or type(offset) is not int or offset < 0
            or op not in {'', '+', '-', '%', '&'} or (not op and offset != 0) or (op == '%' and offset == 0)):
        return None
    operands = [access.index, str(offset)] if op else [access.index]
    kind = common_integer_type(operands, access.parameters, integer_abi)
    if (kind is None or type(access.width) is not int or type(access.signed) is not bool
            or kind.width != access.width or kind.signed != access.signed):
        return None
    if op == '%':
        # C division truncates towards zero; Python % differs for negatives.
        quotient = abs(value) // offset
        quotient = -quotient if value < 0 else quotient
        mathematical = value - quotient * offset
    elif op == '&':
        mathematical = value & offset
    else:
        mathematical = value + offset if op == '+' else value - offset if op == '-' else value
    if kind.signed:
        low, high = -(1 << (kind.width - 1)), (1 << (kind.width - 1)) - 1
        return mathematical if low <= mathematical <= high else None
    return mathematical % (1 << kind.width)


def evaluate_pointer_index(access, values, integer_abi):
    """Replay a pointer displacement mathematically; no value ever wraps.

    Returns (intermediate, final): the element displacement before and after
    the literal adjustment. Forming a pointer outside [0, extent] or
    dereferencing outside [0, extent) is the caller's violation test; both
    conditions matter because `Array + Index` must itself stay within the
    object (one past the end at most) before the adjustment applies.
    """
    op, offset = access.index_operator, access.index_offset
    value = values.get(access.index)
    if type(value) is not int or type(offset) is not int or offset < 0 or op not in {'+', '-'}:
        return None
    kind = common_integer_type([access.index, str(offset)], access.parameters, integer_abi)
    if (kind is None or type(access.width) is not int or type(access.signed) is not bool
            or kind.width != access.width or kind.signed != access.signed):
        return None
    return value, value + offset if op == '+' else value - offset


def index_expression(access):
    """Display the actual checked index, including its bound adjustment."""
    return (f"({access.index}{access.index_operator}{access.index_offset})"
            if access.index_operator else access.index)

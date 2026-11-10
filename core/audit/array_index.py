"""Bounded affine index syntax and independent builtin integer replay."""

from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type
from .condition_extraction import _get_parser
from .integer_literals import integer_literal_value, source_integer_atom


def source_index(node, data):
    """One parameter, optionally plus/minus a nonnegative int literal."""
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
    if op not in {'+', '-'} or left is None or left.type != 'identifier' or offset is None or offset < 0:
        return None
    return text(left), op, offset


def affine_access_claim(hypothesis):
    """Read a complete quoted affine subscript, without inventing a goal."""
    if not isinstance(hypothesis, str) or len(hypothesis) > 8192:
        return None
    pieces = hypothesis.split('`')
    if len(pieces) != 3 or len(pieces[1]) > 512:
        return None
    if '+' not in pieces[1] and '-' not in pieces[1]:
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
            or op not in {'', '+', '-'} or (not op and offset != 0)):
        return None
    operands = [access.index, str(offset)] if op else [access.index]
    kind = common_integer_type(operands, access.parameters, integer_abi)
    if (kind is None or type(access.width) is not int or type(access.signed) is not bool
            or kind.width != access.width or kind.signed != access.signed):
        return None
    mathematical = value + offset if op == '+' else value - offset if op == '-' else value
    if kind.signed:
        low, high = -(1 << (kind.width - 1)), (1 << (kind.width - 1)) - 1
        return mathematical if low <= mathematical <= high else None
    return mathematical % (1 << kind.width)


def index_expression(access):
    """Display the actual checked index, including its bound adjustment."""
    return (f"({access.index}{access.index_operator}{access.index_offset})"
            if access.index_operator else access.index)

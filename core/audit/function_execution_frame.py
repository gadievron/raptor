"""Admission of ordinary function entry for bounded integer source proofs.

Body-only value domains cannot model evaluated parameter bounds, unknown
execution attributes, or the implicit setup/suspension of a coroutine.
This checks the whole selected definition, not just code before the site.
"""

_MAX_NODES = 2048
_COROUTINE_NODES = frozenset({'co_await_expression', 'co_yield_expression', 'co_return_statement', 'co_yield_statement'})


def ordinary_function_frame(function, data, language):
    """Decline unmodeled entry behavior without executing or solving source.

    Return types and unused ordinary parameters do not select an arithmetic
    result frame. Constructors and other definitions without an explicit return
    type require a separate setup model. Ordinary qualifiers remain supported.
    Nonconstant array extents and typeof are unsupported, including unused
    parameters: their types can contain evaluated size expressions. Literal
    extents and ordinary array-to-pointer adjustment need no entry effects.
    """
    body = function.child_by_field_name('body')
    result_type = function.child_by_field_name('type')
    declarator = function.child_by_field_name('declarator')
    if body is None or body.type != 'compound_statement' or declarator is None or result_type is None:
        return False

    def text(node):
        return data[node.start_byte:node.end_byte].decode('utf-8')

    for child in function.named_children:
        if child in (body, result_type, declarator) or child.type == 'comment':
            continue
        if child.type in {'storage_class_specifier', 'function_specifier'} and text(child) in {'static', 'extern', 'inline'}:
            continue
        if child.type == 'type_qualifier' and (text(child) in {'const', 'volatile'}
                                              or (language == 'cpp' and text(child) == 'constexpr')):
            continue
        return False

    # Header attributes can be attached to the function declarator instead
    # of the definition itself. Search nested type/declarator syntax too.
    pending = [child for child in function.named_children if child != body]
    visited = 0
    while pending:
        visited += 1
        if visited > _MAX_NODES:
            return False
        node = pending.pop()
        if (node.type.startswith(('attribute', 'ms_', 'typeof'))
                or node.type in {'attributed_declarator', 'gnu_asm_expression', 'macro_type_specifier', 'requires_clause'}):
            return False
        if node.type in {'array_declarator', 'abstract_array_declarator'}:
            from .integer_literals import source_integer_atom, integer_literal_value
            size = node.child_by_field_name('size')
            if size is None:
                if any(child.type == '*' for child in node.children):
                    return False
            else:
                atom = source_integer_atom(size, data) if size.type == 'number_literal' else None
                value = integer_literal_value(atom) if atom is not None else None
                if type(value) is not int or value <= 0:
                    return False
        pending.extend(node.named_children)

    if language != 'cpp':
        return True
    pending = [body]
    while pending:
        visited += 1
        if visited > _MAX_NODES:
            return False
        node = pending.pop()
        if node != body and node.type in {'function_definition', 'lambda_expression'}:
            continue  # a nested callable cannot make its owner a coroutine
        if node.type in _COROUTINE_NODES:
            return False
        pending.extend(node.named_children)
    return True

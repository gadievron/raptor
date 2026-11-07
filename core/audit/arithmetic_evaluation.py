"""Unevaluated operand contexts shared by bounded integer source checks."""

_UNEVALUATED = frozenset({
    "sizeof_expression", "alignof_expression", "decltype", "noexcept_expression",
    "requires_expression", "static_assert_declaration", "enum_specifier",
})


def unevaluated_context(node, data, language):
    """Recognize grammar contexts; C++ noexcept is a call in the pinned parser.

    A sizeof VLA is not generally unevaluated. The operation binder rejects
    array declarators in sizeof before granting this helper's skip credit.
    """
    if node.type in _UNEVALUATED:
        return True
    function = node.child_by_field_name("function") if node.type == "call_expression" else None
    return (language == "cpp" and function is not None
            and data[function.start_byte:function.end_byte] == b"noexcept")

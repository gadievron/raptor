"""C initializer boundaries and syntax-aware integer-value uses."""


def initializer_text(text: str) -> str:
    """Stop before the next declarator or statement, keeping nested expressions.

    The caller supplies a comment/literal-blanked view starting after '='.
    This is a lexical boundary, not expression typing or a range proof.
    """
    stack: list[str] = []
    closers = {"(": ")", "[": "]", "{": "}"}
    for index, char in enumerate(text):
        if char in closers:
            stack.append(closers[char])
        elif char in ")]}":
            if not stack or stack[-1] != char:
                return text[:index]
            stack.pop()
        elif char in ",;" and not stack:
            return text[:index]
    return text


def initializer_may_use_value(value, source: bytes, variable: str, *, language="c") -> bool:
    """Whether a C initializer may convert this variable's integer value.

    Grouping and casts preserve value uses. Call arguments, scalar sizeof,
    boolean results, indices and conditional selectors do not themselves
    supply the wide integer being converted. This is candidate extraction,
    not callee-return typing or a proof of the expression's range.
    """
    if value is None:
        return True
    stack = [value]
    while stack:
        node = stack.pop()
        kind = node.type
        if kind == "call_expression":
            function = node.child_by_field_name("function")
            named_cast = function.child_by_field_name("name") if function is not None and function.type == "template_function" else None
            cast_name = source[named_cast.start_byte:named_cast.end_byte].decode("utf-8") if named_cast is not None else ""
            if language == "cpp" and function is not None and (
                function.type in {"primitive_type", "sized_type_specifier"}
                or cast_name in {"static_cast", "const_cast", "reinterpret_cast", "dynamic_cast"}
            ):
                arguments = node.child_by_field_name("arguments")
                if arguments is None:
                    return True  # grammar drift must not erase a conversion
                stack.extend(arguments.named_children)
            continue
        if kind in {"alignof_expression", "type_descriptor"}:
            continue
        if kind == "identifier":
            if source[node.start_byte : node.end_byte].decode("utf-8") == variable:
                return True
            continue
        if kind == "sizeof_expression":
            # Scalar operands are unevaluated. A VLA type can depend on
            # runtime dimensions, so retain possible value uses there.
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                stack.extend(type_node.named_children)
            continue
        if kind == "generic_expression":
            # The controlling expression is unevaluated; result arms may
            # supply a value. Selecting an arm requires type resolution.
            stack.extend(node.named_children[1:])
            continue
        if kind in {"binary_expression", "unary_expression", "pointer_expression"}:
            operator = node.child_by_field_name("operator")
            op = (
                source[operator.start_byte : operator.end_byte].decode("utf-8")
                if operator is not None
                else ""
            )
            if (
                (
                    kind == "binary_expression"
                    and op in {"<", "<=", ">", ">=", "==", "!=", "&&", "||"}
                )
                or (kind == "unary_expression" and op == "!")
                or (kind == "pointer_expression" and op == "&")
            ):
                continue
        if kind in {
            "cast_expression",
            "assignment_expression",
            "comma_expression",
            "subscript_expression",
        }:
            field = {
                "cast_expression": "value",
                "assignment_expression": "right",
                "comma_expression": "right",
                "subscript_expression": "argument",
            }[kind]
            child = node.child_by_field_name(field)
            if child is None:
                return True  # grammar drift must not erase a candidate
            stack.append(child)
            continue
        if kind == "conditional_expression":
            # The GNU omitted-middle form reuses its condition as a value.
            consequence = node.child_by_field_name(
                "consequence"
            ) or node.child_by_field_name("condition")
            alternative = node.child_by_field_name("alternative")
            if consequence is None or alternative is None:
                return True
            stack.extend((consequence, alternative))
            continue
        stack.extend(node.named_children)
    return False

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



def _builtin_scalar_value(node, source, depth=0):
    """Recognise builtin C++ results before excluding Boolean operators.

    Unresolved calls, aliases and class operands may select an
    overloaded operator whose result is not Boolean. No widths are inferred.
    """
    if node is None or depth > 64:
        return False
    children = [child for child in node.named_children if child.type != "comment"]
    kind = node.type
    if kind in {"number_literal", "char_literal", "string_literal", "concatenated_string",
                "true", "false", "sizeof_expression", "alignof_expression",
                "requires_expression", "noexcept_expression"}:
        return True
    if kind == "identifier":
        from .narrowing_bindings import visible_declarations

        name = source[node.start_byte:node.end_byte].decode("utf-8")
        record = visible_declarations(node, source, language="cpp").get(name)
        if record is None or record[1].type not in {"declaration", "parameter_declaration", "optional_parameter_declaration"}:
            return False
        owner = node.parent
        while owner is not None and owner.type not in {"function_definition", "lambda_expression"}:
            owner = owner.parent
        declaration = record[1]
        if owner is None or not owner.start_byte <= declaration.start_byte < declaration.end_byte <= owner.end_byte:
            return False  # globals may be hidden by unresolved C++ member/namespace lookup
        pending = [owner]
        for _ in range(2048):
            if not pending:
                break
            item = pending.pop()
            if (declaration.start_byte <= item.start_byte < declaration.end_byte
                    and item.type.startswith(("attribute", "ms_", "declspec"))):
                return False
            if item.type == "using_declaration" and any(child.type == "enum" for child in item.children):
                return False  # imported enumerators need name/type resolution
            if item != owner and item.type in {"function_definition", "lambda_expression"}:
                continue
            pending.extend(item.named_children)
        else:
            return False  # incomplete lookup cannot establish builtin operands
        base = declaration.child_by_field_name("type")
        return base is not None and base.type in {"primitive_type", "sized_type_specifier"}
    if kind == "type_descriptor":
        base = node.child_by_field_name("type")
        return (base is not None and base.type in {"primitive_type", "sized_type_specifier"}
                and all(child == base or child.type == "type_qualifier" for child in children))
    if kind == "cast_expression":
        return _builtin_scalar_value(node.child_by_field_name("type"), source, depth + 1)
    if kind == "call_expression":
        function = node.child_by_field_name("function")
        if function is None:
            return False
        if function.type in {"primitive_type", "sized_type_specifier"}:
            return True
        name = function.child_by_field_name("name") if function.type == "template_function" else function
        spelling = source[name.start_byte:name.end_byte] if name is not None else b""
        if spelling == b"noexcept":
            return True
        if spelling in {b"static_cast", b"const_cast", b"reinterpret_cast", b"dynamic_cast"}:
            arguments = function.child_by_field_name("arguments")
            types = [child for child in arguments.named_children if child.type != "comment"] if arguments is not None else []
            return len(types) == 1 and _builtin_scalar_value(types[0], source, depth + 1)
        return False
    if kind == "subscript_expression":
        index = node.child_by_field_name("index")
        indices = node.child_by_field_name("indices")
        if indices is not None:
            items = [child for child in indices.named_children if child.type != "comment"]
            index = items[0] if len(items) == 1 else None
        return (_builtin_scalar_value(node.child_by_field_name("argument"), source, depth + 1)
                and _builtin_scalar_value(index, source, depth + 1))
    if kind == "assignment_expression":
        return _builtin_scalar_value(node.child_by_field_name("left"), source, depth + 1)
    if kind in {"parenthesized_expression", "expression_statement", "unary_expression",
                "pointer_expression", "update_expression"}:
        return len(children) == 1 and _builtin_scalar_value(children[0], source, depth + 1)
    if kind in {"binary_expression", "comma_expression"}:
        return all(_builtin_scalar_value(node.child_by_field_name(field), source, depth + 1)
                   for field in ("left", "right"))
    if kind == "conditional_expression":
        return all(_builtin_scalar_value(child, source, depth + 1) for child in (
            node.child_by_field_name("consequence") or node.child_by_field_name("condition"),
            node.child_by_field_name("alternative"),
        ))
    if kind == "compound_statement":
        return bool(children) and children[-1].type == "expression_statement" and _builtin_scalar_value(children[-1], source, depth + 1)
    return False


def initializer_may_use_value(value, source: bytes, variable: str, *, language="c") -> bool:
    """Whether a C initializer may convert this variable's integer value.

    Grouping and casts preserve value uses. Call arguments, scalar sizeof,
    Boolean results (including C++ requirements), indices and conditional
    selectors do not themselves supply the wide integer being converted.
    This is candidate extraction, not callee-return typing or a proof of
    the expression's range. Unresolved C++ operator results retain possible
    leads, including assignment, comma and subscript overloads.
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
        if kind == "compound_statement":
            # A GNU statement expression supplies its final expression's
            # value. Earlier evaluated statements do not supply that value.
            children = [child for child in node.named_children if child.type != "comment"]
            if children and children[-1].type == "expression_statement":
                stack.append(children[-1])
            else:
                stack.extend(children)  # unknown result syntax retains leads
            continue
        if kind in {"alignof_expression", "type_descriptor", "requires_expression"}:
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
            if language == "cpp":
                op = {"and": "&&", "or": "||", "not": "!", "not_eq": "!="}.get(op, op)
            boolean_operator = (
                (
                    kind == "binary_expression"
                    and op in {"<", "<=", ">", ">=", "==", "!=", "&&", "||"}
                )
                or (kind == "unary_expression" and op == "!")
            )
            if boolean_operator and (language != "cpp" or _builtin_scalar_value(node, source)):
                continue
            if (kind == "pointer_expression" and op == "&"
                    and (language != "cpp" or _builtin_scalar_value(node, source))):
                continue
        if kind == "assignment_expression":
            operator = node.child_by_field_name("operator")
            right = node.child_by_field_name("right")
            if operator is None or right is None:
                return True
            left = node.child_by_field_name("left")
            if left is None:
                return True
            if (source[operator.start_byte : operator.end_byte] != b"="
                    or language == "cpp" and not _builtin_scalar_value(left, source)):
                # Compound assignments and unresolved C++ assignment overloads
                # may supply a result from their left operand.
                stack.append(left)
            stack.append(right)
            continue
        if (language == "cpp" and kind in {"comma_expression", "subscript_expression"}
                and not _builtin_scalar_value(node, source)):
            stack.extend(node.named_children)
            continue
        if kind in {
            "cast_expression",
            "comma_expression",
            "subscript_expression",
        }:
            field = {
                "cast_expression": "value",
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

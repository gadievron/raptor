"""Lexically visible C/C++ declarations at one selected source location."""


def _node_source(node, source):
    return (
        source[node.start_byte : node.end_byte].decode("utf-8")
        if node is not None
        else ""
    )


def _inner_declarator(node):
    child = node.child_by_field_name("declarator")
    if child is None and node.type in {
        "parenthesized_declarator", "reference_declarator", "attributed_declarator",
    }:
        children = [item for item in node.named_children
                    if item.type in {"identifier", "type_identifier", "structured_binding_declarator"}
                    or item.type.endswith("_declarator")]
        if len(children) == 1:
            child = children[0]
    return child


def callable_declarator(node):
    """Select the function's own parameters, not a returned callable type.

    The callable nearest the declared name owns its entry parameters. This
    also supports a lambda's abstract function declarator.
    """
    declarator = node.child_by_field_name("declarator")
    selected = None
    while declarator is not None:
        if declarator.child_by_field_name("parameters") is not None:
            selected = declarator
        declarator = _inner_declarator(declarator)
    return selected


def _declarator_names(declarator, source):
    while declarator is not None:
        if declarator.type == "identifier":
            return [_node_source(declarator, source)]
        if declarator.type == "structured_binding_declarator":
            return [_node_source(item, source) for item in declarator.named_children
                    if item.type == "identifier"]
        declarator = _inner_declarator(declarator)
    return []


def _declarations(node, source, *, before=None):
    result = {}
    type_node = (
        node if node.type == "enum_specifier" else node.child_by_field_name("type")
    )
    type_name = _node_source(type_node, source)
    if any(child.type.startswith(("attribute", "ms_", "declspec")) for child in node.named_children):
        type_name = None  # modifiers can change storage width or value type
    if (type_node is not None and type_node.type == "enum_specifier"
            and not any(child.type in {"class", "struct"} for child in type_node.children)):
        body = type_node.child_by_field_name("body")
        if body is not None:
            for item in body.named_children:
                name = item.child_by_field_name("name")
                if name is not None:
                    result[_node_source(name, source)] = (None, node)
    for declarator in node.children_by_field_name("declarator"):
        if before is not None and declarator.start_byte > before:
            continue
        if declarator.type == "init_declarator":
            declarator = declarator.child_by_field_name("declarator")
        if declarator is None:
            continue
        plain = declarator.type == "identifier"
        # Unsupported, structured and pointer declarations still shadow.
        for name in _declarator_names(declarator, source):
            result[name] = (type_name if plain else None, node)
    return result


def _preceding_declarations(node, source, before):
    result = {}
    for child in node.named_children:
        if child.start_byte >= before:
            break
        if child.end_byte <= before and child.type in {"declaration", "enum_specifier"}:
            result.update(_declarations(child, source))
        elif child.type in {"labeled_statement", "case_statement"}:
            # Labels do not introduce a C scope; braces do.
            result.update(_preceding_declarations(child, source, before))
    return result


def visible_declarations(target, source: bytes):
    """Collect only declarations in scopes containing this source use.

    Unknown types and non-scalar declarators mask outer names. No type is
    borrowed from another function, a sibling block, or a later declaration.
    """
    chain = []
    node = target
    while node is not None:
        chain.append(node)
        node = node.parent
    result = {}
    for node in reversed(chain):
        if node.type in {
            "translation_unit",
            "compound_statement",
            "labeled_statement",
            "case_statement",
        }:
            result.update(_preceding_declarations(node, source, target.start_byte))
        elif node.type in {"function_definition", "lambda_expression", "catch_clause"}:
            if node.type == "lambda_expression":
                body = node.child_by_field_name("body")
                if body is None or not body.start_byte <= target.start_byte < body.end_byte:
                    continue  # init-capture initialisers still use the outer scope
                captures = node.child_by_field_name("captures")
                for capture in captures.named_children if captures is not None else ():
                    if capture.type == "lambda_capture_initializer":
                        for name in _declarator_names(capture.child_by_field_name("left"), source):
                            result[name] = (None, capture)  # no auto deduction/value-flow model
            declarator = callable_declarator(node)
            params = (node.child_by_field_name("parameters") if node.type == "catch_clause"
                      else declarator.child_by_field_name("parameters") if declarator is not None else None)
            if params is not None:
                for param in params.named_children:
                    if param.type in {"parameter_declaration", "optional_parameter_declaration"}:
                        result.update(_declarations(param, source))
        elif node.type in {"if_statement", "switch_statement", "while_statement", "for_statement", "for_range_loop"}:
            condition = node.child_by_field_name("condition")
            initial = node.child_by_field_name("initializer")
            if condition is not None and condition.type == "condition_clause":
                initial = condition.child_by_field_name("initializer") or initial
                condition = condition.child_by_field_name("value")
            for declaration in (initial, condition):
                if declaration is not None and declaration.type == "init_statement":
                    declaration = next((item for item in declaration.named_children if item.type == "declaration"), None)
                if declaration is not None and declaration.type == "declaration":
                    result.update(_declarations(declaration, source, before=target.start_byte))
            if node.type == "for_range_loop":
                body = node.child_by_field_name("body")
                if body is not None and body.start_byte <= target.start_byte < body.end_byte:
                    result.update(_declarations(node, source))
        elif node.type == "declaration":
            result.update(_declarations(node, source, before=target.start_byte))
    return result


def visible_types(target, source: bytes) -> dict[str, str | None]:
    """Type-only view of the shared, lexically visible declaration records."""
    return {name: record[0] for name, record in visible_declarations(target, source).items()}

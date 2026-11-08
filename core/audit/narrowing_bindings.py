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
        if declarator.type in {"identifier", "type_identifier"}:
            return [_node_source(declarator, source)]
        if declarator.type == "structured_binding_declarator":
            return [_node_source(item, source) for item in declarator.named_children
                    if item.type == "identifier"]
        declarator = _inner_declarator(declarator)
    return []


def _enum_declarations(node, source, *, before=None, language="c"):
    """C records introduce no scope for their enumeration constants.

    Stop at actual block and prototype scopes. C++ records own their
    members, so only the declaration's direct unscoped enum is visible.
    """
    if language != "c":
        node = node if node.type == "enum_specifier" else node.child_by_field_name("type")
        while node is not None and node.type == "type_descriptor":
            node = node.child_by_field_name("type")
        if node is None or node.type != "enum_specifier":
            return {}
    result, pending = {}, [node]
    scopes = {"compound_statement", "function_definition", "function_declarator",
              "abstract_function_declarator", "parameter_list", "if_statement",
              "switch_statement", "for_statement", "while_statement", "do_statement"}
    while pending:
        item = pending.pop()
        if before is not None and item.start_byte >= before:
            continue
        if item.type in scopes or item.type.startswith("preproc_"):
            continue
        if item.type == "enum_specifier":
            body = item.child_by_field_name("body")
            if body is not None and not any(child.type in {"class", "struct"} for child in item.children):
                for enumerator in body.named_children:
                    name = enumerator.child_by_field_name("name")
                    if name is not None and (before is None or enumerator.end_byte <= before):
                        result[_node_source(name, source)] = (None, item)
        pending.extend(reversed(item.named_children))
    return result


def _type_bindings(node, source, *, before=None, language="c"):
    """Mask hidden values without inventing storage layouts for type names."""
    names = []
    if node.type == "type_definition":
        for declarator in node.children_by_field_name("declarator"):
            if before is None or declarator.end_byte <= before:
                names.extend(_declarator_names(declarator, source))
    elif node.type == "alias_declaration":
        name = node.child_by_field_name("name")
        target = node.child_by_field_name("type")
        if name is not None and (before is None or target is not None and target.end_byte <= before):
            names.append(_node_source(name, source))
    if language == "cpp":
        kinds = {"struct_specifier", "union_specifier", "class_specifier", "enum_specifier"}
        kind = node if node.type in kinds else node.child_by_field_name("type")
        while kind is not None and kind.type == "type_descriptor":
            kind = kind.child_by_field_name("type")
        if kind is not None and kind.type in kinds:
            name = kind.child_by_field_name("name")
            if name is not None and (before is None or name.end_byte <= before):
                names.append(_node_source(name, source))
        if node.type == "using_declaration" and not any(child.type in {"namespace", "enum"} for child in node.children):
            for item in node.named_children:
                name = item.child_by_field_name("name") if item.type == "qualified_identifier" else None
                if name is not None and name.type in {"identifier", "type_identifier"} and (before is None or node.end_byte <= before):
                    names.append(_node_source(name, source))
    return {name: (None, node) for name in names}


def _declarations(node, source, *, before=None, language="c"):
    result = {}
    result.update(_type_bindings(node, source, before=before, language=language))
    type_node = (
        node if node.type == "enum_specifier" else node.child_by_field_name("type")
    )
    type_name = _node_source(type_node, source)
    if any(child.type.startswith(("attribute", "ms_", "declspec")) for child in node.named_children):
        type_name = None  # modifiers can change storage width or value type
    result.update(_enum_declarations(node, source, before=before, language=language))
    if node.type == "type_definition":
        return result  # typedef names begin after their complete declarators
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


def _preceding_declarations(node, source, before, language):
    result = {}
    for child in node.named_children:
        if child.start_byte >= before:
            break
        if child.end_byte <= before:
            result.update(_enum_declarations(child, source, before=before, language=language))
        if child.end_byte <= before and child.type in {
            "declaration", "enum_specifier", "type_definition", "alias_declaration", "using_declaration",
            "struct_specifier", "union_specifier", "class_specifier",
        }:
            result.update(_declarations(child, source, language=language))
        elif child.type in {"labeled_statement", "case_statement"}:
            # Labels do not introduce a C scope; braces do.
            result.update(_preceding_declarations(child, source, before, language))
    return result


def visible_declarations(target, source: bytes, *, language="c"):
    """Collect only declarations in scopes containing this source use.

    Unknown types and non-scalar declarators mask outer names. No type is
    borrowed from another function, a sibling block, or a later declaration.
    """
    if language is None:
        language = "c"
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
            result.update(_preceding_declarations(node, source, target.start_byte, language))
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
                        result.update(_declarations(param, source, before=target.start_byte, language=language))
        elif node.type in {"if_statement", "switch_statement", "while_statement", "for_statement", "for_range_loop"}:
            condition = node.child_by_field_name("condition")
            initial = node.child_by_field_name("initializer")
            if language == "c":
                for field in ("initializer", "condition", "update"):
                    header = node.child_by_field_name(field)
                    if header is not None:
                        result.update(_enum_declarations(header, source, before=target.start_byte, language=language))
            if condition is not None and condition.type == "condition_clause":
                initial = condition.child_by_field_name("initializer") or initial
                condition = condition.child_by_field_name("value")
            for declaration in (initial, condition):
                if declaration is not None and declaration.type == "init_statement":
                    declaration = next((item for item in declaration.named_children if item.type == "declaration"), None)
                if declaration is not None and declaration.type == "declaration":
                    result.update(_declarations(declaration, source, before=target.start_byte, language=language))
            if node.type == "for_range_loop":
                body = node.child_by_field_name("body")
                if body is not None and body.start_byte <= target.start_byte < body.end_byte:
                    result.update(_declarations(node, source, language=language))
        elif node.type in {"declaration", "type_definition", "alias_declaration"}:
            result.update(_declarations(node, source, before=target.start_byte, language=language))
    return result


def visible_types(target, source: bytes, *, language="c") -> dict[str, str | None]:
    """Type-only view of the shared, lexically visible declaration records."""
    return {name: record[0] for name, record in visible_declarations(target, source, language=language).items()}

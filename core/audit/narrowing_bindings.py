"""Lexically visible C declaration types at one narrowing initializer."""


def _node_source(node, source):
    return (
        source[node.start_byte : node.end_byte].decode("utf-8")
        if node is not None
        else ""
    )


def _declarations(node, source, *, before=None):
    result = {}
    type_node = (
        node if node.type == "enum_specifier" else node.child_by_field_name("type")
    )
    type_name = _node_source(type_node, source)
    if type_node is not None and type_node.type == "enum_specifier":
        body = type_node.child_by_field_name("body")
        if body is not None:
            for item in body.named_children:
                name = item.child_by_field_name("name")
                if name is not None:
                    result[_node_source(name, source)] = None
    for declarator in node.children_by_field_name("declarator"):
        if before is not None and declarator.start_byte > before:
            continue
        if declarator.type == "init_declarator":
            declarator = declarator.child_by_field_name("declarator")
        if declarator is None:
            continue
        plain = declarator.type == "identifier"
        # Even unsupported/pointer declarations shadow an outer integer.
        while declarator is not None and declarator.type != "identifier":
            child = declarator.child_by_field_name("declarator")
            if (
                child is None
                and declarator.type == "parenthesized_declarator"
                and len(declarator.named_children) == 1
            ):
                child = declarator.named_children[0]
            declarator = child
        if declarator is not None:
            result[_node_source(declarator, source)] = type_name if plain else None
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


def visible_types(target, source: bytes) -> dict[str, str | None]:
    """Collect only declarations in scopes containing this initializer.

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
        elif node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            while declarator is not None and declarator.type != "function_declarator":
                declarator = declarator.child_by_field_name("declarator")
            params = (
                declarator.child_by_field_name("parameters")
                if declarator is not None
                else None
            )
            if params is not None:
                for param in params.named_children:
                    if param.type == "parameter_declaration":
                        result.update(_declarations(param, source))
        elif node.type == "for_statement":
            initial = node.child_by_field_name("initializer")
            if (
                initial is not None
                and initial.type == "declaration"
                and initial.end_byte <= target.start_byte
            ):
                result.update(_declarations(initial, source))
        elif node.type == "declaration":
            result.update(_declarations(node, source, before=target.start_byte))
    return result

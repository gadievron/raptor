"""Negative validator-row value-epoch checks over native syntax.

These checks reject visible writes. Passing does not establish exact call
binding, source types, alias effects or the meaning of an unknown callee.
"""
from __future__ import annotations

from core.analysis import validator_control_scope as _syntax


def _write_target(node):
    if node.type in {"assignment_expression", "augmented_assignment_expression"}:
        return node.child_by_field_name("left")
    if node.type in {"variable_declarator", "function_declaration",
                     "generator_function_declaration", "class_declaration", "enum_declaration"}:
        return node.child_by_field_name("name")
    if node.type == "update_expression":
        target = node.child_by_field_name("argument")
        if target is not None:
            return target
        return node.named_children[0] if len(node.named_children) == 1 else node
    return None


def _target_mentions(target, name: bytes) -> bool:
    pending = [target]
    visited = 0
    while pending:
        node = pending.pop()
        visited += 1
        if visited > 256:
            return True  # Unresolved large binding patterns cannot preserve an epoch.
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            if node.text == name or b"\\" in node.text:
                return True  # Escaped binding names require identity resolution.
        pending.extend(node.named_children)
    return False


def _write_reaches_later_iteration(node, validator_line: int, sink_line: int) -> bool:
    """An enclosing loop can revisit a sink without refreshing an outer guard."""
    parent = node.parent
    visited = 0
    while parent is not None:
        visited += 1
        if visited > 256:
            return True
        if parent.type in _syntax._JAVA_LOOPS | _syntax._JS_LOOPS:
            first, last = parent.start_point[0] + 1, parent.end_point[0] + 1
            if first <= sink_line <= last and not first <= validator_line <= last:
                return True
        parent = parent.parent
    return False


def validator_row_epoch_unverified(source: str, name: str, validator_line: int,
                                    *, language: str) -> bool:
    """Refuse same-row writes beyond the independently established validation.

    A guard's own exiting arm may write before returning; its alternative
    and subsequent statements cannot reuse the old constraint. A returned
    validator may define its output once; repeated same-name definitions
    remain ambiguous until an exact native binding offset is established.
    """
    if validator_line <= 0:
        return True
    try:
        tree = _syntax._native_source_tree(source, language)
        if tree is None:
            return True
        encoded_name = name.encode("utf-8")
        guards = []
        writes = []
        pending = [tree.root_node]
        visited = 0
        while pending:
            node = pending.pop()
            visited += 1
            if visited > _syntax._MAX_NODES:
                return True
            if node.start_point[0] + 1 == validator_line:
                if node.type == "if_statement":
                    guards.append(node)
                target = _write_target(node)
                if target is not None and _target_mentions(target, encoded_name):
                    writes.append(node)
            pending.extend(node.named_children)
        if guards:
            if len(guards) != 1:
                return True
            guard = guards[0]
            alternative = guard.child_by_field_name("alternative")
            return any(write.start_byte >= guard.end_byte or _syntax._contains(alternative, write)
                       for write in writes)
        return len(writes) > 1
    except Exception:  # noqa: BLE001 -- failed syntax binding cannot preserve an epoch
        return True


def _shared_slot_epoch_unverified(tree, name: bytes, after_line: int, through_line: int) -> bool:
    """Opaque calls and suspensions cannot freeze shared name bindings.

    Preserve only simple parameters and direct function-body local slots,
    with no possible nested writer. This is negative ownership filtering,
    not a general closure, alias or callee-effect model.
    """
    nodes = []
    ownership = {}
    deferred = {}
    pending = [(tree.root_node, None, False)]
    while pending:
        node, scope, class_body = pending.pop()
        class_body = class_body or node.type == "class_body"
        if node.type in _syntax._JS_OWNERS:
            scope = node
        nodes.append(node)
        if len(nodes) > _syntax._MAX_NODES:
            return True
        ownership[node.id] = scope
        deferred[node.id] = class_body
        pending.extend((child, scope, class_body) for child in node.named_children)
    anchors = [node for node in nodes
               if node.start_point[0] + 1 == after_line
               and node.type in {"if_statement", "variable_declarator", "assignment_expression"}]
    owners = [ownership[node.id] for node in anchors]
    if not owners or any(owner is None or owner != owners[0] for owner in owners):
        return True
    owner = owners[0]
    exposes_slot = any(
        ((node.type in {"await_expression", "yield_expression"}
          or (node.type == "for_in_statement" and any(child.type == "await" for child in node.children)))
         and after_line < node.start_point[0] + 1 <= through_line)
        or (node.type in {"call_expression", "new_expression"}
            and after_line < node.start_point[0] + 1 < through_line)
        for node in nodes if ownership[node.id] == owner
    )
    if not exposes_slot:
        return False
    if owner.type == "program":
        return True
    body = owner.child_by_field_name("body")
    parameters = owner.child_by_field_name("parameters")
    parameter = owner.child_by_field_name("parameter")
    candidates = list(parameters.named_children) if parameters is not None else []
    if parameter is not None:
        candidates.append(parameter)
    local = False
    for candidate in candidates:
        if candidate.type in {"required_parameter", "optional_parameter"}:
            candidate = candidate.child_by_field_name("pattern")
        if candidate is not None and candidate.type == "identifier" and candidate.text == name:
            local = True
    for node in nodes:
        if node.type == "variable_declarator" and ownership[node.id] == owner:
            target = node.child_by_field_name("name")
            declaration = node.parent
            if (target is not None and target.type == "identifier" and target.text == name
                    and declaration is not None and declaration.parent == body):
                local = True
        target = (node.child_by_field_name("left") if node.type == "for_in_statement"
                  else _write_target(node))
        if (target is not None and _syntax._contains(owner, node)
                and (ownership[node.id] != owner or deferred[node.id])
                and _target_mentions(target, name)):
            return True
    return not local


def native_value_epoch_unverified(source: str, name: str, after_line: int,
                                    through_line: int, *, language: str) -> bool:
    """Refuse new bindings and implicit writes absent from assignment scans.

    This supplies a negative write fact, not declaration identity or a
    complete effect proof. An unavailable native profile remains unverified.
    """
    if after_line <= 0 or through_line < after_line:
        return True
    try:
        tree = _syntax._native_source_tree(source, language)
        if tree is None:
            return True
        encoded_name = name.encode("utf-8")
        if language in {"javascript", "typescript", "tsx"} and _shared_slot_epoch_unverified(
            tree, encoded_name, after_line, through_line,
        ):
            return True
        pending = [tree.root_node]
        visited = 0
        while pending:
            node = pending.pop()
            visited += 1
            if visited > _syntax._MAX_NODES:
                return True
            pending.extend(node.named_children)
            row = node.start_point[0] + 1
            forward_write = after_line < row <= through_line
            if node.type == "for_in_statement":
                target = node.child_by_field_name("left")
            elif node.type == "enhanced_for_statement":
                target = node.child_by_field_name("name")
            elif node.type == "update_expression":
                target = _write_target(node)
            elif node.type in {"assignment_expression", "augmented_assignment_expression"}:
                target = _write_target(node)
                if (forward_write and target is not None and target.type == "identifier"
                        and b"\\" not in target.text):
                    continue  # Bare names retain the lexical self-assignment check.
            elif node.type == "variable_declarator":
                target = _write_target(node)
                if target is None:
                    return True
                if target.type not in {"array_pattern", "object_pattern"}:
                    if node.type != "variable_declarator" or node.child_by_field_name("value") is not None:
                        continue
                    # A JS var redeclaration without an initialiser does not
                    # reset its existing function-scoped value.
                    parent = node.parent
                    if (language in {"javascript", "typescript", "tsx"}
                            and parent is not None and parent.type == "variable_declaration"
                            and any(child.type == "var" for child in parent.children)):
                        continue
            elif node.type in {"function_declaration", "generator_function_declaration",
                               "class_declaration", "enum_declaration"}:
                target = _write_target(node)
            else:
                continue
            if not forward_write and (
                row <= through_line or not _write_reaches_later_iteration(node, after_line, through_line)
            ):
                continue
            if target is None or _target_mentions(target, encoded_name):
                return True
        return False
    except Exception:  # noqa: BLE001 -- unverified syntax cannot preserve an epoch
        return True


def native_object_input_unverified(source: str, name: str, validator_line: int,
                                    *, language: str) -> bool:
    """Refuse visible JS object bindings that need a coercion/transfer contract.

    No observed object is not positive primitive-type evidence. Prior writes
    are conservatively inspected without choosing a reaching definition.
    """
    if language not in {"javascript", "typescript", "tsx"} or validator_line <= 0:
        return True
    try:
        tree = _syntax._native_source_tree(source, language)
        if tree is None:
            return True
        from .validator_input_binding import adjacent_native_string_input

        # A new local lexical binding immediately before the guard has
        # its own primitive value, independent of older/scoped objects.
        if adjacent_native_string_input(source, name, validator_line, language=language) is not None:
            return False
        encoded_name = name.encode("utf-8")
        object_values = {"object", "array", "function_expression", "arrow_function",
                         "generator_function", "class", "new_expression", "regex"}
        pending = [tree.root_node]
        visited = 0
        while pending:
            node = pending.pop()
            visited += 1
            if visited > _syntax._MAX_NODES:
                return True
            pending.extend(node.named_children)
            if node.start_point[0] + 1 > validator_line:
                continue
            target = _write_target(node)
            if target is None or not _target_mentions(target, encoded_name):
                continue
            if node.type in {"function_declaration", "generator_function_declaration",
                             "class_declaration", "enum_declaration"}:
                return True
            value = node.child_by_field_name("value" if node.type == "variable_declarator" else "right")
            while value is not None and value.type == "parenthesized_expression":
                children = [child for child in value.named_children if child.type != "comment"]
                value = children[0] if len(children) == 1 else None
            if value is not None and value.type in object_values:
                return True
        return False
    except Exception:  # noqa: BLE001 -- unverified native input cannot authorise a proof
        return True

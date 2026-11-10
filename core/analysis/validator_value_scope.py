"""Negative validator-row value-epoch checks over native syntax.

These checks reject visible writes. Passing does not establish exact call
binding, source types, alias effects or the meaning of an unknown callee.
"""
from __future__ import annotations

from core.analysis import validator_control_scope as _syntax


def _write_target(node):
    if node.type in {"assignment_expression", "augmented_assignment_expression"}:
        return node.child_by_field_name("left")
    if node.type == "variable_declarator":
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
        if node.type in {"identifier", "shorthand_property_identifier_pattern"} and node.text == name:
            return True
        pending.extend(node.named_children)
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

"""Native direct-result bindings for curated validator call models.

This binds syntax, not runtime library origin, input types or sink slots.
"""
from __future__ import annotations

import re

from core.analysis import validator_control_scope as _syntax

_COMMENTS = frozenset({"comment", "line_comment", "block_comment", "html_comment"})
_DOTTED_NAME = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")


def _parenthesised_value(value):
    while value is not None and value.type == "parenthesized_expression":
        children = [node for node in value.named_children
                    if node.type not in _COMMENTS]
        if len(children) != 1:
            return None
        value = children[0]
    return value


def _callee_parts(value):
    if value.type == "call_expression":
        callee = value.child_by_field_name("function")
        if callee is None:
            return None
        text = callee.text.decode("utf-8")
    elif value.type == "method_invocation":
        name = value.child_by_field_name("name")
        receiver = value.child_by_field_name("object")
        if name is None:
            return None
        text = ((receiver.text.decode("utf-8") + ".") if receiver is not None else "") + name.text.decode("utf-8")
    else:
        return None
    text = "".join(text.split())
    return text.split(".") if _DOTTED_NAME.fullmatch(text) else None


def native_transform_binding_targets(source: str, line: int, library_call: str,
                                      *, language: str) -> set[str]:
    """Names bound directly to the matched call result on a raw LF row.

    Parentheses preserve the call's value. Containers, selections,
    concatenations and unknown wrappers require separate transfer proof.
    Callee suffix matching retains the caller's existing import spelling
    profile; it is not positive evidence of runtime library identity.
    """
    if line <= 0:
        return set()
    try:
        tree = _syntax._native_source_tree(source, language)
        if tree is None:
            return set()
        expected = library_call.split(".")
        targets = set()
        pending = [tree.root_node]
        visited = 0
        while pending:
            node = pending.pop()
            visited += 1
            if visited > _syntax._MAX_NODES:
                return set()
            pending.extend(node.named_children)
            if node.start_point[0] + 1 != line:
                continue
            if node.type == "variable_declarator":
                target, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            elif node.type == "assignment_expression" and any(child.type == "=" for child in node.children):
                target, value = node.child_by_field_name("left"), node.child_by_field_name("right")
            else:
                continue
            value = _parenthesised_value(value)
            if target is None or target.type != "identifier" or value is None:
                continue
            actual = _callee_parts(value)
            if actual and actual == expected[-len(actual):]:
                targets.add(target.text.decode("utf-8"))
        return targets
    except Exception:  # noqa: BLE001 -- failed syntax binding supplies no targets
        return set()



def _sink_statement_value(statement):
    if statement.type in {"expression_statement", "return_statement"}:
        children = [node for node in statement.named_children if node.type not in _COMMENTS]
        return children[0] if len(children) == 1 else None
    if statement.type in {"lexical_declaration", "variable_declaration", "local_variable_declaration"}:
        declarations = [node for node in statement.named_children if node.type == "variable_declarator"]
        return declarations[0].child_by_field_name("value") if len(declarations) == 1 else None
    return None


def native_sink_reads_name(source: str, line: int, name: str, *, language: str) -> bool:
    """Observe one direct native sink value, not a property or callee name.

    Without a column/slot contract, multiple statements, extra arguments,
    containers and transformed expressions are unverified. This is a
    syntax-shape check; name binding, epochs, types and effects remain
    separate consumer obligations.
    """
    if line <= 0:
        return False
    try:
        tree = _syntax._native_source_tree(source, language)
        if tree is None:
            return False
        statements = []
        pending = [tree.root_node]
        visited = 0
        while pending:
            node = pending.pop()
            visited += 1
            if visited > _syntax._MAX_NODES:
                return False
            row = line - 1
            if (node.start_point[0] < row <= node.end_point[0]
                    and (node.end_point[0] > row or node.end_point[1] > 0)
                    and _sink_statement_value(node) is not None):
                return False
            if node.start_point[0] + 1 == line and (
                node.type.endswith("_statement") or node.type in {
                    "statement_block", "block", "lexical_declaration", "variable_declaration",
                    "local_variable_declaration", "class_declaration", "function_declaration",
                    "generator_function_declaration",
                }
            ):
                statements.append(node)
            pending.extend(node.named_children)
        if len(statements) != 1:
            return False
        value = _parenthesised_value(_sink_statement_value(statements[0]))
        if value is not None and value.type == "assignment_expression":
            if not any(child.type == "=" for child in value.children):
                return False
            value = _parenthesised_value(value.child_by_field_name("right"))
        if value is not None and value.type in {"call_expression", "method_invocation"}:
            arguments = value.child_by_field_name("arguments")
            if arguments is None:
                return False
            children = [node for node in arguments.named_children if node.type not in _COMMENTS]
            if len(children) != 1:
                return False
            value = _parenthesised_value(children[0])
        return value is not None and value.type == "identifier" and value.text == name.encode("utf-8")
    except Exception:  # noqa: BLE001 -- unverified syntax cannot establish a consumed value
        return False

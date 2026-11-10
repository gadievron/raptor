"""Negative Java control-ownership checks for source validator proofs.

A passing check is not dominance evidence. Callers must retain their
existing exit-on-failure, value-flow and language-property checks.
"""
from __future__ import annotations

from core.source.java_unicode import java_unicode_unverified

_STATEMENTS = frozenset({"expression_statement", "local_variable_declaration",
                         "return_statement", "throw_statement"})
_OWNERS = frozenset({"method_declaration", "constructor_declaration", "lambda_expression"})
_LOOPS = frozenset({"while_statement", "do_statement", "for_statement", "enhanced_for_statement"})
_UNSUPPORTED = frozenset({"try_statement", "try_with_resources_statement", "catch_clause",
                          "finally_clause", "switch_expression", "switch_statement",
                          "switch_block_statement_group", "switch_rule", "synchronized_statement",
                          "labeled_statement"})
_MAX_NODES = 100_000


def _contains(parent, child):
    return (parent is not None and parent.start_byte <= child.start_byte
            and child.end_byte <= parent.end_byte)


def _owner(node):
    while node is not None:
        if node.type in _OWNERS:
            return node
        node = node.parent
    return None


def java_guard_scope_unverified(source: str, validator_line: int, sink_line: int,
                                *, guard_shaped: bool) -> bool:
    """Refuse unsupported or bypassing syntax around a Java validator.

    Source line numbers are raw LF rows. Ambiguous rows, unavailable
    grammar and parse failures decline. The validator's own guard-shaped
    if is an endpoint; every enclosing conditional arm must also contain
    the sink. Exception, switch and labelled transfers remain unverified.
    """
    if validator_line <= 0 or sink_line <= validator_line:
        return True
    if java_unicode_unverified(source, language="java"):
        return True
    try:
        from core.analysis.cfg_builder_java import _get_parser

        parser = _get_parser()
        if parser is None:
            return True
        tree = parser.parse(source.encode("utf-8"))
        if tree is None or tree.root_node.has_error:
            return True
        validators = []
        sinks = []
        pending = [tree.root_node]
        visited = 0
        while pending:
            node = pending.pop()
            visited += 1
            if visited > _MAX_NODES:
                return True
            row = node.start_point[0] + 1
            if row == validator_line and node.type in ({"if_statement"} if guard_shaped else _STATEMENTS):
                validators.append(node)
            if row == sink_line and node.type in _STATEMENTS:
                sinks.append(node)
            pending.extend(node.named_children)
        if len(validators) != 1 or len(sinks) != 1:
            return True
        validator, sink = validators[0], sinks[0]
        owner = _owner(validator)
        if owner is None or owner != _owner(sink):
            return True
        parent = validator.parent
        while parent is not None and parent != owner:
            if parent.type in _UNSUPPORTED:
                return True
            if parent.type == "if_statement":
                arms = [parent.child_by_field_name(field) for field in ("consequence", "alternative")]
                selected = [arm for arm in arms if _contains(arm, validator)]
                if len(selected) != 1 or not _contains(selected[0], sink):
                    return True
            elif parent.type in _LOOPS:
                body = parent.child_by_field_name("body")
                if not _contains(body, validator) or not _contains(body, sink):
                    return True
            parent = parent.parent
        return parent is None
    except Exception:  # noqa: BLE001 -- unavailable syntax cannot authorise a proof
        return True

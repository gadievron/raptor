"""Negative native control-ownership checks for source validator proofs.

A passing check is not dominance evidence. Callers must retain their
existing exit-on-failure, value-flow and language-property checks.
"""
from __future__ import annotations

from core.source.java_unicode import java_unicode_unverified

_JAVA_STATEMENTS = frozenset({"expression_statement", "local_variable_declaration",
                         "return_statement", "throw_statement"})
_JAVA_OWNERS = frozenset({"method_declaration", "constructor_declaration", "lambda_expression"})
_JAVA_LOOPS = frozenset({"while_statement", "do_statement", "for_statement", "enhanced_for_statement"})
_JAVA_UNSUPPORTED = frozenset({"try_statement", "try_with_resources_statement", "catch_clause",
                          "finally_clause", "switch_expression", "switch_statement",
                          "switch_block_statement_group", "switch_rule", "synchronized_statement",
                          "labeled_statement"})
_JS_STATEMENTS = frozenset({"expression_statement", "lexical_declaration", "variable_declaration",
                           "return_statement", "throw_statement"})
# Program is an execution scope for this negative veto, not origin or import evidence.
_JS_OWNERS = frozenset({"program", "function_declaration", "function_expression", "arrow_function",
                       "generator_function_declaration", "generator_function", "method_definition"})
_JS_LOOPS = frozenset({"while_statement", "do_statement", "for_statement", "for_in_statement"})
_JS_UNSUPPORTED = frozenset({"try_statement", "catch_clause", "finally_clause", "switch_statement",
                            "switch_case", "switch_default", "labeled_statement", "with_statement",
                            "class_static_block"})
_MAX_NODES = 100_000


def _contains(parent, child):
    return (parent is not None and parent.start_byte <= child.start_byte
            and child.end_byte <= parent.end_byte)


def _owner(node, owners):
    while node is not None:
        if node.type in owners:
            return node
        node = node.parent
    return None


def _native_source_tree(source: str, language: str):
    """Return the exact native syntax tree, or None for an unverified profile."""
    if language not in {"java", "javascript", "typescript", "tsx"}:
        return None
    if language == "java" and java_unicode_unverified(source, language="java"):
        return None
    try:
        if language == "java":
            from core.analysis.cfg_builder_java import _get_parser

            parser = _get_parser()
        else:
            from core.inventory.lexical_view import _parser_for

            parser = _parser_for(language)
        if parser is None:
            return None
        tree = parser.parse(source.encode("utf-8"))
        return tree if tree is not None and not tree.root_node.has_error else None
    except Exception:  # noqa: BLE001 -- syntax unavailability cannot authorise a proof
        return None


def validator_control_scope_unverified(source: str, validator_line: int, sink_line: int,
                                        *, guard_shaped: bool, language: str) -> bool:
    """Refuse unsupported or bypassing syntax around a source validator.

    Source line numbers are raw LF rows. Ambiguous control ownership, unavailable
    grammar and parse failures decline. The validator's own guard-shaped
    if is an endpoint; every enclosing conditional arm must also contain
    the sink. Exception, switch and labelled transfers remain unverified.
    """
    if validator_line <= 0 or sink_line <= validator_line:
        return True
    if language == "java":
        statements, owners = _JAVA_STATEMENTS, _JAVA_OWNERS
        loops, unsupported = _JAVA_LOOPS, _JAVA_UNSUPPORTED
        if java_unicode_unverified(source, language="java"):
            return True
    elif language in {"javascript", "typescript", "tsx"}:
        statements, owners = _JS_STATEMENTS, _JS_OWNERS
        loops, unsupported = _JS_LOOPS, _JS_UNSUPPORTED
    else:
        return True
    try:
        tree = _native_source_tree(source, language)
        if tree is None:
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
            if row == validator_line and node.type in ({"if_statement"} if guard_shaped else statements):
                validators.append(node)
            if row == sink_line and node.type in statements:
                sinks.append(node)
            pending.extend(node.named_children)
        # Several same-row statements are harmless only when every
        # possible anchor shares control ownership. Call/value binding
        # is still checked separately by the consumer.
        if not validators or not sinks or max(len(validators), len(sinks)) > 16:
            return True
        if guard_shaped and len(validators) != 1:
            return True
        for validator in validators:
            for sink in sinks:
                owner = _owner(validator, owners)
                if owner is None or owner != _owner(sink, owners):
                    return True
                parent = sink.parent
                while parent is not None and parent != owner:
                    visited += 1
                    if visited > _MAX_NODES or parent.type in unsupported:
                        return True
                    parent = parent.parent
                if parent is None:
                    return True
                parent = validator.parent
                while parent is not None and parent != owner:
                    visited += 1
                    if visited > _MAX_NODES:
                        return True
                    if parent.type in unsupported:
                        return True
                    if parent.type == "if_statement":
                        arms = [parent.child_by_field_name(field)
                                for field in ("consequence", "alternative")]
                        selected = [arm for arm in arms if _contains(arm, validator)]
                        if len(selected) != 1 or not _contains(selected[0], sink):
                            return True
                    elif parent.type in loops:
                        body = parent.child_by_field_name("body")
                        if not _contains(body, validator) or not _contains(body, sink):
                            return True
                    parent = parent.parent
                if parent is None:
                    return True
        return False
    except Exception:  # noqa: BLE001 -- unavailable syntax cannot authorise a proof
        return True

"""Scoped primitive input facts from exact native lexical bindings.

These facts establish a string value at validator entry, not a complete
source safety, callee identity, value-epoch or sink-property certificate.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from core.analysis import validator_control_scope as _syntax
from core.analysis.validator_call_binding import _parenthesised_value


@dataclass(frozen=True)
class NativeStringInputFact:
    source_digest: str
    variable: str
    binding_span: tuple[int, int, int, int]
    validator_span: tuple[int, int, int, int]
    scope: str = "primitive-string-at-validator-entry"
    origin: str = "adjacent-local-lexical-string-literal"


def _span(node):
    """Raw LF rows are one-based; native byte columns are zero-based."""
    return (node.start_point[0] + 1, node.start_point[1],
            node.end_point[0] + 1, node.end_point[1])


def adjacent_native_string_input(source: str, name: str, validator_line: int,
                                *, language: str) -> NativeStringInputFact | None:
    """Bind one adjacent let/const string declaration to an if entry.

    Require the same lexical block and no intervening statement. A single
    declarator avoids effects from later initialisers. Var declarations,
    assignments, containers, calls and type annotations alone are not this
    primitive fact. Consumers retain their control and post-guard checks.
    """
    if (language not in {"javascript", "typescript", "tsx"}
            or type(validator_line) is not int or validator_line <= 0
            or type(source) is not str or type(name) is not str):
        return None
    try:
        tree = _syntax._native_source_tree(source, language)
        if tree is None:
            return None
        guards, pending, visited = [], [tree.root_node], 0
        while pending:
            node = pending.pop()
            visited += 1
            if visited > _syntax._MAX_NODES:
                return None
            if node.type == "if_statement" and node.start_point[0] + 1 == validator_line:
                guards.append(node)
            pending.extend(node.named_children)
        if len(guards) != 1:
            return None
        guard = guards[0]
        parent = guard.parent
        if parent is None or parent.type not in {"statement_block", "program"}:
            return None
        statements = [node for node in parent.named_children if node.type != "comment"]
        index = statements.index(guard)
        if index == 0:
            return None
        declaration = statements[index - 1]
        if (declaration.type != "lexical_declaration"
                or not any(child.type in {"let", "const"} for child in declaration.children)):
            return None
        declarators = [node for node in declaration.named_children if node.type == "variable_declarator"]
        if len(declarators) != 1:
            return None
        declarator = declarators[0]
        target = declarator.child_by_field_name("name")
        value = _parenthesised_value(declarator.child_by_field_name("value"))
        if (target is None or target.type != "identifier" or target.text != name.encode("utf-8")
                or value is None or value.type != "string"):
            return None
        return NativeStringInputFact(
            sha256(source.encode("utf-8")).hexdigest(), name,
            _span(declaration), _span(guard),
        )
    except Exception:  # noqa: BLE001 -- unavailable syntax cannot establish a primitive fact
        return None

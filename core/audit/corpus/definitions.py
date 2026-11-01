"""Definition identity for corpus pins; never treats mentions as definitions."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


def source_function_id(function_id: str) -> str:
    """Remove a label version suffix without changing its source path."""
    if not isinstance(function_id, str):
        return ""
    file, separator, name = function_id.partition(":")
    if not separator:
        return file.split("@", 1)[0]
    return file + separator + name.split("@", 1)[0]


def function_name(function_id: str, *, qualified: bool = False) -> str:
    name = source_function_id(function_id).rsplit(":", 1)[-1]
    return name if qualified else name.rsplit(".", 1)[-1]


@dataclass(frozen=True)
class Definition:
    name: str
    start: int
    end: int
    uncertain: bool = False


def definitions(text: str, filename: str, *, kernel_extensions: bool = False) -> list[Definition]:
    """Return actual Python/C/Go definitions, or raise if unavailable.

    Conditional C definitions remain distinct. Parsing errors within a
    candidate make it uncertain, so callers cannot stamp it as verified.
    """
    suffix = Path(filename).suffix.lower()
    found: list[Definition] = []
    if suffix == ".py":
        tree = ast.parse(text)
        def visit(node, scope=()):
            nested = scope
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                nested = (*scope, node.name)
                if not isinstance(node, ast.ClassDef):
                    # Decorators may be included as context but are not
                    # necessary to establish function/body coverage.
                    found.append(Definition(".".join(nested), node.lineno, node.end_lineno))
            for child in ast.iter_child_nodes(node):
                visit(child, nested)
        visit(tree)
        return found
    language = {".c": "c", ".h": "c", ".go": "go"}.get(suffix)
    if language is None:
        raise ValueError(f"definition verification unsupported for {suffix!r}")
    from core.inventory.extractors import _ts_parser_for
    parser = _ts_parser_for(language)
    if parser is None:
        raise ValueError(f"{language} definition parser unavailable")
    if language == "c" and kernel_extensions:
        from .kernel_syntax import kernel_parse_view
        text = kernel_parse_view(text, parser)
    data = text.encode("utf-8")
    tree = parser.parse(data)
    if tree is None:
        raise ValueError(f"{language} definition parser returned no tree")
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(reversed(node.named_children))
        if node.type not in ("function_definition", "function_declaration", "method_declaration"):
            continue
        if node.child_by_field_name("body") is None:
            continue
        ident = node.child_by_field_name("name")
        explicit_function = True
        if language == "c":
            explicit_function = False
            ident = node.child_by_field_name("declarator")
            while ident is not None and ident.type != "identifier":
                explicit_function |= ident.type == "function_declarator"
                ident = ident.child_by_field_name("declarator")
        if ident is None:
            continue
        name = data[ident.start_byte:ident.end_byte].decode("utf-8")
        receiver = node.child_by_field_name("receiver")
        if receiver is not None:
            pending = [receiver]
            while pending:
                part = pending.pop()
                if part.type == "type_identifier":
                    name = data[part.start_byte:part.end_byte].decode("utf-8") + "." + name
                    break
                pending.extend(reversed(part.named_children))
        found.append(Definition(name, node.start_point.row + 1, node.end_point.row + 1, node.has_error or not explicit_function))
    return found

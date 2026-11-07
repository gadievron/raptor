"""Read-only traversal shared by the repository's AST census visitors."""

from __future__ import annotations

import ast


class CensusVisitor(ast.NodeVisitor):
    """Cache unbound handlers and visit parsed AST fields without a generator.

    Context markers and scalar spelling fields contain no candidate sites.
    Visit expression children directly on common wrappers; subclasses can
    override any handler when their detector inspects the wrapper itself.
    All candidate nodes retain the stdlib visitor's order and traversal.
    """

    def __init__(self) -> None:
        self._visitor_methods = {}

    def visit(self, node: ast.AST):
        kind = type(node)
        method = self._visitor_methods.get(kind)
        if method is None:
            method = getattr(type(self), "visit_" + kind.__name__, type(self).generic_visit)
            self._visitor_methods[kind] = method
        return method(self, node)

    def generic_visit(self, node: ast.AST) -> None:
        # ast.iter_fields wraps these same lookups in a generator. The
        # scanners visit millions of nodes; iterate fields directly instead.
        for field in node._fields:
            value = getattr(node, field, None)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def visit_Name(self, node: ast.Name) -> None:
        """Name identifiers and contexts contain no child candidate sites."""

    def visit_Constant(self, node: ast.Constant) -> None:
        """Parsed literal values contain no AST children."""

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.visit(node.value)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self.visit(node.value)
        self.visit(node.slice)

    def visit_keyword(self, node: ast.keyword) -> None:
        self.visit(node.value)

    def visit_arg(self, node: ast.arg) -> None:
        if node.annotation is not None:
            self.visit(node.annotation)

    def visit_alias(self, node: ast.alias) -> None:
        """Import spellings contain no AST children."""

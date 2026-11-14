"""Explicitly synthetic AST fixtures for complete-expression refusal checks."""

import ast


def parse_target_refusal_fixture(source, *args, **kwargs):
    """Parse source, then mark designated loads as malformed expression nodes.

    These trees test AST admission, not compiler-accepted source behaviour.
    Other unsupported statement/header cases pass through without mutation.
    """
    tree = ast.parse(source, *args, **kwargs)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == '_raptor_unsupported_target':
            assert isinstance(node.ctx, ast.Load), 'refusal markers must start as loads'
            node.ctx = ast.Del()
    return tree

"""Recognize and exercise explicit unittest mock sites in ownership censuses."""

import ast
from pkgutil import resolve_name
from unittest.mock import patch

from core.testing.module_bindings import mock_module_attribute


def patch_target(node):
    """Return a literal target for legacy patches or consumer-owned mocks."""
    if not isinstance(node, ast.Call) or not node.args:
        return None
    name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
    if name == "patch" and isinstance(node.args[0], ast.Constant):
        return node.args[0].value if isinstance(node.args[0].value, str) else None
    if name != "mock_module_attribute" or len(node.args) < 3:
        return None
    owner, binding, attribute = node.args[:3]
    if (not isinstance(owner, ast.Call) or not isinstance(owner.func, ast.Name)
            or owner.func.id != "_mock_owner" or len(owner.args) != 1):
        return None
    parts = [owner.args[0], binding, attribute]
    if not all(isinstance(part, ast.Constant) and isinstance(part.value, str) for part in parts):
        return None
    return ".".join(part.value for part in parts)


def patch_site(node, target, value):
    """Inject only the fake value, retaining the source site's mock API."""
    assert patch_target(node) == target, ast.unparse(node)
    if getattr(node.func, "id", "") == "mock_module_attribute":
        owner = resolve_name(node.args[0].args[0].value)
        return mock_module_attribute(owner, node.args[1].value, node.args[2].value, new=value)
    return patch(target, new=value)

"""Read native mock targets while fixture inventories migrate to explicit scopes."""

import ast
import copy


def as_patch_call(node):
    """Normalize a literal consumer mock for legacy fixture-source inventories.

    Keep configuration and source locations; unrecognized calls pass through.
    This reads syntax only and never imports or executes the target.
    """
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return node
    if node.func.id != "mock_module_attribute" or len(node.args) < 3:
        return node
    owner, binding, attribute = node.args[:3]
    if not (isinstance(owner, ast.Call) and isinstance(owner.func, ast.Name)
            and owner.func.id == "_mock_owner" and len(owner.args) == 1
            and isinstance(owner.args[0], ast.Constant) and isinstance(owner.args[0].value, str)
            and isinstance(binding, ast.Constant) and isinstance(binding.value, str)
            and isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
        return node
    normalized = copy.deepcopy(node)
    normalized.func = ast.Name(id="patch", ctx=ast.Load())
    normalized.args = [ast.Constant(".".join((owner.args[0].value, binding.value, attribute.value))),
                       *normalized.args[3:]]
    return ast.fix_missing_locations(normalized)

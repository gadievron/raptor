"""Static rotation fault-domain checks, without importing native fault consumers."""
import ast
import copy
from functools import lru_cache
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


_ROTATE_FAULT_FILE = "core/audit/tests/test_audit_log_rotate_remedy.py"


def _rotation_fault_contract(tree):
    """Key the seven native seams and the separately owned adoption fault."""
    modules = {alias.asname: alias.name for node in tree.body if isinstance(node, ast.Import)
               for alias in node.names if alias.asname and alias.asname.startswith("_os_fault_consumer")}
    keys = []
    adoption = []
    modes = []
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef) or not function.name.startswith("test_"):
            continue
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            if (isinstance(node.func, ast.Name) and node.func.id == "patch_module_attribute"
                    and len(node.args) >= 5 and isinstance(node.args[1], ast.Name)
                    and node.args[1].id in modules):
                keys.append((function.name, modules[node.args[1].id],
                             ast.unparse(node.args[2]), ast.unparse(node.args[3])))
            if (function.name == "test_stream_setup_failure_closes_fd_and_removes_temp"
                    and isinstance(node.func, ast.Attribute) and node.func.attr == "setattr"
                    and len(node.args) >= 3):
                adoption.append(tuple(ast.unparse(arg) for arg in node.args[:3]))
        if function.name == "test_stream_setup_failure_closes_fd_and_removes_temp":
            for decorator in function.decorator_list:
                if (isinstance(decorator, ast.Call) and len(decorator.args) >= 2
                        and isinstance(decorator.args[0], ast.Constant)
                        and decorator.args[0].value == "mode"):
                    modes = ast.literal_eval(decorator.args[1])
    expected = [
        ("test_symlink_swapped_in_after_snapshot_refused", "lstat"),
        ("test_size_change_mid_rewrite_refuses", "lstat"),
        ("test_append_rolling_to_new_shard_mid_rotate_refused", "fsync"),
        ("test_rotation_swap_failure_restores_trail", "rename"),
        ("test_cleanup_failure_does_not_mask_primary_or_skip_remaining_temps", "fsync"),
        ("test_failed_restore_keeps_recovery_backup", "rename"),
        ("test_swap_failure_restores_multiple_original_shards", "rename"),
    ]
    expected = [(name, "core.audit.audit_log_rotate", repr("os"), repr(attribute))
                for name, attribute in expected]
    return (sorted(keys) == sorted(expected)
            and adoption == [("rotate_mod", repr("adopt_fd"), "fail_setup")]
            and modes == ["rb", "wb"])


def test_rotation_fault_inventory_retains_native_domains_and_owned_adoption():
    assert _rotation_fault_contract(_tree(_ROTATE_FAULT_FILE))


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "retarget", "consumer", "adoption"])
def test_rotation_fault_inventory_refuses_same_count_or_missing_domain_drift(mutation):
    tree = copy.deepcopy(_tree(_ROTATE_FAULT_FILE))
    native = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
              and isinstance(node.func, ast.Name) and node.func.id == "patch_module_attribute"]
    if mutation == "missing":
        native[0].func = ast.Name(id="removed_native_fault", ctx=ast.Load())
    elif mutation == "duplicate":
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                        and node.lineno <= native[0].lineno <= node.end_lineno
                        and node.name.startswith("test_"))
        function.body.append(ast.Expr(value=copy.deepcopy(native[0])))
    elif mutation == "retarget":
        native[0].args[3] = ast.Constant(value="stat")
    elif mutation == "consumer":
        alias = next(alias for node in tree.body if isinstance(node, ast.Import)
                     for alias in node.names if alias.asname == "_os_fault_consumer")
        alias.name = "core.audit.record"
    else:
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                        and node.name == "test_stream_setup_failure_closes_fd_and_removes_temp")
        call = next(node for node in ast.walk(function) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == "setattr")
        call.args[1] = ast.Constant(value="fdopen")
    assert not _rotation_fault_contract(tree)

"""Native OS fault mocks must leave shared and borrowed namespaces untouched."""
import ast
import copy
from collections import Counter
from contextlib import ExitStack, contextmanager
from functools import lru_cache
import importlib
import os
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from core.testing.mock_sites import patch_site, patch_target
from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = [{'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 42,
  'module': 'core.build.toolchain',
  'target': 'os.path.realpath'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 53,
  'module': 'core.build.toolchain',
  'target': 'os.path.realpath'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 60,
  'module': 'core.build.toolchain',
  'target': 'os.path.realpath'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 70,
  'module': 'core.build.toolchain',
  'target': 'os.path.isdir'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 78,
  'module': 'core.build.toolchain',
  'target': 'os.path.isdir'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 80,
  'module': 'core.build.toolchain',
  'target': 'os.path.realpath'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 87,
  'module': 'core.build.toolchain',
  'target': 'os.path.isdir'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 89,
  'module': 'core.build.toolchain',
  'target': 'os.path.isfile'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 95,
  'module': 'core.build.toolchain',
  'target': 'os.path.isdir'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 97,
  'module': 'core.build.toolchain',
  'target': 'os.path.realpath'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 108,
  'module': 'core.build.toolchain',
  'target': 'os.path.realpath'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 109,
  'module': 'core.build.toolchain',
  'target': 'os.path.isdir'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 130,
  'module': 'core.build.toolchain',
  'target': 'os.path.isdir'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 145,
  'module': 'core.build.toolchain',
  'target': 'os.path.isdir'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 153,
  'module': 'core.build.toolchain',
  'target': 'os.path.isdir'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 172,
  'module': 'core.build.toolchain',
  'target': 'os.path.isdir'},
 {'file': 'core/build/tests/test_toolchain.py',
  'kind': 'string',
  'line': 173,
  'module': 'core.build.toolchain',
  'target': 'os.path.isfile'},
 {'file': 'core/run/tests/test_output.py',
  'kind': 'string',
  'line': 223,
  'module': 'core.run.output',
  'target': 'os.getpid'},
 {'file': 'core/run/tests/test_output.py',
  'kind': 'string',
  'line': 232,
  'module': 'core.run.output',
  'target': 'os.getpid'},
 {'file': 'core/run/tests/test_output.py',
  'kind': 'string',
  'line': 242,
  'module': 'core.run.output',
  'target': 'os.getpid'},
 {'file': 'core/run/tests/test_output.py',
  'kind': 'string',
  'line': 255,
  'module': 'core.run.output',
  'target': 'os.getpid'},
 {'file': 'core/run/tests/test_output.py',
  'kind': 'string',
  'line': 274,
  'module': 'core.run.output',
  'target': 'os.getpid'},
 {'file': 'core/run/tests/test_output.py',
  'kind': 'string',
  'line': 276,
  'module': 'core.run.output',
  'target': 'os.getpid'},
 {'file': 'core/run/tests/test_output.py',
  'kind': 'string',
  'line': 69,
  'module': 'core.run.output',
  'target': 'os.getpid'},
 {'file': 'core/run/tests/test_output.py',
  'kind': 'string',
  'line': 71,
  'module': 'core.run.output',
  'target': 'os.getpid'},
 {'file': 'core/run/tests/test_worker_liveness.py',
  'kind': 'string',
  'line': 94,
  'module': 'core.run.metadata',
  'target': 'os.getppid'},
 {'file': 'core/run/tests/test_worker_liveness.py',
  'kind': 'string',
  'line': 111,
  'module': 'core.run.metadata',
  'target': 'os.getppid'},
 {'file': 'core/run/tests/test_worker_liveness.py',
  'kind': 'string',
  'line': 124,
  'module': 'core.run.metadata',
  'target': 'os.getppid'},
 {'file': 'core/run/tests/test_worker_liveness.py',
  'kind': 'string',
  'line': 138,
  'module': 'core.run.metadata',
  'target': 'os.getppid'},
 {'file': 'core/run/tests/test_worker_liveness.py',
  'kind': 'string',
  'line': 154,
  'module': 'core.run.metadata',
  'target': 'os.getppid'},
 {'file': 'core/run/tests/test_worker_liveness.py',
  'kind': 'string',
  'line': 169,
  'module': 'core.run.metadata',
  'target': 'os.getppid'},
 {'file': 'core/run/tests/test_worker_liveness.py',
  'kind': 'string',
  'line': 170,
  'module': 'core.run.metadata',
  'target': 'os.getpid'},
 {'file': 'core/run/tests/test_worker_liveness.py',
  'kind': 'string',
  'line': 193,
  'module': 'core.run.metadata',
  'target': 'os.getppid'},
 {'file': 'core/source/tests/test_gated.py',
  'kind': 'monkey',
  'line': 74,
  'module': 'core.source.gated',
  'target': 'os.fstat'},
 {'file': 'core/source/tests/test_gated.py',
  'kind': 'monkey',
  'line': 179,
  'module': 'core.source.gated',
  'target': 'os.fstat'},
 {'file': 'core/source/tests/test_gated.py',
  'kind': 'monkey',
  'line': 354,
  'module': 'core.source.gated',
  'target': 'os.fstat'},
 {'file': 'core/source/tests/test_gated.py',
  'kind': 'monkey',
  'line': 367,
  'module': 'core.source.gated',
  'target': 'os.fstat'},
 {'file': 'core/source/tests/test_gated.py',
  'kind': 'monkey',
  'line': 384,
  'module': 'core.source.gated',
  'target': 'os.fstat'},
 {'file': 'core/json/tests/test_jsonl.py',
  'kind': 'monkey',
  'line': 93,
  'module': 'core.json.jsonl',
  'target': 'os.write'},
 {'file': 'core/json/tests/test_jsonl.py',
  'kind': 'monkey',
  'line': 104,
  'module': 'core.json.jsonl',
  'target': 'os.write'},
 {'file': 'packages/codeql/tests/test_temp_env.py',
  'kind': 'monkey',
  'line': 20,
  'module': 'packages.codeql.temp_env',
  'target': 'os.statvfs'},
 {'file': 'packages/codeql/tests/test_temp_env.py',
  'kind': 'monkey',
  'line': 27,
  'module': 'packages.codeql.temp_env',
  'target': 'os.statvfs'},
 {'file': 'packages/codeql/tests/test_temp_env.py',
  'kind': 'monkey',
  'line': 49,
  'module': 'packages.codeql.temp_env',
  'target': 'os.statvfs'},
 {'file': 'packages/codeql/tests/test_temp_env.py',
  'kind': 'monkey',
  'line': 97,
  'module': 'packages.codeql.temp_env',
  'target': 'os.statvfs'},
 {'file': 'core/iris/tests/test_store_integrity.py',
  'kind': 'monkey',
  'line': 347,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/iris/tests/test_store_integrity.py',
  'kind': 'monkey',
  'line': 358,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/iris/tests/test_store_integrity.py',
  'kind': 'monkey',
  'line': 390,
  'module': 'core.security.mac_key',
  'target': 'os.open'},
 {'file': 'core/llm/scorecard/tests/test_integrity.py',
  'kind': 'monkey',
  'line': 365,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/llm/scorecard/tests/test_integrity.py',
  'kind': 'monkey',
  'line': 376,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/llm/scorecard/tests/test_integrity.py',
  'kind': 'monkey',
  'line': 408,
  'module': 'core.security.mac_key',
  'target': 'os.open'},
 {'file': 'core/witness/tests/test_provenance.py',
  'kind': 'monkey',
  'line': 562,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/witness/tests/test_provenance.py',
  'kind': 'monkey',
  'line': 573,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/witness/tests/test_provenance.py',
  'kind': 'monkey',
  'line': 646,
  'module': 'core.security.mac_key',
  'target': 'os.open'},
 {'file': 'core/coverage/tests/test_journal_mac.py',
  'kind': 'monkey',
  'line': 37,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/coverage/tests/test_journal_mac.py',
  'kind': 'monkey',
  'line': 50,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/coverage/tests/test_journal_mac.py',
  'kind': 'monkey',
  'line': 82,
  'module': 'core.security.mac_key',
  'target': 'os.open'},
 {'file': 'core/llm/tests/test_cache_integrity.py',
  'kind': 'monkey',
  'line': 250,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/llm/tests/test_cache_integrity.py',
  'kind': 'monkey',
  'line': 263,
  'module': 'core.security.mac_key',
  'target': 'os.read'},
 {'file': 'core/labeled_attempts/test_store.py',
  'kind': 'monkey',
  'line': 748,
  'module': 'core.labeled_attempts.store',
  'target': 'os.open'},
 {'file': 'core/labeled_attempts/test_store.py',
  'kind': 'monkey',
  'line': 749,
  'module': 'core.labeled_attempts.store',
  'target': 'os.write'},
 {'file': 'core/labeled_attempts/test_store.py',
  'kind': 'monkey',
  'line': 790,
  'module': 'core.labeled_attempts.store',
  'target': 'os.open'},
 {'file': 'core/labeled_attempts/test_store.py',
  'kind': 'monkey',
  'line': 791,
  'module': 'core.labeled_attempts.store',
  'target': 'os.write'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 91,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.scandir'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 157,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.rename'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 212,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.rename'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 338,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.rename'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 41,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.unlink'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 236,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.open'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 237,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.fdopen'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 304,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.rename'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 305,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.unlink'},
 {'file': 'core/labeled_attempts/test_pruning_ownership.py',
  'kind': 'monkey',
  'line': 306,
  'module': 'core.labeled_attempts.pruning',
  'target': 'os.rmdir'},
 # Checklist rename failures now patch rename_without_replace directly;
 # only replacement still patches a native OS consumer binding.
 {'file': 'core/inventory/tests/test_checklist_replacement.py',
  'kind': 'monkey',
  'line': 77,
  'module': 'core.inventory',
  'target': 'os.replace'},
 {'file': 'core/run/tests/test_archive_publication_cleanup.py',
  'kind': 'monkey',
  'line': 47,
  'module': 'raptor',
  'target': 'os.replace'},
 {'file': 'core/run/tests/test_archive_publication_cleanup.py',
  'kind': 'monkey',
  'line': 143,
  'module': 'raptor',
  'target': 'os.replace'},
 {'file': 'core/run/tests/test_archive_publication_cleanup.py',
  'kind': 'monkey',
  'line': 182,
  'module': 'raptor',
  'target': 'os.replace'},
 {'file': 'core/inventory/tests/test_perlasm_cache_lifecycle.py',
  'kind': 'monkey',
  'line': 58,
  'module': 'core.inventory.perlasm',
  'target': 'os.read'},
 {'file': 'core/inventory/tests/test_perlasm_cache_lifecycle.py',
  'kind': 'monkey',
  'line': 133,
  'module': 'core.inventory.perlasm',
  'target': 'os.read'},
 {'file': 'core/inventory/tests/test_perlasm_cache_lifecycle.py',
  'kind': 'monkey',
  'line': 154,
  'module': 'core.inventory.perlasm',
  'target': 'os.read'},
 {'file': 'core/inventory/tests/test_perlasm_cache_lifecycle.py',
  'kind': 'monkey',
  'line': 181,
  'module': 'core.atomic_fs',
  'target': 'os.replace'},
 {'file': 'core/inventory/tests/test_perlasm_cache_lifecycle.py',
  'kind': 'monkey',
  'line': 194,
  'module': 'core.atomic_fs',
  'target': 'os.write'},
 {'file': 'core/audit/tests/test_audit_log_rotate_remedy.py',
  'kind': 'monkey',
  'line': 544,
  'module': 'core.audit.audit_log_rotate',
  'target': 'os.rename'},
 {'file': 'core/audit/tests/test_audit_log_rotate_remedy.py',
  'kind': 'monkey',
  'line': 608,
  'module': 'core.audit.audit_log_rotate',
  'target': 'os.fdopen'},
 {'file': 'core/audit/tests/test_audit_log_rotate_remedy.py',
  'kind': 'monkey',
  'line': 667,
  'module': 'core.audit.audit_log_rotate',
  'target': 'os.rename'},
 {'file': 'core/audit/tests/test_audit_log_rotate_remedy.py',
  'kind': 'monkey',
  'line': 694,
  'module': 'core.audit.audit_log_rotate',
  'target': 'os.rename'},
 {'file': 'core/audit/tests/test_audit_log_rotate_remedy.py',
  'kind': 'monkey',
  'line': 423,
  'module': 'core.audit.audit_log_rotate',
  'target': 'os.lstat'},
 {'file': 'core/audit/tests/test_audit_log_rotate_remedy.py',
  'kind': 'monkey',
  'line': 467,
  'module': 'core.audit.audit_log_rotate',
  'target': 'os.lstat'},
 {'file': 'core/audit/tests/test_audit_log_rotate_remedy.py',
  'kind': 'monkey',
  'line': 507,
  'module': 'core.audit.audit_log_rotate',
  'target': 'os.fsync'},
 {'file': 'core/audit/tests/test_audit_log_rotate_remedy.py',
  'kind': 'monkey',
  'line': 642,
  'module': 'core.audit.audit_log_rotate',
  'target': 'os.fsync'}]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


@lru_cache(maxsize=None)
def _nodes(file):
    result = []
    for node in ast.walk(_tree(file)):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        owned_target = patch_target(node)
        if getattr(node.func, "id", "") == "mock_module_attribute" and any(
                owned_target == row["module"] + "." + row["target"]
                for row in _SPECS if row["file"] == file):
            result.append(node)
            continue
        if getattr(node.func, "id", "") == "patch_module_attribute" and len(node.args) >= 5:
            if isinstance(node.args[1], ast.Name) and node.args[1].id.startswith("_os_fault_consumer"):
                result.append(node)
        elif getattr(node.func, "attr", "") == "setattr" and len(node.args) >= 3 and ast.unparse(node.args[0]) == "os":
            result.append(node)
        elif (getattr(node.func, "id", "") == "patch" or getattr(node.func, "attr", "") == "patch") and isinstance(node.args[0], ast.Constant):
            target = node.args[0].value
            if isinstance(target, str) and (target.startswith("os.") or any(target == row["module"] + "." + row["target"] for row in _SPECS if row["file"] == file)):
                result.append(node)
    return sorted(result, key=lambda node: (node.lineno, node.col_offset))


@lru_cache(maxsize=None)
def _namespace(file):
    namespace = {"patch_module_attribute": patch_module_attribute, "os": os}
    for node in _tree(file).body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.asname.startswith("_os_fault_consumer"):
                    namespace[alias.asname] = importlib.import_module(alias.name)
    node = next((n for n in _tree(file).body if isinstance(n, ast.FunctionDef) and n.name == "_isolate_os_fault_patches"), None)
    if node:
        node = copy.deepcopy(node)
        node.decorator_list = []
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), file, "exec"), namespace)
    return namespace


def _assert_namespace(owner, before):
    current = vars(owner)
    assert current.keys() == before.keys()
    assert all(current[key] is value for key, value in before.items())


@contextmanager
def _snapshot(row, borrowed):
    owner = importlib.import_module(row["module"])
    with pytest.MonkeyPatch.context() as inherited:
        if borrowed:
            view = ModuleType(owner.os.__name__)
            vars(view).update(vars(owner.os))
            path = ModuleType(view.path.__name__)
            vars(path).update(vars(view.path))
            view.path = path
            inherited.setitem(vars(owner), "os", view)
        raw = [(owner, dict(vars(owner)))]
        namespaces = [(value, dict(vars(value))) for value in (os, os.path, owner.os, owner.os.path)]
        yield owner, raw, namespaces


def _exercise(row, index, borrowed, exit_mode, mock=True):
    with _snapshot(row, borrowed) as (owner, raw, namespaces):
        namespace = dict(_namespace(row["file"]))
        fake = MagicMock(name="owned_os_fault")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope, ExitStack() as patches:
                namespace.update(monkeypatch=scope, fault=scope, faults=scope, _owned_fake=fake)
                fixture = namespace.get("_isolate_os_fault_patches")
                if fixture:
                    fixture(scope)
                if mock:
                    node = copy.deepcopy(_nodes(row["file"])[index])
                    if row["kind"] == "string":
                        target = patch_target(node)
                        patches.enter_context(patch_site(node, target, fake))
                    else:
                        # Execute the actual native target/scope/attribute expression,
                        # substituting only the fault value; no syscall is executed.
                        node.args[-1] = ast.Name(id="_owned_fake", ctx=ast.Load())
                        eval(compile(ast.fix_missing_locations(ast.Expression(node)), row["file"], "eval"), namespace)
                    for namespace_owner, before in namespaces:
                        _assert_namespace(namespace_owner, before)
                    actual = owner
                    for part in row["target"].split("."):
                        actual = getattr(actual, part)
                    assert actual is fake
                else:
                    for namespace_owner, before in namespaces:
                        _assert_namespace(namespace_owner, before)
                if exit_mode != "normal":
                    raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
        except BaseException as error:
            caught = error
        for namespace_owner, before in raw + namespaces:
            _assert_namespace(namespace_owner, before)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            expected = RuntimeError if exit_mode == "error" else KeyboardInterrupt
            assert isinstance(caught, expected), repr(caught)
            assert str(caught) == "owned scope exit"


def _cases():
    for file, count in Counter(row["file"] for row in _SPECS).items():
        assert len(_nodes(file)) == count, f"refresh native OS fault inventory: {file}"
    seen = {}
    for row in sorted(_SPECS, key=lambda row: (row["file"], row["line"])):
        index = seen.get(row["file"], 0)
        seen[row["file"]] = index + 1
        yield pytest.param(row, index, id=row["file"] + ":" + str(row["line"]))


@pytest.mark.parametrize("row,index", list(_cases()))
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_os_fault_is_consumer_owned(row, index, borrowed, exit_mode):
    _exercise(row, index, borrowed, exit_mode)


@pytest.mark.parametrize("row", list({row["file"]: row for row in _SPECS}.values()), ids=lambda row: row["file"])
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
def test_unmodified_os_control(row, borrowed):
    _exercise(row, 0, borrowed, "normal", mock=False)

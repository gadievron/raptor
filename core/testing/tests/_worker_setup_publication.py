from pathlib import Path
import ast, __future__, json, os, socket, subprocess, sys, threading, time
from contextlib import contextmanager
from types import ModuleType
root, scratch = map(Path, sys.argv[1:3])
case, stage, outcome, expectation = sys.argv[3:7]
attempts = []
def denied(*args, **kwargs):
    attempts.append("secondary execution, worker or transport")
    raise AssertionError(attempts[-1])
subprocess.Popen = denied
for name in ("fork", "forkpty", "system", "posix_spawn", "posix_spawnp", "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"):
    if hasattr(os, name): setattr(os, name, denied)
for name in ("connect", "connect_ex", "bind", "listen", "accept", "sendto"):
    setattr(socket.socket, name, denied)
socket.socketpair = denied
threading.Thread.start = denied
sys.path.insert(0, str(root))
import pytest
import ctypes.util
ctypes.util.find_library = lambda name: None
from core.testing.module_views import module_function_view
from core.testing.module_bindings import patch_module_attribute
# Imports remain runtime-unvalidated until an admitted guarded baseline.
if case == "proxy":
    from core.sandbox import summary
    native_source = root / "core/sandbox/tests/test_proxy_persist_snapshots.py"
    target_name, class_name = "test_snapshot_survives_an_update_from_another_thread", None
    slots = [(vars(summary), "_proxy_persist_state")]
else:
    from packages.joern import runner, heap_ledger, server as server_module
    if case == "runner":
        assert "runner" not in vars(runner._thread_bound_runner), "baseline requires observed absent fresh thread-local slot"
        slots = [(vars(runner._thread_bound_runner), "runner")]
        native_source = root / "packages/joern/tests/test_runner_seam_binding.py"
        target_name, class_name = "test_pin_is_thread_local", "TestBoundSandboxRunner"
    else:
        slots = [(vars(heap_ledger), "_LEDGER_PATH"), (vars(heap_ledger), "_host_budget_mb"), (vars(server_module), "subprocess")]
        native_source = root / "packages/joern/tests/test_heap_ledger.py"
        target_name, class_name = "test_racing_reservations_never_oversubscribe", "TestConcurrentAdmission"
missing = object()
borrowed = [(mapping, name, mapping.get(name, missing)) for mapping, name in slots]
failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]("owned worker fixture setup fault")
selected_index = {"runner": 0, "proxy": 0, "heap-path": 0, "heap-budget": 1, "heap-subprocess": 2}.get(stage)
patches, fired = [], []
def selected(mapping, name):
    return selected_index is not None and mapping is slots[selected_index][0] and name == slots[selected_index][1]
class Patch(pytest.MonkeyPatch):
    def __init__(self):
        super().__init__()
        patches.append(self)
    def setattr(self, owner, name, value, *args, **kwargs):
        result = super().setattr(owner, name, value, *args, **kwargs)
        if selected(vars(owner), name):
            fired.append(stage)
            raise failure
        return result
    def setitem(self, mapping, name, value):
        result = super().setitem(mapping, name, value)
        if selected(mapping, name):
            fired.append(stage)
            raise failure
        return result
private_pytest = ModuleType("pytest")
vars(private_pytest).update(vars(pytest))
private_pytest.MonkeyPatch = Patch
native = ModuleType("owned_worker_native")
vars(native).update(patch_module_attribute=patch_module_attribute)
if case == "proxy": native.summary = summary
body = ast.parse(native_source.read_bytes()).body
container = next(x for x in body if isinstance(x, ast.ClassDef) and x.name == class_name).body if class_name else body
method = next(x for x in container if isinstance(x, ast.FunctionDef) and x.name == target_name)
method.decorator_list = []
node = ast.ClassDef(name=class_name, bases=[], keywords=[], body=[method], decorator_list=[]) if class_name else method
nodes = [node]
fixture_name = {"proxy": "isolated_mirror", "heap": "_isolate_subprocess_launch_patches"}.get(case)
if fixture_name:
    fixture = next(x for x in body if isinstance(x, ast.FunctionDef) and x.name == fixture_name)
    fixture.decorator_list = []
    nodes.append(fixture)
exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(native_source), "exec", flags=__future__.annotations.compiler_flag), vars(native))
if fixture_name:
    fixture = getattr(native, fixture_name)
    fixture.__wrapped__ = fixture
owners = ModuleType("owned_heap_fixtures")
if case == "heap":
    source = root / "packages/joern/tests/conftest.py"
    fixture = next(x for x in ast.parse(source.read_bytes()).body if isinstance(x, ast.FunctionDef) and x.name == "_isolated_heap_ledger")
    fixture.decorator_list = []
    owners.heap_ledger = heap_ledger
    exec(compile(ast.Module(body=[fixture], type_ignores=[]), str(source), "exec", flags=__future__.annotations.compiler_flag), vars(owners))
    owners._isolated_heap_ledger.__wrapped__ = owners._isolated_heap_ledger
label = {"runner": "runner_pin", "proxy": "proxy_snapshot", "heap": "heap_admission"}[case]
source = root / ("core/testing/tests/test_" + label + "_worker_ownership_scope.py")
node = next(x for x in ast.parse(source.read_bytes()).body if isinstance(x, ast.FunctionDef) and x.name == "exercise")
namespace = dict(contextmanager=contextmanager, ModuleType=ModuleType, threading=threading, time=time, pytest=private_pytest, native=native, owners=owners, module_function_view=module_function_view)
if case != "proxy": namespace.update(runner=runner, heap_ledger=heap_ledger, server_module=server_module)
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec", flags=__future__.annotations.compiler_flag), namespace)
try:
    caught = None
    args = ("normal",) if case == "runner" else ("normal", scratch)
    try:
        with namespace["exercise"](*args) as (invoke, workers):
            assert stage == "normal" and not workers
            assert any(mapping.get(name, missing) is not value for mapping, name, value in borrowed)
            # Do not invoke original worker/updater/heap/server body.
    except BaseException as error: caught = error
    if stage == "normal": assert caught is None and not fired
    else: assert caught is failure and fired == [stage], repr(caught)
    restored = all(mapping.get(name, missing) is value for mapping, name, value in borrowed)
    if expectation == "baseline": assert not restored and stage != "normal"
    else: assert expectation == "candidate" and restored
    assert not attempts
    result = dict(result="WORKER_SETUP_BASELINE_LEAK" if expectation == "baseline" else "WORKER_SETUP_OWNER_OK", case=case, stage=stage, forbidden_attempts=attempts)
finally:
    for patch in reversed(patches): patch.undo()
assert all(mapping.get(name, missing) is value for mapping, name, value in borrowed)
print(json.dumps(result, sort_keys=True))

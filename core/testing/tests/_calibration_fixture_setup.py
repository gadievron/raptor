from pathlib import Path
import ast, __future__, json, os, socket, subprocess, sys, threading
from contextlib import contextmanager
from types import ModuleType
root, scratch = map(Path, sys.argv[1:3])
case, stage, outcome, expectation = sys.argv[3:7]
attempts = []
def denied(*args, **kwargs):
    attempts.append("secondary execution, calibration, worker or transport")
    raise AssertionError(attempts[-1])
subprocess.Popen = denied
for name in ("fork", "forkpty", "system", "posix_spawn", "posix_spawnp", "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"):
    if hasattr(os, name): setattr(os, name, denied)
socket.socket.connect = denied
socket.socket.connect_ex = denied
socket.socket.bind = denied
socket.socket.listen = denied
socket.socket.accept = denied
socket.socketpair = denied
threading.Thread.start = denied
sys.path.insert(0, str(root))
import pytest
import ctypes.util
ctypes.util.find_library = lambda name: None
from core.sandbox import calibrate as cal, calibrated_hosts as memo
from core.testing.module_views import module_function_view
borrowed = (memo._CACHE, cal._CACHE_DIR, cal.load_or_calibrate)
borrowed_env = dict(os.environ)
failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]("owned calibration fixture setup fault")
patches, fired = [], []
class Patch(pytest.MonkeyPatch):
    def __init__(self):
        super().__init__()
        patches.append(self)
    def setattr(self, owner, name, value, *args, **kwargs):
        result = super().setattr(owner, name, value, *args, **kwargs)
        selected = (stage == "directory" and owner is cal and name == "_CACHE_DIR") or (stage == "cache" and owner is memo and name == "_CACHE")
        if selected:
            fired.append(stage)
            raise failure
        return result
private_pytest = ModuleType("pytest")
vars(private_pytest).update(vars(pytest))
private_pytest.MonkeyPatch = Patch
class OwnedPath(type(Path())):
    def write_bytes(self, data):
        if stage == "write-before":
            fired.append(stage)
            raise failure
        result = super().write_bytes(data)
        if stage == "write-after":
            fired.append(stage)
            raise failure
        return result
native_source = root / "core/sandbox/tests/test_calibration_cache_identity.py"
body = ast.parse(native_source.read_bytes()).body
names = ["isolated_cache", "binary", {"generation": "test_old_waiters_do_not_receive_or_overwrite_new_generation", "waiter": "test_waiter_timeout_does_not_cancel_or_replace_owner"}[case]]
selected = [next(x for x in body if isinstance(x, ast.FunctionDef) and x.name == name) for name in names]
for node in selected: node.decorator_list = []
native = ModuleType("owned_calibration_native")
vars(native).update(cal=cal, memo=memo, os=os)
exec(compile(ast.Module(body=selected, type_ignores=[]), str(native_source), "exec", flags=__future__.annotations.compiler_flag), vars(native))
for name in ("isolated_cache", "binary"):
    function = getattr(native, name)
    function.__wrapped__ = function
source = root / ("core/testing/tests/test_calibration_" + case + "_worker_ownership_scope.py")
node = next(x for x in ast.parse(source.read_bytes()).body if isinstance(x, ast.FunctionDef) and x.name == "exercise")
namespace = dict(contextmanager=contextmanager, ModuleType=ModuleType, threading=threading, pytest=private_pytest, native=native, module_function_view=module_function_view)
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec", flags=__future__.annotations.compiler_flag), namespace)
try:
    caught = None
    try:
        with namespace["exercise"]("normal", OwnedPath(scratch)) as (invoke, workers):
            assert stage == "normal" and not workers
            assert memo._CACHE is not borrowed[0] and cal._CACHE_DIR == scratch / "profiles"
            assert (scratch / "tool").read_bytes() == b"one"
            # Never invoke the calibration test/loader or worker body.
    except BaseException as error:
        caught = error
    if stage == "normal": assert caught is None and not fired
    else: assert caught is failure and fired == [stage], repr(caught)
    if expectation == "baseline":
        assert stage == "write-before" and memo._CACHE is not borrowed[0] and cal._CACHE_DIR is not borrowed[1]
    else:
        assert expectation == "candidate" and memo._CACHE is borrowed[0] and cal._CACHE_DIR is borrowed[1]
    assert cal.load_or_calibrate is borrowed[2] and dict(os.environ) == borrowed_env and not attempts
    result = dict(result="CALIBRATION_SETUP_BASELINE_LEAK" if expectation == "baseline" else "CALIBRATION_SETUP_OWNER_OK", case=case, stage=stage, forbidden_attempts=attempts)
finally:
    for patch in reversed(patches): patch.undo()
assert memo._CACHE is borrowed[0] and cal._CACHE_DIR is borrowed[1] and cal.load_or_calibrate is borrowed[2]
assert dict(os.environ) == borrowed_env
print(json.dumps(result, sort_keys=True))

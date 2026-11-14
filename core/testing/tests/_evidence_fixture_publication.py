from pathlib import Path
import ast, __future__, json, os, socket, subprocess, sys, threading
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
# Avoid incidental ldconfig/compiler discovery during sandbox bootstrap.
ctypes.util.find_library = lambda name: None
from core.sandbox import evidence
from core.testing.module_views import module_function_view
borrowed = evidence.EvidenceFile
borrowed_os, original_write = evidence.os, os.write
failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]("owned evidence publication fault")
patches, fired = [], []
class Patch(pytest.MonkeyPatch):
    def __init__(self):
        super().__init__()
        patches.append(self)
    def setattr(self, owner, name, value, *args, **kwargs):
        if owner is evidence and name == "EvidenceFile" and stage == "before":
            fired.append(stage)
            raise failure
        result = super().setattr(owner, name, value, *args, **kwargs)
        if owner is evidence and name == "EvidenceFile" and stage == "after":
            fired.append(stage)
            raise failure
        return result
private_pytest = ModuleType("pytest")
vars(private_pytest).update(vars(pytest))
private_pytest.MonkeyPatch = Patch
native_source = root / "core/sandbox/tests/test_evidence_lifecycle.py"
name = {"closer": "test_concurrent_closers_share_one_verification_and_release", "encoding": "test_close_during_encoding_cannot_write_to_reused_descriptor"}[case]
function = next(x for x in ast.parse(native_source.read_bytes()).body if isinstance(x, ast.FunctionDef) and x.name == name)
function.decorator_list = []
native = ModuleType("owned_evidence_native")
native.evidence = evidence
exec(compile(ast.Module(body=[function], type_ignores=[]), str(native_source), "exec", flags=__future__.annotations.compiler_flag), vars(native))
source = root / ("core/testing/tests/test_evidence_" + case + "_worker_ownership_scope.py")
raw = source.read_bytes()
node = next(x for x in ast.parse(raw).body if isinstance(x, ast.FunctionDef) and x.name == "exercise")
namespace = dict(contextmanager=contextmanager, ModuleType=ModuleType, os=os, threading=threading, pytest=private_pytest, native=native, module_function_view=module_function_view)
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec", flags=__future__.annotations.compiler_flag), namespace)
try:
    caught = None
    args = ("normal", scratch, True) if case == "closer" else ("normal", scratch)
    try:
        with namespace["exercise"](*args) as (invoke, workers, handles):
            assert stage == "normal" and not workers and not handles
            assert evidence.EvidenceFile is not borrowed
            # Do not invoke native body or instantiate EvidenceFile.
    except BaseException as error:
        caught = error
    if stage == "normal": assert caught is None and not fired
    else: assert caught is failure and fired == [stage], repr(caught)
    if expectation == "baseline":
        assert stage == "after" and evidence.EvidenceFile is not borrowed
    else:
        assert expectation == "candidate" and evidence.EvidenceFile is borrowed
    assert evidence.os is borrowed_os and os.write is original_write and not attempts
    result = dict(result="EVIDENCE_SETUP_BASELINE_LEAK" if expectation == "baseline" else "EVIDENCE_SETUP_OWNER_OK", case=case, stage=stage, forbidden_attempts=attempts)
finally:
    for patch in reversed(patches): patch.undo()
assert evidence.EvidenceFile is borrowed and evidence.os is borrowed_os and os.write is original_write
print(json.dumps(result, sort_keys=True))

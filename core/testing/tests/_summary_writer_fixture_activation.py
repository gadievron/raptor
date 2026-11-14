from pathlib import Path
import ast, __future__, json, os, socket, subprocess, sys, threading
from contextlib import contextmanager
from types import ModuleType
from unittest.mock import Mock
root, scratch = map(Path, sys.argv[1:3])
stage, outcome, expectation = sys.argv[3:6]
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
from core.sandbox import summary, state
from core.testing.module_views import module_function_view
from core.testing.sandbox_state_scope import SUMMARY_DEFAULTS, SUMMARY_REGISTRIES, isolated_summary_state
failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]("owned summary fixture setup fault")
fired = []
def namespace(*args, **kwargs):
    result = ModuleType(*args, **kwargs)
    if stage == "namespace":
        fired.append(stage)
        raise failure
    return result
def view(*args, **kwargs):
    result = module_function_view(*args, **kwargs)
    if stage == "view":
        fired.append(stage)
        raise failure
    return result
native_source = root / "core/sandbox/tests/test_summary_run_generation.py"
body = ast.parse(native_source.read_bytes()).body
names = ["isolated_state", "test_threaded_transition_does_not_append_to_new_run_handle"]
nodes = [next(x for x in body if isinstance(x, ast.FunctionDef) and x.name == name) for name in names]
for node in nodes: node.decorator_list = []
native = ModuleType("owned_summary_native")
vars(native).update(summary=summary, state=state, isolated_summary_state=isolated_summary_state, Mock=Mock)
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(native_source), "exec", flags=__future__.annotations.compiler_flag), vars(native))
native.isolated_state.__wrapped__ = native.isolated_state
source = root / "core/testing/tests/test_summary_writer_ownership_scope.py"
node = next(x for x in ast.parse(source.read_bytes()).body if isinstance(x, ast.FunctionDef) and x.name == "exercise")
ns = dict(contextmanager=contextmanager, ModuleType=namespace, threading=threading, pytest=pytest, native=native, module_function_view=view, SUMMARY_DEFAULTS=SUMMARY_DEFAULTS, SUMMARY_REGISTRIES=SUMMARY_REGISTRIES)
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec", flags=__future__.annotations.compiler_flag), ns)
with pytest.MonkeyPatch.context() as caller:
    caller.setattr(state, "_cli_sandbox_disabled", True)
    names = (*SUMMARY_DEFAULTS, *SUMMARY_REGISTRIES, "_evidence", "dumps_artifact", "_log_security_event")
    borrowed = {name: getattr(summary, name) for name in names}
    caught = None
    scope = ns["exercise"]("normal", scratch)
    try:
        try:
            with scope as (invoke, workers):
                assert stage == "normal" and not workers
                assert summary._evidence is not borrowed["_evidence"]
                assert state._cli_sandbox_disabled is False
                # Never invoke writer/worker/native test body or create evidence handle.
        except BaseException as error: caught = error
        if stage == "normal": assert caught is None and not fired
        else: assert caught is failure and fired == [stage], repr(caught)
        restored = all(getattr(summary, name) is value for name, value in borrowed.items()) and state._cli_sandbox_disabled is True
        if expectation == "baseline":
            assert not restored and stage != "normal"
            assert summary._evidence is not borrowed["_evidence"]
            assert state._cli_sandbox_disabled is False
        else: assert expectation == "candidate" and restored
        assert not attempts
        result = dict(result="SUMMARY_ACTIVATION_BASELINE_LEAK" if expectation == "baseline" else "SUMMARY_ACTIVATION_OWNER_OK", stage=stage, forbidden_attempts=attempts)
    finally:
        # Observe first, then recover the fixture through the ordinary caught
        # primary traceback. No extra fixture reference is retained before observation.
        if caught is not None:
            trace = caught.__traceback__
            while trace is not None:
                frame = trace.tb_frame
                if frame.f_code.co_filename == str(source) and frame.f_code.co_name == "exercise":
                    fixture = frame.f_locals.get("fixture")
                    if fixture is not None:
                        try: next(fixture)
                        except StopIteration: pass
                trace = trace.tb_next
        scope.gen.close()
    assert all(getattr(summary, name) is value for name, value in borrowed.items())
    assert state._cli_sandbox_disabled is True
print(json.dumps(result, sort_keys=True))

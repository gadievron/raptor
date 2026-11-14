from pathlib import Path
import ast,__future__,json,os,socket,subprocess,sys,threading
from contextlib import contextmanager
from types import ModuleType
root,scratch=map(Path,sys.argv[1:3]);stage,outcome,expectation=sys.argv[3:6]
attempts=[]
def denied(*args,**kwargs):
    attempts.append("secondary execution, worker or transport")
    raise AssertionError(attempts[-1])
subprocess.Popen=denied
for name in ("fork","forkpty","system","posix_spawn","posix_spawnp","execl","execle","execv","execve","execvp","execvpe"):
    if hasattr(os,name):setattr(os,name,denied)
socket.socket.connect=denied;socket.socket.connect_ex=denied
threading.Thread.start=denied
sys.path.insert(0,str(root))
import pytest
from core.security import prompt_telemetry
from core.testing.module_views import module_function_view
failure={"error":RuntimeError,"interrupt":KeyboardInterrupt}[outcome]("owned nonce fixture setup fault")
borrowed=prompt_telemetry.defense_telemetry
snapshot=borrowed.summary()
patches=[];fired=[]
class Patch(pytest.MonkeyPatch):
    def __init__(self):
        super().__init__();patches.append(self)
    def setattr(self,obj,name,value,*args,**kwargs):
        super().setattr(obj,name,value,*args,**kwargs)
        if stage=="publication" and obj is prompt_telemetry and name=="defense_telemetry":
            fired.append(stage);raise failure
private_pytest=ModuleType("pytest");vars(private_pytest).update(vars(pytest));private_pytest.MonkeyPatch=Patch
private_threads=ModuleType("threading");vars(private_threads).update(vars(threading))
def event(*args,**kwargs):
    if stage=="event":fired.append(stage);raise failure
    return threading.Event(*args,**kwargs)
private_threads.Event=event
native_source=root/"packages/llm_analysis/tests/test_defense_wiring.py";native_tree=ast.parse(native_source.read_bytes())
fixture=next(x for x in native_tree.body if isinstance(x,ast.FunctionDef) and x.name=="_isolated_defense_telemetry");fixture.decorator_list=[]
cls=next(x for x in native_tree.body if isinstance(x,ast.ClassDef) and x.name=="TestNonceTracking")
method=next(x for x in cls.body if isinstance(x,ast.FunctionDef) and x.name=="test_nonce_thread_safety")
# Only an uninvoked source method is needed to enter the companion context.
# No AnalysisTask globals or provider/task implementations are supplied.
selected=ast.ClassDef(name=cls.name,bases=[],keywords=[],body=[method],decorator_list=[])
native=ModuleType("owned_nonce_native")
exec(compile(ast.fix_missing_locations(ast.Module(body=[fixture,selected],type_ignores=[])),str(native_source),"exec",flags=__future__.annotations.compiler_flag),vars(native))
native._isolated_defense_telemetry.__wrapped__=native._isolated_defense_telemetry
source=root/"core/testing/tests/test_nonce_thread_ownership_scope.py";raw=source.read_bytes();node=next(x for x in ast.parse(raw).body if isinstance(x,ast.FunctionDef) and x.name=="exercise")
namespace=dict(contextmanager=contextmanager,pytest=private_pytest,prompt_telemetry=prompt_telemetry,threading=private_threads,ModuleType=ModuleType,native=native,module_function_view=module_function_view)
exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),"exec",flags=__future__.annotations.compiler_flag),namespace)
try:
    scope=namespace["exercise"]("normal")
    caught=None
    try:
        with scope as (invoke,workers):
            assert stage=="normal" and not workers
            assert prompt_telemetry.defense_telemetry is not borrowed
            # Intentionally do not invoke the task/worker body.
    except BaseException as error:caught=error
    if stage=="normal":assert caught is None and not fired
    else:assert caught is failure and fired==[stage],repr(caught)
    if expectation=="baseline":
        assert stage!="normal" and prompt_telemetry.defense_telemetry is not borrowed
    else:
        assert expectation=="candidate" and prompt_telemetry.defense_telemetry is borrowed
        assert borrowed.summary()==snapshot
    assert not attempts
    result={"result":"NONCE_SETUP_BASELINE_LEAK" if expectation=="baseline" else "NONCE_SETUP_OWNER_OK","stage":stage,"source_sha256":__import__("hashlib").sha256(raw).hexdigest(),"forbidden_attempts":attempts}
finally:
    for patch in reversed(patches):patch.undo()
assert prompt_telemetry.defense_telemetry is borrowed and borrowed.summary()==snapshot
print(json.dumps(result,sort_keys=True))

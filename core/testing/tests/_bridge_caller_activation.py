from pathlib import Path
import ast, __future__, atexit, builtins, importlib.util, inspect, json, os, socket, subprocess, sys, threading
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from types import ModuleType
root, scratch = map(Path, sys.argv[1:3])
stage, outcome, expectation = sys.argv[3:6]
if stage != "pair-refusal" or expectation != "candidate":
    raise ValueError("this profile admits only candidate pair refusal")
attempts, pairs, fired = [], [], []
attempt_total = socket_creations = sent = received = 0
pair_factory_calls = 0
def blocked(api):
    def denied(*args, **kwargs):
        global attempt_total
        attempt_total += 1
        if len(attempts) < 32: attempts.append(api)
        raise AssertionError("denied proof boundary: " + api)
    return denied
def audit(event, args):
    global socket_creations
    if event == "socket.__new__":
        return blocked("all socket construction denied in refusal-only profile")(*args)
    elif event.startswith("subprocess.") or event in {"os.fork", "os.forkpty", "os.system", "os.posix_spawn", "os.exec", "socket.connect", "socket.bind", "socket.getaddrinfo", "socket.gethostbyname", "socket.sendto", "ctypes.dlopen", "ctypes.dlsym"}:
        return blocked("audit:" + event)(*args)
sys.addaudithook(audit)
def guard_record():
    (scratch / "guard.json").write_text(json.dumps(dict(attempts=attempts, attempt_total=attempt_total, owned_unix_pairs=len(pairs), socket_creations=socket_creations, sent=sent, received=received, pair_factory_calls=pair_factory_calls, profile="refusal-only", pair_closed=[sock.fileno() == -1 for value in pairs for sock in value]), sort_keys=True))
atexit.register(guard_record)
subprocess.Popen = blocked("subprocess.Popen")
for name in ("fork", "forkpty", "system", "posix_spawn", "posix_spawnp", "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"):
    if hasattr(os, name): setattr(os, name, blocked("os." + name))
for name in ("connect", "connect_ex", "bind", "listen", "accept", "sendto"):
    setattr(socket.socket, name, blocked("socket." + name))
socket.socketpair = blocked("socket.socketpair outside selected seam")
threading.Thread.start = blocked("Thread.start")
socket.socket.sendall = blocked("sendall in refusal-only profile")
socket.socket.recv = blocked("recv in refusal-only profile")
sys.path.insert(0, str(root))
import pytest
# Load the complete exact stdlib-only helper file under a private library name.
# This does not import core.sandbox or a native bridge test module.
library_path = root / "core/sandbox/tests/socket_server.py"
spec = importlib.util.spec_from_file_location("owned_socket_server_library", library_path)
library = importlib.util.module_from_spec(spec)
spec.loader.exec_module(library)
SocketServer = library.SocketServer
SocketServer.__new__ = staticmethod(blocked("SocketServer construction"))
failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome]("owned bridge caller setup fault")
native_source = root / "core/sandbox/tests/test_proxy_bridge_setup_failure.py"
native_name = "core.sandbox.tests.test_proxy_bridge_setup_failure"
native = ModuleType(native_name)
vars(native).update(SocketServer=SocketServer, socket=socket, os=os, threading=threading)
private_sys = ModuleType("sys")
vars(private_sys).update(vars(sys))
private_sys.modules = dict(sys.modules)
private_sys.modules[native_name] = native
original_import = builtins.__import__
def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "sys" and level == 0: return private_sys
    return original_import(name, globals, locals, fromlist, level)
native.__dict__["__builtins__"] = dict(vars(builtins), __import__=fixture_import)
nodes = [x for x in ast.parse(native_source.read_bytes()).body if isinstance(x, ast.FunctionDef) and x.name in {"_owned_backends", "test_upstream_socket_exhaustion_allows_later_connection"}]
assert len(nodes) == 2
for node in nodes: node.decorator_list = []
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(native_source), "exec", flags=__future__.annotations.compiler_flag), vars(native))
native._owned_backends.__wrapped__ = native._owned_backends
private_importlib = ModuleType("importlib")
def selected_import(name):
    assert name == native_name
    return native
private_importlib.import_module = selected_import
def pair():
    global pair_factory_calls
    pair_factory_calls += 1
    if pair_factory_calls != 1:
        return blocked("repeated refusal factory")()
    assert len(tracking) == 1
    assert native.SocketServer is not tracking[0]
    assert issubclass(native.SocketServer, tracking[0])
    fired.append(stage)
    raise failure
private_socket = ModuleType("socket")
vars(private_socket).update(vars(socket))
private_socket.socketpair = pair
source = root / "core/testing/tests/test_bridge_resource_unwind.py"
nodes = [x for x in ast.parse(source.read_bytes()).body if isinstance(x, (ast.FunctionDef, ast.ClassDef)) and x.name in {"_private", "_Resources", "_native_resources"}]
assert len(nodes) == 3
ns = dict(contextmanager=contextmanager, importlib=private_importlib, inspect=inspect, os=os, Path=Path, socket=private_socket, subprocess=subprocess, TemporaryDirectory=TemporaryDirectory, threading=threading, ModuleType=ModuleType, pytest=pytest)
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec", flags=__future__.annotations.compiler_flag), ns)
tracking = []
class ExternalPatch(pytest.MonkeyPatch):
    def setattr(self, owner, name, value, *args, **kwargs):
        result = super().setattr(owner, name, value, *args, **kwargs)
        if owner is native and name == "SocketServer": tracking.append(value)
        return result
with ExternalPatch.context() as external:
    scope = ns["_native_resources"](("setup_failure", "test_upstream_socket_exhaustion_allows_later_connection"), "bind", RuntimeError, external)
    caught = None
    try:
        try:
            with scope as (resources, invoke):
                raise AssertionError("the selected pair-refusal seam was not reached")
        except BaseException as error: caught = error
        assert len(tracking) == 1
        assert caught is failure and fired == [stage] and pair_factory_calls == 1
        assert not pairs and socket_creations == sent == received == 0
        assert native.SocketServer is tracking[0]
        assert not attempts
        result = dict(result="BRIDGE_REFUSAL_OWNER_OK", stage=stage, owned_unix_pairs=len(pairs), forbidden_attempts=attempts)
    finally:
        # Observe first. Recover an unclosed backend generator only through
        # the ordinary caught primary traceback, before external undo.
        if caught is not None:
            trace = caught.__traceback__
            while trace is not None:
                frame = trace.tb_frame
                if frame.f_code.co_filename == str(source) and frame.f_code.co_name == "_native_resources":
                    backend = frame.f_locals.get("backend_owner")
                    if backend is not None: backend.close()
                    body = frame.f_locals.get("body")
                    if body is not None: body.undo()
                trace = trace.tb_next
        scope.gen.close()
        for pair_value in pairs:
            for sock in pair_value: sock.close()
    assert native.SocketServer is tracking[0]
assert native.SocketServer is SocketServer
assert all(sock.fileno() == -1 for pair_value in pairs for sock in pair_value)
assert not attempts
print(json.dumps(result, sort_keys=True))

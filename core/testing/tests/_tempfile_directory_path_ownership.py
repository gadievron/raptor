from pathlib import Path
import ast, errno, hashlib, json, os, sys, tempfile
from types import FunctionType, ModuleType
root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in {"path_error", "healthy"}
output = Path(sys.argv[3]).resolve()
assert output.parent.is_dir() and not output.exists()
sys.path.insert(0, str(root))
import pytest
from core.testing.tempdirs import private_tempfile_module
from core.testing.module_views import module_function_view
source = root / "core/testing/tests/test_tempfile_views.py"
data = source.read_bytes()
assert hashlib.sha256(data).hexdigest() == "e7ca53ee28e5c30ab22b0d23de1c2c8f78c7c2551934e84b3f5abc6cb5896b2d"
tree = ast.parse(data)
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "test_real_factory_obeys_private_root_and_releases_resources")
node.decorator_list = []
namespace = {"pytest": pytest, "tempfile": tempfile, "Path": Path, "os": os, "errno": errno, "module_function_view": module_function_view, "private_tempfile_module": private_tempfile_module}
from contextlib import ExitStack
import shutil
namespace.update(ExitStack=ExitStack, shutil=shutil)
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
original = namespace[node.name]
owned = []
removal_calls = []
private_shutil = ModuleType("shutil")
vars(private_shutil).update(vars(shutil))
def remove(name):
    removal_calls.append(name)
    return shutil.rmtree(name)
private_shutil.rmtree = remove
sentinel = RuntimeError("private Path setup refusal")
real_factory = private_tempfile_module
forbidden = []
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec"}:
        forbidden.append(event)
        raise AssertionError("forbidden action: " + event)
sys.addaudithook(audit)
work = output.parent / "factory-root"
work.mkdir(mode=0o700)
def view(original):
    private = real_factory(original)
    allocate = private.mkdtemp
    def mkdtemp(*args, **kwargs):
        name = allocate(*args, **kwargs)
        st = os.stat(name)
        owned.append((name, (st.st_dev, st.st_ino)))
        return name
    private.mkdtemp = mkdtemp
    return private
def path_refusal(name):
    assert len(owned) == 1 and name == owned[0][0]
    if mode == "path_error":
        raise sentinel
    return Path(name)
caller = FunctionType(original.__code__, {**original.__globals__, "Path": path_refusal, "private_tempfile_module": view, "shutil": private_shutil})
observed = None
try:
    try:
        caller(work, "canonical", "mkdtemp", "normal")
    except BaseException as error:
        observed = error
    assert (isinstance(observed, AssertionError) and observed.__context__ is sentinel) if mode == "path_error" else observed is None
    assert len(owned) == 1
    name, identity = owned[0]
    absent = not Path(name).exists()
    assert absent and removal_calls == [name] and not forbidden
    payload = {"mode": mode, "outward_assertion": isinstance(observed, AssertionError), "path_error_context_identity": observed.__context__ is sentinel if observed else None, "owned_directory_absent_before_rescue": absent, "source_removal_calls": len(removal_calls), "source_body_unchanged_except_cleanup_registration": True, "forbidden_attempts": forbidden}
finally:
    for name, identity in owned:
        if Path(name).exists():
            st = os.stat(name)
            assert (st.st_dev, st.st_ino) == identity and not list(Path(name).iterdir())
            os.rmdir(name)
        assert not Path(name).exists()
    assert not list(work.iterdir())
    work.rmdir()
payload["independent_verified_rescue_complete"] = True
with output.open("x") as stream:
    json.dump(payload, stream)

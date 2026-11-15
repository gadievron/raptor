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
assert hashlib.sha256(data).hexdigest() == "0514a96b94697e53bfab082d1e1c295446b86ea0bd0d46502b4eb1551210c7cd"
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
close_calls = []
unlink_calls = []
private_os = ModuleType("os")
vars(private_os).update(vars(os))
def close(fd):
    close_calls.append(fd)
    return os.close(fd)
def unlink(name):
    unlink_calls.append(name)
    return os.unlink(name)
private_os.close, private_os.unlink = close, unlink
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
    allocate = private.mkstemp
    def mkstemp(*args, **kwargs):
        fd, name = allocate(*args, **kwargs)
        st = os.fstat(fd)
        owned.append((fd, name, (st.st_dev, st.st_ino)))
        return fd, name
    private.mkstemp = mkstemp
    return private
def path_refusal(name):
    assert len(owned) == 1 and name == owned[0][1]
    if mode == "path_error":
        raise sentinel
    return Path(name)
caller = FunctionType(original.__code__, {**original.__globals__, "Path": path_refusal, "private_tempfile_module": view, "os": private_os})
observed = None
try:
    try:
        caller(work, "canonical", "mkstemp", "normal")
    except BaseException as error:
        observed = error
    assert (isinstance(observed, AssertionError) and observed.__context__ is sentinel) if mode == "path_error" else observed is None
    assert len(owned) == 1
    fd, name, identity = owned[0]
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        live = False
    else:
        live = True
    present = Path(name).exists()
    assert not live and not present and not forbidden
    assert close_calls == [fd] and unlink_calls == [name]
    payload = {"mode": mode, "outward_assertion": isinstance(observed, AssertionError), "path_error_context_identity": observed.__context__ is sentinel if observed else None, "owned_fd_closed_before_rescue": not live, "owned_path_absent_before_rescue": not present, "source_close_calls": len(close_calls), "source_unlink_calls": len(unlink_calls), "source_body_unchanged_except_cleanup_registration": True, "forbidden_attempts": forbidden}
finally:
    for fd, name, identity in owned:
        try:
            st = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            assert (st.st_dev, st.st_ino) == identity
            os.close(fd)
        if Path(name).exists():
            Path(name).unlink()
    assert not list(work.iterdir())
    work.rmdir()
payload["independent_verified_rescue_complete"] = True
with output.open("x") as stream:
    json.dump(payload, stream)

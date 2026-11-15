from pathlib import Path
import ast, errno, hashlib, json, logging, os, sys
from contextlib import ExitStack, contextmanager
from types import ModuleType
import pytest
root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in {"attach_error", "healthy", "body_error"}
output = Path(sys.argv[3]).resolve()
assert output.parent.is_dir() and not output.exists()
pins = {'core/testing/tests/test_logging_state.py': '6fac9a429c45d7f39e00403da518b5e777a29d07cfd232bb4c2390742d9c9c8d', 'core/testing/logging_state.py': '8dace79f2da1419dcc4afa1f9a710931238821c5620b71f5d98fe851cd0d351a', 'core/logging/__init__.py': 'f5ce44b7751975e88f878142472e64eacbfb76f6b3da21c7d16d04cd232ce8a3'}
for name, digest in pins.items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
native_path = root / "core/testing/tests/test_logging_state.py"
helper_path = root / "core/testing/logging_state.py"
producer_path = root / "core/logging/__init__.py"
native = ast.parse(native_path.read_bytes())
helper = ast.parse(helper_path.read_bytes())
producer = ast.parse(producer_path.read_bytes())
selected = next(n for n in native.body if isinstance(n, ast.FunctionDef) and n.name == "test_file_handler_and_levels_restored_on_every_exit")
selected.decorator_list = []
helpers = [n for n in helper.body if isinstance(n, ast.FunctionDef) and n.name in {"isolated_cli_logging", "owned_log_handler"}]
assert len(helpers) == 2
quiet = next(n for n in producer.body if isinstance(n, ast.FunctionDef) and n.name == "quiet_third_party_loggers")
constant = next(n for n in producer.body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == "NOISY_THIRD_PARTY_LOGGERS")
names = ast.literal_eval(constant.value)
sentinel = OSError("owned borrowed handler comparison refused")
class Borrowed(logging.NullHandler):
    __hash__ = object.__hash__
    def __eq__(self, other):
        if isinstance(other, logging.FileHandler) and mode == "attach_error":
            raise sentinel
        return self is other
private_root = logging.RootLogger(logging.WARNING)
manager = logging.Manager(private_root)
private_root.manager = manager
borrowed = Borrowed()
private_root.addHandler(borrowed)
original_list = private_root.handlers
created = []
source_closes = []
real_file_handler = logging.FileHandler
def file_handler(*args, **kwargs):
    handler = real_file_handler(*args, **kwargs)
    stream = handler.stream
    st = os.fstat(stream.fileno())
    created.append((handler, stream, stream.fileno(), (st.st_dev, st.st_ino)))
    real_close = handler.close
    def close():
        source_closes.append(handler)
        return real_close()
    handler.close = close
    return handler
private_logging = ModuleType("logging")
vars(private_logging).update(vars(logging))
private_logging.getLogger = lambda name=None: private_root if not name else manager.getLogger(name)
private_logging.FileHandler = file_handler
namespace = {"logging": private_logging, "NOISY_THIRD_PARTY_LOGGERS": names, "ExitStack": ExitStack, "contextmanager": contextmanager, "__file__": str(native_path), "pytest": pytest}
exec(compile(ast.Module(body=helpers + [quiet, selected], type_ignores=[]), str(native_path), "exec"), namespace)
forbidden = []
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.kill", "os.killpg"}:
        forbidden.append(event)
        raise AssertionError("forbidden action: " + event)
sys.addaudithook(audit)
work = output.parent / "logging-root"
work.mkdir(mode=0o700)
try:
    observed = None
    try:
        namespace[selected.name](work, mode == "body_error")
    except BaseException as error:
        observed = error
    expected = observed is sentinel if mode == "attach_error" else observed is None
    assert expected and len(created) == 1 and not forbidden
    handler, stream, fd, identity = created[0]
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        closed = True
    else:
        closed = False
    assert closed and stream.closed and handler._closed and source_closes == [handler]
    assert private_root.handlers is original_list and len(private_root.handlers) == 1 and private_root.handlers[0] is borrowed
    assert not borrowed._closed
    if mode != "attach_error":
        assert (work / "debug.log").read_text().strip() == "written"
    payload = {"mode": mode, "expected_exception_or_native_success": expected, "stream_fd_closed_before_rescue": closed and stream.closed, "source_close_calls": len(source_closes), "unattached_after_scope": all(item is not handler for item in private_root.handlers), "borrowed_root_list_restored": True, "borrowed_handler_kept_open": not borrowed._closed, "private_manager": private_root.manager is manager, "full_selected_function": True, "native_content_assertions_passed": mode != "attach_error", "forbidden_attempts": forbidden}
finally:
    for handler, stream, fd, identity in created:
        real_file_handler.close(handler)
        assert stream.closed
        try:
            os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("rescue failed to close file descriptor")
    private_root.removeHandler(borrowed)
    borrowed.close()
    for file in work.iterdir():
        assert file.name == "debug.log" and file.is_file()
        file.unlink()
    work.rmdir()
payload["independent_verified_rescue_complete"] = True
with output.open("x") as stream:
    json.dump(payload, stream)

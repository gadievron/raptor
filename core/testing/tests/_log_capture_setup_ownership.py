from pathlib import Path
import ast, copy, errno, hashlib, json, logging, os, sys
from types import ModuleType, SimpleNamespace
root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in {"setup_error", "healthy"}
output = Path(sys.argv[3]).resolve()
assert output.parent.is_dir() and not output.exists()
source = root / "core/testing/tests/test_log_capture_cleanup.py"
data = source.read_bytes()
assert hashlib.sha256(data).hexdigest() == "610a24cb253e5d48ba083adb530d34c42b25273b8a192237a6f574530379ae8b"
tree = ast.parse(data)
function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "test_class_capture_cleanup")
assert ast.dump(function.body[0], include_attributes=False) == ast.dump(ast.parse("module = import_module(module_name)").body[0], include_attributes=False)
assert isinstance(function.body[4], ast.Try)
assert isinstance(function.body[4].body[2], ast.If)
assert all(isinstance(n, ast.Assign) for n in function.body[1:4])
private_logger = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "private_logger")
function.decorator_list = []
guarded = copy.deepcopy(function.body[4])
guarded.body = guarded.body[:3]
function.body = function.body[1:4] + [guarded]
# Only the import assignment is excluded. This prefix does not inspect module
# state or execute a consumer class/body; the receiver is an opaque owned token.
receiver = ModuleType("owned_capture_consumer_token")
created = []
close_calls = []
callback_stream_live = []
publications = []
logger_pair = []
real_file_handler = logging.FileHandler
private_logging = ModuleType("logging")
vars(private_logging).update(vars(logging))
def file_handler(*args, **kwargs):
    handler = real_file_handler(*args, **kwargs)
    raw = handler.stream
    st = os.fstat(raw.fileno())
    created.append((handler, raw, raw.fileno(), (st.st_dev, st.st_ino)))
    real_close = handler.close
    def close():
        close_calls.append(handler)
        return real_close()
    handler.close = close
    return handler
private_logging.FileHandler = file_handler
namespace = {"logging": private_logging, "SimpleNamespace": SimpleNamespace, "module": receiver}
exec(compile(ast.Module(body=[private_logger, function], type_ignores=[]), str(source), "exec"), namespace)
actual_private_logger = namespace["private_logger"]
def own_logger():
    pair = actual_private_logger()
    logger_pair.append(pair)
    return pair
namespace["private_logger"] = own_logger
sentinel = RuntimeError("private capture setup refusal")
class Patch:
    def setattr(self, consumer, name, value):
        assert consumer is receiver and name == "RaptorLogger" and len(created) == 1
        callback_stream_live.append(not created[0][1].closed)
        if mode == "setup_error":
            raise sentinel
        setattr(consumer, name, value)
        publications.append(name)
attempts = []
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec"}:
        attempts.append(event)
        raise AssertionError("forbidden action: " + event)
sys.addaudithook(audit)
work = output.parent / "capture-root"
work.mkdir(mode=0o700)
observed = None
try:
    try:
        namespace["test_class_capture_cleanup"]("core.logging.tests.test_logger_format_args", "FormatArgsAcrossLevelsTest", "normal", work, Patch())
    except BaseException as error:
        observed = error
    assert (observed is sentinel) if mode == "setup_error" else observed is None
    assert len(created) == len(logger_pair) == 1
    handler, stream, fd, identity = created[0]
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        closed = True
    else:
        closed = False
    assert closed and stream.closed and handler._closed
    assert callback_stream_live == [True] and close_calls == [handler]
    assert publications == (["RaptorLogger"] if mode == "healthy" else [])
    assert logger_pair[0][1]._closed and not attempts
    payload = {"mode": mode, "primary_identity": observed is sentinel if observed else None, "owned_file_stream_closed_before_rescue": closed and stream.closed, "source_close_calls": len(close_calls), "stream_live_during_setup": callback_stream_live == [True], "private_publication_names": publications, "borrowed_closed_by_source_finally": logger_pair[0][1]._closed, "consumer_module_body_excluded": True, "opaque_receiver_not_inspected": True, "forbidden_attempts": attempts}
finally:
    for handler, stream, fd, identity in created:
        real_file_handler.close(handler)
        assert stream.closed
        try:
            os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("rescue did not close capture descriptor")
    for logger, borrowed in logger_pair:
        logger.removeHandler(borrowed)
        borrowed.close()
    for file in work.iterdir():
        assert file.name == "owned.log" and file.is_file()
        file.unlink()
    work.rmdir()
payload["independent_verified_rescue_complete"] = True
with output.open("x") as stream:
    json.dump(payload, stream)

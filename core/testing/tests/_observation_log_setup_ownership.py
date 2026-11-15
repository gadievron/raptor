import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

parser = argparse.ArgumentParser()
parser.add_argument("root", type=Path)
parser.add_argument("scenario", choices=("error", "interrupt", "success"))
parser.add_argument("expect", choices=("candidate",))
parser.add_argument("output", type=Path)
args = parser.parse_args()
attempts = []
def audit(event, values):
    if event.startswith(("subprocess.", "socket.", "ctypes.dlopen", "ctypes.dlsym")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "pty.spawn"}:
        attempts.append(event)
        raise PermissionError("denied observation setup boundary: " + event)
sys.addaudithook(audit)
source_path = args.root / "core/audit/tests/test_frida_observe.py"
source = source_path.read_bytes()
assert hashlib.sha256(source).hexdigest() == "3d88722238e20f776b85a5bddd2a8e5113a9c1a686ebb5839c288943433bb728"
cls = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == "TestParseObservations")
method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_write_log")
assert not method.decorator_list
owned = []
closed = []
writes = []
unlinks = []
primary = KeyboardInterrupt("owned log write interruption") if args.scenario == "interrupt" else OSError("owned log write refusal")
def allocate(*positional, **keywords):
    assert not owned
    fd, name = tempfile.mkstemp(*positional, **keywords)
    owned.append((fd, Path(name)))
    return fd, name
def close(fd):
    assert len(owned) == 1 and fd == owned[0][0] and not closed
    os.close(fd)
    closed.append(fd)
def unlink(name):
    assert len(owned) == 1 and Path(name) == owned[0][1] and not unlinks
    os.unlink(name)
    unlinks.append(str(name))

class OwnedPath(type(Path())):
    def write_text(self, text, *positional, **keywords):
        assert len(owned) == 1 and Path(self) == owned[0][1]
        size = Path.write_text(self, text, *positional, **keywords)
        writes.append(Path.read_text(self))
        if args.scenario != "success":
            raise primary
        return size
    def unlink(self, missing_ok=False):
        assert len(owned) == 1 and Path(self) == owned[0][1]
        Path.unlink(self, missing_ok=missing_ok)
        unlinks.append(str(self))
namespace = {"tempfile": SimpleNamespace(mkstemp=allocate), "os": SimpleNamespace(close=close, unlink=unlink), "Path": OwnedPath}
exec(compile(ast.Module(body=[method], type_ignores=[]), str(source_path), "exec"), namespace)
caught = None
returned = None
result = None
try:
    try:
        returned = namespace["_write_log"](None, ["owned-call", "owned-return"])
    except BaseException as error:
        caught = error
    assert len(owned) == len(closed) == 1 and writes == ["owned-call\nowned-return"]
    path = owned[0][1]
    if args.scenario == "success":
        assert caught is None and Path(returned) == path and path.is_file()
        assert not unlinks
        returned.unlink()
        assert not path.exists() and len(unlinks) == 1
    else:
        assert caught is primary and returned is None
        assert path.exists() is (args.expect == "baseline")
    assert not attempts
    result = {"scenario": args.scenario, "expect": args.expect, "primary_identity": caught is primary if caught is not None else None, "descriptor_close_calls": len(closed), "actual_written_text": writes, "path_remaining_before_rescue": path.exists(), "unlink_calls": len(unlinks), "success_transfer_then_caller_cleanup": args.scenario == "success", "forbidden_attempts": attempts}
finally:
    for fd, path in owned:
        if fd not in closed:
            os.close(fd)
        if path.exists():
            path.unlink()
assert result is not None and not attempts
args.output.write_text(json.dumps(result, indent=2) + "\n")

import argparse
import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

parser = argparse.ArgumentParser()
parser.add_argument("root", type=Path)
parser.add_argument("scenario", choices=("error", "interrupt", "after-close"))
parser.add_argument("expect", choices=("candidate",))
parser.add_argument("output", type=Path)
args = parser.parse_args()
attempts = []
def denied(api):
    def fail(*positional, **keywords):
        attempts.append(api)
        raise AssertionError("denied scan setup boundary: " + api)
    return fail
def audit(event, values):
    if event.startswith(("subprocess.", "socket.", "ctypes.dlopen", "ctypes.dlsym")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "pty.spawn"}:
        return denied(event)()
sys.addaudithook(audit)
source_path = args.root / "packages/sca/tests/test_perf_baseline.py"
source = source_path.read_bytes()
assert hashlib.sha256(source).hexdigest() == "a5e769c19a7ea480472e32d6b3f35bb66d3031a1100999f69b7e894f3799378c"
node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "_run_scan")
assert not node.decorator_list
owned = []
closed = []
unlinked = []
clock_hits = []
primary = KeyboardInterrupt("owned result close interruption") if args.scenario == "interrupt" else RuntimeError("owned result setup error")
def allocate(*positional, **keywords):
    assert not owned
    fd, name = tempfile.mkstemp(*positional, **keywords)
    owned.append((fd, Path(name)))
    return fd, name
def close(fd):
    assert len(owned) == 1 and fd == owned[0][0] and not closed
    os.close(fd)
    closed.append(fd)
    if args.scenario != "after-close":
        raise primary
def unlink(name):
    assert len(owned) == 1 and Path(name) == owned[0][1] and not unlinked
    os.unlink(name)
    unlinked.append(str(name))
def clock():
    if args.scenario != "after-close":
        return denied("unexpected timing continuation")()
    clock_hits.append("after-close")
    raise primary
namespace = {"Path": Path, "sys": SimpleNamespace(executable=sys.executable), "tempfile": SimpleNamespace(mkstemp=allocate, TemporaryFile=denied("temporary scan stream")), "os": SimpleNamespace(close=close, unlink=unlink, wait4=denied("wait4"), killpg=denied("killpg")), "time": SimpleNamespace(perf_counter=clock, sleep=denied("sleep")), "subprocess": SimpleNamespace(Popen=denied("scan relay launch"))}
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source_path), "exec"), namespace)
caught = None
result = None
try:
    try:
        namespace["_run_scan"](args.output.parent / "unused-target", args.output.parent / "unused-scan-output")
    except BaseException as error:
        caught = error
    assert caught is primary and len(owned) == len(closed) == 1
    fd, path = owned[0]
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        raise AssertionError("owned descriptor was not closed")
    remains = path.exists()
    assert remains is (args.expect == "baseline" and args.scenario != "after-close")
    assert clock_hits == (["after-close"] if args.scenario == "after-close" else [])
    assert not attempts
    result = {"scenario": args.scenario, "expect": args.expect, "primary_identity": caught is primary, "owned_descriptor_closed": True, "result_path_remaining_before_rescue": remains, "unlink_calls": len(unlinked), "clock_hits": clock_hits, "forbidden_attempts": attempts}
finally:
    for fd, path in owned:
        if fd not in closed:
            os.close(fd)
        if path.exists():
            path.unlink()
assert result is not None and not attempts
args.output.write_text(json.dumps(result, indent=2) + "\n")

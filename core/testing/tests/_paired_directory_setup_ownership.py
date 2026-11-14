import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("root", type=Path)
parser.add_argument("site", choices=("demotion", "landlock"))
parser.add_argument("scenario", choices=("second-error", "second-interrupt", "healthy"))
parser.add_argument("output", type=Path)
args = parser.parse_args()
attempts = []
def audit(event, values):
    if event.startswith(("subprocess.", "socket.", "ctypes.dlopen", "ctypes.dlsym")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "pty.spawn"}:
        attempts.append(event)
        raise PermissionError("denied suffix proof boundary: " + event)
sys.addaudithook(audit)
path, class_name, digest = {
    "demotion": ("core/sandbox/tests/test_backend_demotion.py", "_Base", "1be4f46c4a335e6608e3685edea5243598eda43283dde77e8b9d13029236d3b8"),
    "landlock": ("core/sandbox/tests/test_ll_private_scratch.py", "TestRestrictedLandlockOnlyScratch", "a8011967af39471dd961fefe464b8082dda5dc38179eb9e268ab3439235b4f4c"),
}[args.site]
source_path = args.root / path
source = source_path.read_bytes()
assert hashlib.sha256(source).hexdigest() == digest
module = ast.parse(source)
cls = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == class_name)
method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "setUp")
assert not method.decorator_list
start = next(i for i, n in enumerate(method.body) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute) and n.value.func.attr == "TemporaryDirectory")
method.body = method.body[start:]
assert len(method.body) == 6
expected_suffix = {'_Base': 'e885eb0df044abe5bb8a4a5de8b61cc07cf8d07e08f5805ce30db0e9a879f3f1', 'TestRestrictedLandlockOnlyScratch': 'bc364e14a465747662d6025ccfa2acb594b6c9ddf5d3692c895ecc5bdaafce8d'}
assert hashlib.sha256(ast.dump(ast.Module(body=method.body, type_ignores=[]), include_attributes=False).encode()).hexdigest() == expected_suffix[class_name]
assert {n.id for n in ast.walk(method) if isinstance(n, ast.Name)} <= {"self", "tempfile", "os"}
case = unittest.TestCase()
allocated = []
calls = []
primary = KeyboardInterrupt("owned second allocation refusal") if args.scenario == "second-interrupt" else OSError("owned second allocation refusal")
def allocate(*positional, **keywords):
    calls.append(len(calls) + 1)
    assert len(calls) <= 2
    if len(calls) == 2 and args.scenario != "healthy":
        raise primary
    directory = tempfile.TemporaryDirectory(*positional, **keywords)
    allocated.append(directory)
    return directory
namespace = {"tempfile": SimpleNamespace(TemporaryDirectory=allocate), "os": SimpleNamespace(path=SimpleNamespace(realpath=os.path.realpath))}
exec(compile(ast.Module(body=[method], type_ignores=[]), str(source_path), "exec"), namespace)
caught = None
result = None
try:
    try:
        namespace["setUp"](case)
    except BaseException as error:
        caught = error
    assert calls == [1, 2]
    assert caught is (None if args.scenario == "healthy" else primary)
    assert len(allocated) == (2 if args.scenario == "healthy" else 1)
    assert case.doCleanups()
    remaining = [Path(directory.name).exists() for directory in allocated]
    assert remaining == ([False, False] if args.scenario == "healthy" else [False])
    result = {"site": args.site, "scenario": args.scenario, "scope": "selected allocation suffix only", "primary_identity": caught is primary if caught is not None else None, "remaining_before_rescue": remaining, "forbidden_attempts": attempts}
finally:
    for directory in allocated:
        directory.cleanup()
assert not attempts, attempts
assert result is not None
args.output.write_text(json.dumps(result, indent=2) + "\n")

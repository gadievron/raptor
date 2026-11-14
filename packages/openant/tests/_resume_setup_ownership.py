import argparse
import ast
import json
import tempfile
import sys
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
parser.add_argument("class_name", choices=("TestValidatePriorRun", "TestInFlightPriorRunRefuses", "TestScanFailedReportResumesLikeSuccess"))
parser.add_argument("scenario", choices=("mkdir-error", "mkdir-interrupt", "healthy"))
parser.add_argument("expect", choices=("baseline", "candidate"))
parser.add_argument("output", type=Path)
args = parser.parse_args()
attempts = []
def deny_event(event, values):
    if event.startswith(("subprocess.", "socket.", "ctypes.dlopen", "ctypes.dlsym")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "pty.spawn"}:
        attempts.append(event)
        raise PermissionError("secondary execution or transport denied: " + event)
sys.addaudithook(deny_event)
source = args.source.read_text()
assert args.expect == "candidate"
assert hashlib.sha256(source.encode()).hexdigest() == "150f0723847d29ac4d39218cca7e72dc32f19afd08a912c172430d0a0f45d484"
module = ast.parse(source, filename=str(args.source))
cls = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == args.class_name)
setup = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "setUp")
assert not setup.decorator_list
assert ast.dump(setup.args) == ast.dump(ast.parse("def setUp(self): pass").body[0].args)
allowed = {"tempfile", "Path", "self"}
assert {n.id for n in ast.walk(setup) if isinstance(n, ast.Name)} <= allowed
namespace = {"tempfile": tempfile, "Path": Path}
exec(compile(ast.Module(body=[setup], type_ignores=[]), str(args.source), "exec"), namespace)
case = unittest.TestCase()
primary = KeyboardInterrupt("owned mkdir refusal") if args.scenario == "mkdir-interrupt" else OSError("owned mkdir refusal")
original_mkdir = Path.mkdir
caught = None
result = None

def mkdir(path, *positional, **keywords):
    if hasattr(case, "repo") and path == case.repo and args.scenario != "healthy":
        raise primary
    return original_mkdir(path, *positional, **keywords)

try:
    try:
        with patch.object(Path, "mkdir", mkdir):
            namespace["setUp"](case)
    except BaseException as error:
        caught = error
    root = Path(case._td.name)
    assert root.is_dir()
    if args.scenario == "healthy":
        assert caught is None and case.repo.is_dir()
    else:
        assert caught is primary
        assert not case.repo.exists()
    assert case.doCleanups()
    remains = root.exists()
    expected_remains = args.expect == "baseline" and args.scenario != "healthy"
    assert remains == expected_remains, (remains, expected_remains)
    result = {"class": args.class_name, "scenario": args.scenario, "expect": args.expect, "primary_identity": caught is primary if caught is not None else None, "directory_exists_after_unittest_cleanup": remains, "independent_rescue_not_yet_run": True}
finally:
    if hasattr(case, "_td"):
        case._td.cleanup()
assert not attempts, attempts
assert result is not None
result["forbidden_attempts"] = attempts
args.output.write_text(json.dumps(result, indent=2) + "\n")

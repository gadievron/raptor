import argparse
import ast
import builtins
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
parser.add_argument("scenario", choices=("error", "interrupt", "cleanup-only"))
parser.add_argument("output", type=Path)
args = parser.parse_args()
attempts = []
def audit(event, values):
    if event.startswith(("subprocess.", "socket.", "ctypes.dlopen", "ctypes.dlsym")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "pty.spawn"}:
        attempts.append(event)
        raise PermissionError("denied setup proof boundary: " + event)
sys.addaudithook(audit)
source = args.source.read_bytes()
assert hashlib.sha256(source).hexdigest() == "88c833b28d16df5372fb1abd0eba04429a99b07b62d28a3a6f6de80fd3b1d0c8"
module = ast.parse(source)
cls = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == "TestSageFuzzingMemoryAPI")
setup = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "setUp")
assert not setup.decorator_list
primary = KeyboardInterrupt("owned import interruption") if args.scenario == "interrupt" else ImportError("owned import refusal")
hits = []
def import_owned(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "core.sage.config" and level == 0 and tuple(fromlist) == ("SageConfig",):
        hits.append(name)
        raise primary
    if name == "shutil" and level == 0:
        return shutil
    attempts.append("unapproved import:" + name)
    raise AssertionError("unapproved import: " + name)
namespace = {"tempfile": tempfile, "Path": Path, "__builtins__": dict(vars(builtins), __import__=import_owned)}
cleanup = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_cleanup_tmpdir")
exec(compile(ast.Module(body=[setup, cleanup], type_ignores=[]), str(args.source), "exec"), namespace)
case = unittest.TestCase()
case._cleanup_tmpdir = namespace["_cleanup_tmpdir"].__get__(case, type(case))
caught = None
result = None
try:
    try:
        if args.scenario == "cleanup-only":
            case.tmpdir = tempfile.mkdtemp()
            (Path(case.tmpdir) / "owned-marker").write_text("owned")
            case.addCleanup(case._cleanup_tmpdir)
        else:
            namespace["setUp"](case)
    except BaseException as error:
        caught = error
    assert caught is (None if args.scenario == "cleanup-only" else primary)
    assert hits == ([] if args.scenario == "cleanup-only" else ["core.sage.config"])
    directory = Path(case.tmpdir)
    assert directory.is_dir()
    assert case.doCleanups()
    remains = directory.exists()
    assert not remains
    result = {"scenario": args.scenario, "primary_identity": caught is primary if caught is not None else None, "import_seam_hits": hits, "directory_remaining_before_rescue": remains, "forbidden_attempts": attempts}
finally:
    if hasattr(case, "tmpdir") and Path(case.tmpdir).exists():
        shutil.rmtree(case.tmpdir)
assert not attempts, attempts
args.output.write_text(json.dumps(result, indent=2) + "\n")

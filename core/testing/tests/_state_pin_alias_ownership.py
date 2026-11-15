from pathlib import Path
import ast, hashlib, json, os, sys
root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in {"dotdot", "relative", "symlink", "root_symlink", "safe_child", "safe_missing"}
output = Path(sys.argv[3]).resolve()
assert not output.exists() and output.parent.is_dir()
assert sys.executable == "/home/raptor/raptor/out/codex-fleet/artifacts/root-release-environment-20261114/sdk/venv/bin/python"
source = root / "core/testing/state_isolation.py"
assert hashlib.sha256(source.read_bytes()).hexdigest() == "95f54d66b9986de9d8147cd8364931e33c82f19ddfbb7e23c7150fcdd7152f14"
tree = ast.parse(source.read_bytes())
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "pin_user_state_dirs")
stop = next(i for i, n in enumerate(fn.body) if isinstance(n, ast.ImportFrom) and n.module == "core.security")
prefix = fn.body[:stop]
assert not any(isinstance(n, (ast.Import, ast.ImportFrom)) for node in prefix for n in ast.walk(node))
# Only this return is carrier code; preceding statements are the exact native guard.
fn.body = prefix + [ast.Return(value=ast.Name(id="base", ctx=ast.Load()))]
namespace = {"Path": Path}
exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), str(source), "exec"), namespace)
forbidden = []
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.kill", "os.killpg"}:
        forbidden.append(event)
        raise AssertionError("forbidden action: " + event)
sys.addaudithook(audit)
home = Path.home()
assert home == output.parent / "home" and home.is_dir()
work = output.parent / "owned-guard-root"
work.mkdir(mode=0o700)
protected = home / ".raptor"
parent = home / "existing"
alias = work / "base-alias"
external = work / "protected-target"
try:
    if mode == "root_symlink":
        external.mkdir(mode=0o700)
        protected.symlink_to(external, target_is_directory=True)
        base = external
    else:
        protected.mkdir(mode=0o700)
        if mode == "dotdot":
            parent.mkdir(mode=0o700)
            base = parent / ".." / ".raptor"
        elif mode == "relative":
            base = Path(os.path.relpath(protected, Path.cwd()))
        elif mode == "symlink":
            alias.symlink_to(protected, target_is_directory=True)
            base = alias
        elif mode == "safe_child":
            base = home / "safe-scratch" / "child"
        else:
            base = work / "missing-scratch" / "child"
    canonical = base.resolve()
    expected_refusal = mode not in {"safe_child", "safe_missing"}
    if expected_refusal:
        assert canonical == protected.resolve()
    else:
        assert not base.exists() and canonical != protected.resolve()
    caught = None
    checked = None
    try:
        checked = namespace["pin_user_state_dirs"](None, base)
    except ValueError as error:
        caught = error
    if expected_refusal:
        assert caught is not None and "covers real user state" in str(caught)
        assert checked is None
    else:
        assert caught is None and checked == canonical and checked.is_absolute()
    assert not forbidden
    payload = {"mode": mode, "outcome": "refused" if expected_refusal else "admitted", "guard_matches_expected_outcome": True, "canonical_admission_or_refusal_verified": True, "stopped_before_producer_imports": True, "forbidden_attempts": forbidden}
finally:
    if alias.is_symlink():
        alias.unlink()
    if protected.is_symlink():
        protected.unlink()
    elif protected.exists():
        protected.rmdir()
    if parent.exists():
        parent.rmdir()
    if external.exists():
        external.rmdir()
    work.rmdir()
payload["owned_paths_retired"] = True
with output.open("x") as stream:
    json.dump(payload, stream)

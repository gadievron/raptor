from pathlib import Path
import ast, hashlib, json, os, sys
import pytest
root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in {"present", "empty", "absent", "override", "error", "interrupt"}
output = Path(sys.argv[3]).resolve()
assert not output.exists() and output.parent.is_dir()
assert sys.executable == "/home/raptor/raptor/out/codex-fleet/artifacts/root-release-environment-20261114/sdk/venv/bin/python"
pins = {'core/llm/tests/conftest.py': 'f6a3fd21e9fc63ba1a90c1271acddd79a750e410661e9cd2be515c2ff75dc1bc', '/home/raptor/raptor/out/codex-fleet/artifacts/root-release-environment-20261114/sdk/venv/lib/python3.14/site-packages/_pytest/monkeypatch.py': 'b5c405ed57dbd58adfb7f0fae44f84d62402993c50058e07f03387285c03df33'}
for name, digest in pins.items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
source = root / "core/llm/tests/conftest.py"
fn = next(n for n in ast.parse(source.read_bytes()).body if isinstance(n, ast.FunctionDef) and n.name == "_scrub_dispatcher_route")
fn.decorator_list = []
wrapper = next(n for n in ast.parse(source.read_bytes()).body if isinstance(n, ast.FunctionDef) and n.name == "monkeypatch")
wrapper.decorator_list = []
assert not any(isinstance(n, (ast.Import, ast.ImportFrom)) for node in (fn, wrapper) for n in ast.walk(node))
namespace = {"pytest": pytest}
exec(compile(ast.Module(body=[fn, wrapper], type_ignores=[]), str(source), "exec"), namespace)
forbidden = []
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.kill", "os.killpg"}:
        forbidden.append(event)
        raise AssertionError("forbidden action: " + event)
sys.addaudithook(audit)
name = "RAPTOR_LLM_SOCKET"
before = dict(os.environ)
caller = str(output.parent / "owned-caller-never-connected.sock")
body_value = str(output.parent / "owned-body-never-connected.sock")
assert not Path(caller).exists() and not Path(body_value).exists()
# The body stack deliberately exists before either source fixture is entered.
body = pytest.MonkeyPatch()
owner = body_scope = None
try:
    if mode in {"absent", "interrupt"}:
        os.environ.pop(name, None)
    elif mode == "empty":
        os.environ[name] = ""
    else:
        os.environ[name] = caller
    prepared = dict(os.environ)
    owner = namespace["_scrub_dispatcher_route"]()
    assert next(owner) is None and name not in os.environ
    body_scope = namespace["monkeypatch"](None, None, body)
    assert next(body_scope) is body
    if mode == "absent":
        os.environ[name] = body_value
        body.undo()
        assert os.environ[name] == body_value
    elif mode == "override":
        body.setenv(name, body_value)
        assert os.environ[name] == body_value
    else:
        if mode in {"error", "interrupt"}:
            body.setenv(name, body_value)
            assert os.environ[name] == body_value
        body.undo()
        assert name not in os.environ
    failure = RuntimeError("owned route body error") if mode == "error" else KeyboardInterrupt("owned route body interrupt") if mode == "interrupt" else None
    caught = None
    try:
        if failure is not None:
            raise failure
    except (RuntimeError, KeyboardInterrupt) as error:
        caught = error
    assert caught is failure
    try:
        next(body_scope)
    except StopIteration:
        pass
    else:
        raise AssertionError("body wrapper yielded twice")
    body_scope = None
    if mode == "absent":
        assert os.environ[name] == body_value
    else:
        assert name not in os.environ
    try:
        next(owner)
    except StopIteration:
        pass
    else:
        raise AssertionError("route owner yielded twice")
    owner = None
    assert dict(os.environ) == prepared
    body.undo()
    assert dict(os.environ) == prepared and not forbidden
    payload = {"mode": mode, "selected_body_route_preserved": True, "expected_body_outcome_preserved": True, "body_wrapper_drained_before_owner_exit": True, "initial_presence_and_value_restored_before_rescue": True, "late_body_undo_keeps_caller_environment": True, "native_fixture_strip_reached": True, "provider_or_socket_never_used": True, "forbidden_attempts": forbidden}
finally:
    if body_scope is not None:
        body_scope.close()
    body.undo()
    if owner is not None:
        owner.close()
    if name in before:
        os.environ[name] = before[name]
    else:
        os.environ.pop(name, None)
assert dict(os.environ) == before
payload["independent_environment_rescue_complete"] = True
with output.open("x") as stream:
    json.dump(payload, stream)

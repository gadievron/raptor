from pathlib import Path
import ast, builtins, hashlib, json, sys
from types import ModuleType
import pytest
root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in {"normal", "error", "interrupt", "override"}
output = Path(sys.argv[3]).resolve()
assert not output.exists() and output.parent.is_dir()
assert sys.executable == "/home/raptor/raptor/out/codex-fleet/artifacts/root-release-environment-20261114/sdk/venv/bin/python"
pins = {'core/llm/tests/conftest.py': '1e31165c508244cf386b44644001f135ab16d8a3feb2143c665fa76be0151e26', 'core/llm/client.py': '71b7de158b0b4d2952763935e539a487ced1578697315d8f27d499f1b0d72e1b', '/home/raptor/raptor/out/codex-fleet/artifacts/root-release-environment-20261114/sdk/venv/lib/python3.14/site-packages/_pytest/monkeypatch.py': 'b5c405ed57dbd58adfb7f0fae44f84d62402993c50058e07f03387285c03df33', 'core/llm/tests/test_scorecard_flush_aggregation.py': '55e4e03e7ed4e09af94f2bd626e8aa3cbcb03f1bdc8b6305c9fbb7fffc32284c'}
for name, digest in pins.items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
client_source = root / "core/llm/client.py"
client_tree = ast.parse(client_source.read_bytes())
client_class = next(n for n in client_tree.body if isinstance(n, ast.ClassDef) and n.name == "LLMClient")
assert not client_class.bases and not client_class.keywords and not client_class.decorator_list
for node in client_class.body:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        assert all(isinstance(value, ast.Constant) for value in node.args.defaults + [v for v in node.args.kw_defaults if v is not None])
        assert all(isinstance(d, ast.Name) and d.id in {"property", "staticmethod"} for d in node.decorator_list)
    elif isinstance(node, ast.Assign):
        assert isinstance(node.value, ast.Constant)
    elif isinstance(node, ast.AnnAssign):
        assert node.value is None or isinstance(node.value, ast.Constant)
    else:
        assert isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
client_namespace = {"__name__": "owned_source_client_declaration"}
exec(compile(ast.fix_missing_locations(ast.Module(body=[future, client_class], type_ignores=[])), str(client_source), "exec"), client_namespace)
client = ModuleType("owned_source_client")
client.LLMClient = client_namespace["LLMClient"]
original = client.LLMClient.flush_usage_to_scorecard
source = root / "core/llm/tests/conftest.py"
node = next(n for n in ast.parse(source.read_bytes()).body if isinstance(n, ast.FunctionDef) and n.name == "_isolate_scorecard")
node.decorator_list = []
wrapper = next(n for n in ast.parse(source.read_bytes()).body if isinstance(n, ast.FunctionDef) and n.name == "monkeypatch")
wrapper.decorator_list = []
imports = []
def importing(name, globals=None, locals=None, fromlist=(), level=0):
    assert name == "core.llm.client" and tuple(fromlist) == ("LLMClient",) and level == 0
    imports.append(name)
    return client
namespace = {"pytest": pytest, "__builtins__": dict(vars(builtins), __import__=importing)}
exec(compile(ast.Module(body=[node, wrapper], type_ignores=[]), str(source), "exec"), namespace)
forbidden = []
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.kill", "os.killpg"}:
        forbidden.append(event)
        raise AssertionError("forbidden action: " + event)
sys.addaudithook(audit)
aggregation_source = root / "core/llm/tests/test_scorecard_flush_aggregation.py"
aggregation_tree = ast.parse(aggregation_source.read_bytes())
aggregation = next(n for n in aggregation_tree.body if isinstance(n, ast.FunctionDef) and n.name == "_reset_registry")
aggregation.decorator_list = []
client._SCORECARD_FLUSH_CLIENTS = []
client._SCORECARD_ATEXIT_ARMED = False
registry_before = client._SCORECARD_FLUSH_CLIENTS
armed_before = client._SCORECARD_ATEXIT_ARMED
aggregation_namespace = {"client_mod": client, "LLMClient": client.LLMClient, "_REAL_FLUSH": original}
exec(compile(ast.Module(body=[aggregation], type_ignores=[]), str(aggregation_source), "exec"), aggregation_namespace)
# Acquire the body stack first to exercise explicit owner ordering.
body = pytest.MonkeyPatch()
fixture = body_scope = None
try:
    fixture = namespace["_isolate_scorecard"]()
    assert next(fixture) is None
    guard = client.LLMClient.flush_usage_to_scorecard
    assert guard is not original and imports == ["core.llm.client"]
    body_scope = namespace["monkeypatch"](None, body)
    assert next(body_scope) is body
    if mode == "override":
        aggregation_namespace["_reset_registry"](body)
        assert client.LLMClient.flush_usage_to_scorecard is original
        assert client._SCORECARD_FLUSH_CLIENTS is not registry_before
        assert client._SCORECARD_ATEXIT_ARMED is True
    else:
        body.undo()
        assert client.LLMClient.flush_usage_to_scorecard is guard
    failure = RuntimeError("owned fixture body error") if mode == "error" else KeyboardInterrupt("owned fixture body interrupt") if mode == "interrupt" else None
    caught = None
    try:
        if failure is not None:
            raise failure
    except (RuntimeError, KeyboardInterrupt) as error:
        caught = error
    assert caught is failure
    assert client.LLMClient.flush_usage_to_scorecard is (original if mode == "override" else guard)
    # Run the exact wrapper teardown before the exact private owner teardown.
    try:
        next(body_scope)
    except StopIteration:
        pass
    else:
        raise AssertionError("body wrapper yielded twice")
    body_scope = None
    survived = client.LLMClient.flush_usage_to_scorecard is guard
    assert survived
    assert client._SCORECARD_FLUSH_CLIENTS is registry_before and client._SCORECARD_ATEXIT_ARMED is armed_before
    try:
        next(fixture)
    except StopIteration:
        pass
    else:
        raise AssertionError("fixture yielded twice")
    fixture = None
    assert client.LLMClient.flush_usage_to_scorecard is original
    body.undo()
    assert client.LLMClient.flush_usage_to_scorecard is original
    assert not forbidden
    payload = {"mode": mode, "guard_survives_body_undo": survived, "expected_body_outcome_preserved": True, "deliberate_body_override_supported": True, "body_wrapper_drained_before_owner_exit": True, "late_body_undo_keeps_original": True, "guard_original_restored_before_rescue": True, "borrowed_registry_identity_preserved": True, "actual_source_class_declaration": True, "client_constructor_or_method_never_called": True, "forbidden_attempts": forbidden}
finally:
    if body_scope is not None:
        body_scope.close()
    body.undo()
    if fixture is not None:
        fixture.close()
    client.LLMClient.flush_usage_to_scorecard = original
    client._SCORECARD_FLUSH_CLIENTS = registry_before
    client._SCORECARD_ATEXIT_ARMED = armed_before
assert client.LLMClient.flush_usage_to_scorecard is original
payload["independent_class_binding_rescue_complete"] = True
with output.open("x") as stream:
    json.dump(payload, stream)

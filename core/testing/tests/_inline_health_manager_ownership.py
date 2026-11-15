from pathlib import Path
import ast, hashlib, json, logging, sys
from contextlib import ExitStack, contextmanager
from types import ModuleType, SimpleNamespace
root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in {"success", "error", "success_disabled", "error_disabled"}
output = Path(sys.argv[3]).resolve()
assert not output.exists() and output.parent.is_dir()
assert sys.executable == "/home/raptor/raptor/out/codex-fleet/artifacts/root-release-environment-20261114/sdk/venv/bin/python"
assert Path(logging.__file__).resolve() == Path("/usr/lib/python3.14/logging/__init__.py")
pins = {'core/testing/tests/test_inline_log_ownership.py': '26614026a92d945da4d2fc5a74ef994237ec1237723b114ae2c9e857bd295938', 'core/testing/logging_state.py': '8dace79f2da1419dcc4afa1f9a710931238821c5620b71f5d98fe851cd0d351a', 'core/logging/__init__.py': 'f5ce44b7751975e88f878142472e64eacbfb76f6b3da21c7d16d04cd232ce8a3', '/usr/lib/python3.14/logging/__init__.py': '60682a2e00512c56fe9de436034fbe7a882891964145a8e0b438bb2e6b55cd98'}
for name, digest in pins.items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
source = root / "core/testing/tests/test_inline_log_ownership.py"
tree = ast.parse(source.read_bytes())
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "test_health_offline_cli_restores_logging")
first = fn.body[0]
assert isinstance(first, ast.Assign) and len(first.targets) == 1 and isinstance(first.targets[0], ast.Name) and first.targets[0].id == "module"
assert isinstance(first.value, ast.Call) and isinstance(first.value.func, ast.Name) and first.value.func.id == "import_module" and ast.literal_eval(first.value.args[0]) == "packages.sca.tests.test_health"
end = next(i for i, n in enumerate(fn.body) if isinstance(n, ast.FunctionDef) and n.name == "configure")
prefix = fn.body[1:end+1]
assert not any(isinstance(n, (ast.Import, ast.ImportFrom)) for node in prefix for n in ast.walk(node))
assert not any(isinstance(n, ast.Name) and n.id == "module" for node in prefix for n in ast.walk(node))
cleanup_try = fn.body[-1]
assert isinstance(cleanup_try, ast.Try) and cleanup_try.finalbody
helper_source = root / "core/testing/logging_state.py"
helper_tree = ast.parse(helper_source.read_bytes())
producer = ast.parse((root / "core/logging/__init__.py").read_bytes())
constant = next(n for n in producer.body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == "NOISY_THIRD_PARTY_LOGGERS")
helper = ModuleType("owned_inline_logging_state")
vars(helper).update({"logging": logging, "NOISY_THIRD_PARTY_LOGGERS": ast.literal_eval(constant.value), "ExitStack": ExitStack, "contextmanager": contextmanager})
exec(compile(ast.Module(body=[n for n in helper_tree.body if isinstance(n, ast.FunctionDef)], type_ignores=[]), str(helper_source), "exec"), vars(helper))
# Only this return is carrier code; all preceding statements are the exact native prefix.
expose = ast.parse("return SimpleNamespace(root=root, sdk=sdk, borrowed=borrowed, created=created, configure=configure, original_list=original_list, proxy=proxy)").body[0]
fn.body = prefix + [expose]
fn.decorator_list = []
namespace = {"logging": logging, "logging_state": helper, "SimpleNamespace": SimpleNamespace}
exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), str(source), "exec"), namespace)
# Run the original native finally statements using the actual owned locals.
cleanup = ast.FunctionDef(name="source_cleanup", args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=n) for n in ("root", "created", "borrowed")], kwonlyargs=[], kw_defaults=[], defaults=[]), body=cleanup_try.finalbody, decorator_list=[])
exec(compile(ast.fix_missing_locations(ast.Module(body=[cleanup], type_ignores=[])), str(source), "exec"), namespace)
forbidden = []
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.kill", "os.killpg"}:
        forbidden.append(event)
        raise AssertionError("forbidden action: " + event)
sys.addaudithook(audit)
manager = logging.Logger.manager
disable_before = manager.disable
registry = dict(manager.loggerDict)
existing = [logging.root] + [item for item in registry.values() if isinstance(item, logging.Logger)]
snapshots = [(logger, logger._cache, dict(logger._cache)) for logger in existing]
threshold = logging.CRITICAL if mode.endswith("_disabled") else 0
logging.disable(threshold)
caller_name = "ownedinlinecallercachesentinel"
assert caller_name not in registry
caller = manager.getLogger(caller_name)
caller.isEnabledFor(logging.DEBUG)
caller.isEnabledFor(logging.WARNING)
cache = caller._cache
before = dict(cache)
assert set(before) == {logging.DEBUG, logging.WARNING}
work = output.parent / "owned-source-root"
work.mkdir(mode=0o700)
state = None
try:
    state = namespace[fn.name](mode.startswith("error"), work, None)
    owned = [state.root, *state.sdk.values()]
    shapes = [(item, item.name, item.parent, item.propagate) for item in owned]
    own_manager = state.root.manager
    assert own_manager is not manager and own_manager.root is state.root and own_manager.disable == threshold
    assert all(item.parent is None and item.manager is own_manager for item in owned)
    assert all(own_manager.loggerDict[item.name] is item for item in state.sdk.values())
    assert caller._cache is cache and cache == before
    state.root.isEnabledFor(logging.DEBUG)
    private_cache = state.root._cache
    assert private_cache[logging.DEBUG] is (threshold < logging.DEBUG)
    helper.logging = state.proxy
    try:
        with helper.isolated_cli_logging():
            caught = None
            try:
                state.configure(0)
            except RuntimeError as error:
                caught = error
            assert (caught is not None) == (mode.startswith("error"))
            if caught is not None:
                assert str(caught) == "owned CLI setup failed"
            preserved = caller._cache is cache and cache == before
            invalidated = all(not item._cache for item in owned)
            assert preserved and invalidated and state.root.level == logging.CRITICAL
            assert all(item.level == logging.INFO for item in state.sdk.values())
            assert len(state.created) == 1 and not state.created[0][1].closed
    finally:
        helper.logging = logging
    assert state.root.handlers is state.original_list and state.root.handlers == [state.borrowed]
    assert state.root.level == logging.DEBUG and all(item.level == logging.ERROR for item in state.sdk.values())
    filtering = state.root.isEnabledFor(logging.DEBUG) is (threshold < logging.DEBUG)
    assert filtering and caller._cache is cache and cache == before
    assert all((item.name, item.parent, item.propagate) == (name, parent, propagate) for item, name, parent, propagate in shapes)
    assert all(handler._closed and stream.closed for handler, stream in state.created)
    assert not state.borrowed._closed
    namespace["source_cleanup"](state.root, state.created, state.borrowed)
    assert state.borrowed._closed
    payload = {"mode": mode, "borrowed_cache_preserved_before_restoration": preserved, "private_caches_invalidated": invalidated, "disable_filtering_preserved": filtering, "original_levels_and_shapes_restored": True, "owned_stream_closed_by_source_helper": True, "original_source_cleanup_completed": True, "forbidden_attempts": forbidden}
finally:
    helper.logging = logging
    if state is not None:
        for handler, stream in state.created:
            state.root.removeHandler(handler)
            handler.close()
            stream.close()
        state.borrowed.close()
    assert manager.disable == threshold
    manager.disable = disable_before
    for logger, original, contents in snapshots:
        assert logger._cache is original
        original.clear()
        original.update(contents)
    assert manager.loggerDict.get(caller_name) is caller
    del manager.loggerDict[caller_name]
    assert manager.loggerDict.keys() == registry.keys() and all(manager.loggerDict[name] is value for name, value in registry.items())
    for file in work.iterdir():
        assert file.name == "owned-cli.log" and file.is_file()
        file.unlink()
    work.rmdir()
payload["independent_identity_preserving_rescue_complete"] = True
with output.open("x") as stream:
    json.dump(payload, stream)

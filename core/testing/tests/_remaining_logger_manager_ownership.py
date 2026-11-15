from pathlib import Path
import ast, hashlib, json, logging, sys
from contextlib import ExitStack, contextmanager
from types import ModuleType, SimpleNamespace
import pytest
root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in {"root", "named", "child", "root_disabled"}
output = Path(sys.argv[3]).resolve()
assert not output.exists() and output.parent.is_dir()
assert sys.executable == "/home/raptor/raptor/out/codex-fleet/artifacts/root-release-environment-20261114/sdk/venv/bin/python"
assert Path(logging.__file__).resolve() == Path("/usr/lib/python3.14/logging/__init__.py")
pins = {'core/testing/tests/test_remaining_log_owners.py': 'd359e9b1c36656eced9814078e6cab91e0736854b8669d6b7244035a41d1c730', 'core/testing/logging_state.py': '8dace79f2da1419dcc4afa1f9a710931238821c5620b71f5d98fe851cd0d351a', 'core/logging/__init__.py': 'f5ce44b7751975e88f878142472e64eacbfb76f6b3da21c7d16d04cd232ce8a3', '/usr/lib/python3.14/logging/__init__.py': '60682a2e00512c56fe9de436034fbe7a882891964145a8e0b438bb2e6b55cd98'}
for name, digest in pins.items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
source = root / "core/testing/tests/test_remaining_log_owners.py"
tree = ast.parse(source.read_bytes())
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "private_logs")
node.decorator_list = []
helper_source = root / "core/testing/logging_state.py"
helper_tree = ast.parse(helper_source.read_bytes())
producer = ast.parse((root / "core/logging/__init__.py").read_bytes())
constant = next(n for n in producer.body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == "NOISY_THIRD_PARTY_LOGGERS")
helper = ModuleType("owned_logging_state")
vars(helper).update({"__file__": str(helper_source), "logging": logging, "NOISY_THIRD_PARTY_LOGGERS": ast.literal_eval(constant.value), "ExitStack": ExitStack, "contextmanager": contextmanager})
functions = [n for n in helper_tree.body if isinstance(n, ast.FunctionDef)]
exec(compile(ast.Module(body=functions, type_ignores=[]), str(helper_source), "exec"), vars(helper))
namespace = {"logging": logging, "logging_state": helper, "pytest": pytest, "ExitStack": ExitStack, "SimpleNamespace": SimpleNamespace, "io": __import__("io")}
exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
forbidden = []
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.kill", "os.killpg"}:
        forbidden.append(event)
        raise AssertionError("forbidden action: " + event)
sys.addaudithook(audit)
manager = logging.Logger.manager
caller_name = "owned-caller-cache-sentinel"
assert caller_name not in manager.loggerDict
registry_before = dict(manager.loggerDict)
existing = [logging.root] + [item for item in registry_before.values() if isinstance(item, logging.Logger)]
rescue_caches = [(logger, logger._cache, dict(logger._cache)) for logger in existing]
disable_before = manager.disable
threshold = logging.CRITICAL if mode == "root_disabled" else 0
logging.disable(threshold)
caller = manager.getLogger(caller_name)
caller.isEnabledFor(logging.DEBUG)
caller.isEnabledFor(logging.WARNING)
cache = caller._cache
before = dict(cache)
assert set(before) == {logging.DEBUG, logging.WARNING}
registry = dict(manager.loggerDict)
work = output.parent / "fixture-root"
work.mkdir(mode=0o700)
generator = None
try:
    with pytest.MonkeyPatch.context() as patch:
        generator = namespace["private_logs"](patch, work)
        state = next(generator)
        assert caller._cache is cache and cache == before
        owned = [state.root, *state.loggers.values()]
        shapes = [(item, item.name, item.parent, item.propagate) for item in owned]
        assert state.loggers["core.sandbox.proxy"].parent is state.loggers["core.sandbox"]
        assert state.loggers["jailfix_guard_walk_test.child"].parent is state.loggers["jailfix_guard_walk_test"]
        assert state.loggers["jailfix_guard_walk_test.child"].propagate is False
        own_manager = state.root.manager
        assert own_manager is not manager and own_manager.root is state.root
        assert all(item.manager is own_manager for item in owned)
        assert own_manager.disable == threshold
        handler = logging.NullHandler()
        state.instrument(handler)
        with helper.isolated_cli_logging(logger_names=tuple(state.loggers)):
            state.root.addHandler(handler)
            for item in owned:
                item.isEnabledFor(logging.DEBUG)
                assert logging.DEBUG in item._cache
            target = state.root if mode.startswith("root") else state.loggers["core.sandbox"] if mode == "named" else state.loggers["jailfix_guard_walk_test.child"]
            target.setLevel(logging.DEBUG)
            invalidated = all(not item._cache for item in owned)
            assert invalidated
            filtering = target.isEnabledFor(logging.DEBUG) is (threshold < logging.DEBUG)
            assert filtering
            assert caller._cache is cache and cache == before
        assert caller._cache is cache and cache == before
        state.verify()
        assert all((item.name, item.parent, item.propagate) == (name, parent, propagate) for item, name, parent, propagate in shapes)
        assert all(item.level == logging.ERROR for item in owned)
        closed = all(stream.closed for _, stream in state.created)
        assert closed
        generator.close()
        generator = None
    assert helper.logging is logging
    assert logging.Logger.manager is manager and manager.disable == threshold
    assert caller._cache is cache and cache == before
    assert manager.loggerDict.keys() == registry.keys()
    assert all(manager.loggerDict[name] is value for name, value in registry.items())
    payload = {"mode": mode, "borrowed_cache_preserved_before_rescue": True, "borrowed_cache_object_same": True, "private_caches_invalidated": invalidated, "disable_filtering_preserved": filtering, "private_shapes_preserved": True, "owned_streams_closed_by_source": closed, "owned_helper_restored": True, "forbidden_attempts": forbidden}
finally:
    if generator is not None:
        generator.close()
    manager.disable = disable_before
    for logger, original, contents in rescue_caches:
        assert logger._cache is original
        original.clear()
        original.update(contents)
    assert manager.loggerDict.get(caller_name) is caller
    del manager.loggerDict[caller_name]
    assert manager.loggerDict.keys() == registry_before.keys()
    assert all(manager.loggerDict[name] is value for name, value in registry_before.items())
    for file in work.iterdir():
        assert file.name == "owned-0.log" and file.is_file()
        file.unlink()
    work.rmdir()
payload["independent_identity_preserving_rescue_complete"] = True
with output.open("x") as stream:
    json.dump(payload, stream)

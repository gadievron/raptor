"""Shared guards preserve real caller state, including held evidence files."""

import ast
import builtins
from contextlib import ExitStack, contextmanager
from functools import lru_cache
import itertools
import logging
import os
from pathlib import Path
import socket
import tempfile
from types import ModuleType

import pytest

from core.run import pin
from core.sandbox import evidence, state, summary
from core.testing.sandbox_state_scope import SUMMARY_DEFAULTS, SUMMARY_REGISTRIES

ROOT = Path(__file__).resolve().parents[3]
ROOT_FIXTURES = "conftest.py"
SANDBOX_FIXTURES = "core/sandbox/tests/conftest.py"
PIN_FIELDS = ("_frozen_pins", "_process_project", "_process_project_set",
              "_process_project_threaded")
CLI_FIELDS = ("_cli_sandbox_disabled", "_cli_sandbox_profile",
              "_cli_sandbox_disable_consent")


def _node(path, name):
    tree = ast.parse((ROOT / path).read_text())
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


@lru_cache(maxsize=None)
def _fixture_code(path, name, inject_error):
    # Source is immutable within a test run. Cache code, not function globals.
    node = _node(path, name)
    node.decorator_list = []
    if inject_error:
        class Fault(ast.NodeTransformer):
            def visit_Assign(self, item):
                if any(isinstance(n, ast.Name) and n.id == "_HERMETIC_OLLAMA_HOST" for n in item.targets) and isinstance(item.value, ast.JoinedStr):
                    return [item, ast.Raise(exc=ast.Call(func=ast.Name(id="PublicationError", ctx=ast.Load()), args=[], keywords=[]), cause=None)]
                return item
        node = Fault().visit(node)
    return compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(ROOT / path), "exec")


def _function(path, name, *, imports=None, publication_error=None):
    namespace = dict(pytest=pytest, os=os, Path=Path, _tempfile=tempfile,
                     _SESSIONS_DIR_SEQ=itertools.count(), socket=socket)
    if imports:
        real_import = builtins.__import__
        def import_owned(name, *args, **kwargs):
            return imports[name] if name in imports else real_import(name, *args, **kwargs)
        namespace["__builtins__"] = {**vars(builtins), "__import__": import_owned}
    if publication_error is not None:
        namespace["PublicationError"] = publication_error
    exec(_fixture_code(path, name, publication_error is not None), namespace)
    return namespace[name], namespace


def _state_names():
    node = _node(SANDBOX_FIXTURES, "_sandbox_state_guard")
    assignment = next(n for n in ast.walk(node) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "state_names" for t in n.targets))
    return ast.literal_eval(assignment.value)


STATE_FIELDS = (*_state_names(), "_speculative_failure_cache", "_unshare_engage_cache")
SUMMARY_FIELDS = (*SUMMARY_DEFAULTS, *SUMMARY_REGISTRIES, "_evidence")
FIELDS = [("state", name) for name in STATE_FIELDS] + [("summary", name) for name in SUMMARY_FIELDS]


def _finish(generator, mode):
    if mode == "normal":
        with pytest.raises(StopIteration):
            next(generator)
    elif mode == "close":
        generator.close()
    else:
        error = RuntimeError if mode == "error" else KeyboardInterrupt
        with pytest.raises(error):
            generator.throw(error)


@contextmanager
def _sandbox_guard():
    function, _ = _function(SANDBOX_FIXTURES, "_sandbox_state_guard")
    # Execute the shipped dependency order, including the original fixture's
    # dependency on monkeypatch when checking the unpatched baseline.
    with ExitStack() as cleanup:
        if "monkeypatch" in function.__code__.co_varnames[:function.__code__.co_argcount]:
            patch = cleanup.enter_context(pytest.MonkeyPatch.context())
            generator = function(patch)
            cleanup.callback(generator.close)
            next(generator)
        else:
            generator = function(None)
            cleanup.callback(generator.close)
            next(generator)
            wrapper, _ = _function(SANDBOX_FIXTURES, "monkeypatch")
            body = wrapper(None)
            cleanup.callback(body.close)
            patch = next(body)
        yield patch


def _replacement(value, name, path, handles):
    if name == "_evidence_handle":
        handle = summary._evidence.EvidenceFile.open(path, "extra.jsonl")
        handles.append(handle)
        return handle
    if isinstance(value, ModuleType):
        view = ModuleType(value.__name__)
        vars(view).update(vars(value))
        return view
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if isinstance(value, Path):
        return path
    if isinstance(value, str):
        return str(path)
    if isinstance(value, list):
        return [str(path)]
    if isinstance(value, dict) or name == "_user_limits_cache":
        if name == "_speculative_failure_cache":
            return {str(path): True}
        if name == "_unshare_engage_cache":
            return {("--user",): (False, "owned")}
        if name == "_user_limits_cache":
            return {"nofile": 128}
        if name == "_cli_disables":
            return {str(path): "owned"}
        if name == "_floor_refusals":
            return {str(path): []}
        if name in SUMMARY_REGISTRIES[2:]:
            return {str(path): {}}
        return {str(path): True}
    if name in ("_cli_sandbox_readable_paths", "_cli_sandbox_tool_paths"):
        return [str(path)]
    if name.endswith("_path_cache") or name == "_cli_sandbox_disable_consent":
        return str(path)
    if name == "_cli_sandbox_profile":
        return "default"
    if name == "_libseccomp_cache":
        return value  # Keep opaque native-library handles intact.
    return False


def _contents(value):
    return value.copy() if isinstance(value, (dict, list, set)) else None


@pytest.mark.parametrize("owner_name,name", FIELDS, ids=[owner + "." + name for owner, name in FIELDS])
@pytest.mark.parametrize("mode", ["normal", "error", "interrupt", "publication_error"])
def test_sandbox_guard_restores_every_borrowed_binding(owner_name, name, mode, tmp_path, monkeypatch):
    borrowed_run, owned_run = tmp_path / "borrowed", tmp_path / "owned"
    borrowed_run.mkdir()
    owned_run.mkdir()
    borrowed = evidence.EvidenceFile.open(borrowed_run, "borrowed.jsonl")
    handles = []
    try:
        monkeypatch.setattr(summary, "_active_run_dir", borrowed_run)
        monkeypatch.setattr(summary, "_active_run_generation", 41)
        monkeypatch.setattr(summary, "_denial_count", 17)
        monkeypatch.setattr(summary, "_evidence_handle", borrowed)
        owners = {"state": state, "summary": summary}
        before = {(owner, field): getattr(owners[owner], field) for owner, field in FIELDS}
        contents = {key: _contents(value) for key, value in before.items()}
        class PublicationError(Exception):
            pass
        actual = pytest.MonkeyPatch.setattr
        armed = mode == "publication_error"
        def publish(patch, obj, field, value, *args, **kwargs):
            nonlocal armed
            actual(patch, obj, field, value, *args, **kwargs)
            if armed and obj is owners[owner_name] and field == name:
                armed = False
                raise PublicationError
        with pytest.MonkeyPatch.context() as injection:
            injection.setattr(pytest.MonkeyPatch, "setattr", publish)
            try:
                with _sandbox_guard() as body:
                    if mode != "publication_error":
                        summary.set_active_run_dir(owned_run)
                        summary.record_denial("owned command", 1, "network", host="example.test")
                        handles.append(summary._evidence_handle)
                        owner = owners[owner_name]
                        setattr(owner, name, _replacement(getattr(owner, name), name, owned_run, handles))
                        # A direct write followed by a body override exposes
                        # restoration in the wrong fixture dependency order.
                        body.setattr(owner, name, before[(owner_name, name)])
                        if mode in ("error", "interrupt"):
                            raise RuntimeError if mode == "error" else KeyboardInterrupt
            except (PublicationError, RuntimeError, KeyboardInterrupt):
                pass
        for (owner, field), value in before.items():
            assert getattr(owners[owner], field) is value, (owner, field)
            assert _contents(value) == contents[(owner, field)], (owner, field)
        assert not borrowed._closed
        os.fstat(borrowed.fd)
        assert all(handle._closed for handle in handles)
    finally:
        for handle in handles:
            evidence.EvidenceFile.close(handle)
        evidence.EvidenceFile.close(borrowed)


@pytest.mark.parametrize("mode", ["normal", "error", "interrupt", "publication_error"])
@pytest.mark.parametrize("owner_name,name", [("pin", n) for n in PIN_FIELDS] + [("state", n) for n in CLI_FIELDS])
def test_process_pin_guard_preserves_caller_values(owner_name, name, mode, tmp_path, monkeypatch):
    borrowed = pin.RunPin(None, "argv", tmp_path, True, True)
    monkeypatch.setattr(pin, "_frozen_pins", {str(tmp_path): borrowed})
    monkeypatch.setattr(pin, "_process_project", "-")
    monkeypatch.setattr(pin, "_process_project_set", True)
    monkeypatch.setattr(pin, "_process_project_threaded", True)
    owners = {"pin": pin, "state": state}
    fields = [("pin", n) for n in PIN_FIELDS] + [("state", n) for n in CLI_FIELDS]
    before = {(owner, field): getattr(owners[owner], field) for owner, field in fields}
    frozen = pin._frozen_pins.copy()
    class PublicationError(Exception):
        pass
    actual = pytest.MonkeyPatch.setattr
    armed = mode == "publication_error"
    def publish(patch, obj, field, value, *args, **kwargs):
        nonlocal armed
        actual(patch, obj, field, value, *args, **kwargs)
        if armed and obj is owners[owner_name] and field == name:
            armed = False
            raise PublicationError
    try:
        function, _ = _function(ROOT_FIXTURES, "_process_pin_state")
    except StopIteration:
        function, _ = _function(ROOT_FIXTURES, "_sessions_registry_in_tmp")
    with pytest.MonkeyPatch.context() as body, pytest.MonkeyPatch.context() as injection:
        injection.setattr(pytest.MonkeyPatch, "setattr", publish)
        generator = None
        try:
            if "monkeypatch" in function.__code__.co_varnames[:function.__code__.co_argcount]:
                function(body)
            else:
                # The outer pytest registry owner is already active here.
                arguments = (None,) if "_registry_paths" in function.__code__.co_varnames[:function.__code__.co_argcount] else ()
                generator = function(*arguments)
                next(generator)
            if mode in ("error", "interrupt"):
                raise RuntimeError if mode == "error" else KeyboardInterrupt
        except (PublicationError, RuntimeError, KeyboardInterrupt):
            pass
        finally:
            if generator is not None:
                generator.close()
    for (owner, field), value in before.items():
        assert getattr(owners[owner], field) is value, (owner, field)
    assert pin._frozen_pins == frozen


@pytest.mark.parametrize("initial", [False, True])
@pytest.mark.parametrize("mode", ["normal", "close", "error", "interrupt", "publication_error"])
def test_root_logger_fixture_restores_real_logger(initial, mode, monkeypatch):
    logger = logging.Logger("owned.fixture.logger")
    logger.propagate = initial
    view = ModuleType("logging")
    vars(view).update(vars(logging))
    view.getLogger = lambda name: logger
    function, _ = _function(ROOT_FIXTURES, "_raptor_logger_propagates", imports={"logging": view})
    class PublicationError(Exception):
        pass
    actual = pytest.MonkeyPatch.setattr
    armed = mode == "publication_error"
    def publish(patch, obj, name, value, *args, **kwargs):
        nonlocal armed
        actual(patch, obj, name, value, *args, **kwargs)
        if armed and obj is logger and name == "propagate":
            armed = False
            raise PublicationError
    monkeypatch.setattr(pytest.MonkeyPatch, "setattr", publish)
    generator = function()
    try:
        try:
            next(generator)
        except PublicationError:
            pass
        else:
            _finish(generator, "close" if mode == "publication_error" else mode)
    finally:
        generator.close()
    assert logger.propagate is initial


@pytest.mark.parametrize("initial", [None, "", "borrowed-cache"])
@pytest.mark.parametrize("mode", ["normal", "close", "error", "interrupt", "publication_error"])
def test_binary_cache_fixture_preserves_absent_empty_and_present(initial, mode, tmp_path_factory, monkeypatch):
    key = "RAPTOR_BINARY_CACHE_DIR"
    if initial is None:
        monkeypatch.delenv(key, raising=False)
    else:
        monkeypatch.setenv(key, initial)
    function, _ = _function(ROOT_FIXTURES, "_binary_cache_in_tmp")
    class PublicationError(Exception):
        pass
    actual = type(os.environ).__setitem__
    armed = mode == "publication_error"
    def publish(env, name, value):
        nonlocal armed
        actual(env, name, value)
        if armed and name == key:
            armed = False
            raise PublicationError
    monkeypatch.setattr(type(os.environ), "__setitem__", publish)
    generator = function(tmp_path_factory)
    try:
        try:
            next(generator)
        except PublicationError:
            pass
        else:
            _finish(generator, "close" if mode == "publication_error" else mode)
    finally:
        generator.close()
    assert os.environ.get(key) == initial
    assert (key in os.environ) is (initial is not None)


@pytest.mark.parametrize("mode", ["normal", "close", "error", "interrupt", "publication_error"])
def test_reserved_endpoint_restores_borrowed_marker(mode):
    class PublicationError(Exception):
        pass
    function, namespace = _function(
        "core/audit/tests/test_resume_e2e.py", "_reserve_unavailable_ollama",
        publication_error=PublicationError if mode == "publication_error" else None)
    namespace["_HERMETIC_OLLAMA_HOST"] = "http://127.0.0.1:4321"
    generator = function()
    try:
        try:
            next(generator)
        except PublicationError:
            pass
        else:
            _finish(generator, mode)
    finally:
        generator.close()
    assert namespace["_HERMETIC_OLLAMA_HOST"] == "http://127.0.0.1:4321"


@pytest.mark.parametrize("guard", ["root", "sandbox", "validation"])
def test_real_pytest_teardown_preserves_configure_time_callers(guard, tmp_path, monkeypatch):
    import json
    import subprocess
    import sys

    job = tmp_path / "child"
    job.mkdir()
    sources = [("root_source", ROOT / "conftest.py")]
    if guard != "root":
        path = SANDBOX_FIXTURES if guard == "sandbox" else "packages/exploitability_validation/tests/conftest.py"
        sources.append(("directory_source", ROOT / path))
    for name, path in sources:
        (job / (name + ".py")).write_text(
            "from pathlib import Path\n__file__ = " + repr(str(path))
            + "\nexec(compile(Path(__file__).read_text(), __file__, 'exec'), globals())\n")
    report = job / "restoration.json"
    seed = '''import json
import logging
import os
from pathlib import Path
import pytest
from core.run import pin
from core.sandbox import evidence, state, summary
JOB = Path(JOB_VALUE)
REPORT = Path(REPORT_VALUE)
SANDBOX = SANDBOX_VALUE
OWNED = []

@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    global FROZEN, PIN, HANDLE, RUN
    RUN = JOB / 'borrowed'
    RUN.mkdir()
    HANDLE = evidence.EvidenceFile.open(RUN, 'borrowed.jsonl')
    PIN = pin.RunPin(None, 'argv', RUN, True, True)
    FROZEN = {str(RUN): PIN}
    pin._frozen_pins = FROZEN
    pin.set_process_project('-', threaded=True)
    summary._active_run_dir = RUN
    summary._active_run_generation = 41
    summary._denial_count = 17
    summary._evidence_handle = HANDLE
    os.environ['RAPTOR_BINARY_CACHE_DIR'] = ''
    logging.getLogger('raptor').propagate = True

@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    result = {
        'frozen_identity': pin._frozen_pins is FROZEN,
        'frozen_contents': pin._frozen_pins == {str(RUN): PIN},
        'process_project': pin.get_process_project() == '-',
        'threaded': pin._process_project_threaded is True,
        'handle_identity': summary._evidence_handle is HANDLE,
        'borrowed_handle_open': not HANDLE._closed,
        'active_run': summary._active_run_dir == RUN,
        'generation': summary._active_run_generation == 41,
        'counter': summary._denial_count == 17,
        'empty_cache_env': 'RAPTOR_BINARY_CACHE_DIR' in os.environ and os.environ['RAPTOR_BINARY_CACHE_DIR'] == '',
        'propagation': logging.getLogger('raptor').propagate is True,
        'owned_evidence_closed': all(handle._closed for handle in OWNED),
    }
    try:
        REPORT.write_text(json.dumps(result))
    finally:
        for handle in OWNED:
            evidence.EvidenceFile.close(handle)
        evidence.EvidenceFile.close(HANDLE)
'''
    seed = seed.replace("JOB_VALUE", repr(str(job))).replace("REPORT_VALUE", repr(str(report))).replace("SANDBOX_VALUE", repr(guard == "sandbox"))
    (job / "caller_seed.py").write_text(seed)
    (job / "test_lifetime.py").write_text('''from pathlib import Path
import caller_seed
from core.run import pin
from core.sandbox import state, summary


def test_defaults_survive_body_undo(monkeypatch, tmp_path):
    assert pin._frozen_pins == {}
    assert pin.get_process_project() is None
    assert pin._process_project_threaded is False
    assert state._cli_sandbox_disabled is False
    assert state._cli_sandbox_profile is None
    monkeypatch.setattr(pin, '_process_project', 'owned')
    monkeypatch.undo()
    assert pin.get_process_project() is None
    if caller_seed.SANDBOX:
        assert summary._evidence_handle is None
        assert summary._active_run_dir is None
        target = tmp_path / 'owned'
        target.mkdir()
        summary.set_active_run_dir(target)
        summary.record_denial('owned command', 1, 'network', host='example.test')
        caller_seed.OWNED.append(summary._evidence_handle)
        # Lose the current binding deliberately. Construction tracking must
        # still close this real descriptor before restoring the caller.
        summary._evidence_handle = None


def test_next_scope_is_private():
    assert pin._frozen_pins == {}
    assert pin.get_process_project() is None
    assert all(handle._closed for handle in caller_seed.OWNED)
''')
    env = dict(os.environ)
    env.pop("RAPTOR_RANDOMISE_TESTS", None)
    env.pop("RAPTOR_TEST_LIVE_LLM", None)
    for key, leaf in (("HOME", "home"), ("TMPDIR", "tmp"), ("XDG_DATA_HOME", "data"),
                      ("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"),
                      ("RAPTOR_OUT_DIR", "out")):
        directory = job / leaf
        directory.mkdir()
        env[key] = str(directory)
    env["PYTHONPATH"] = str(job) + os.pathsep + str(ROOT)
    args = [sys.executable, "-m", "pytest", "--noconftest", "-c", str(ROOT / "pytest.ini"),
            "-p", "core.testing.llm_tripwire"]
    for name, _ in sources:
        args += ["-p", name]
    args += ["-p", "caller_seed", str(job / "test_lifetime.py"), "-q", "-m", "", "--tb=short"]
    result = subprocess.run(args, cwd=job, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    restored = json.loads(report.read_text())
    assert all(restored.values()), restored

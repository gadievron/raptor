"""Run native security fixtures while observing shared modules and borrowed views."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

_REPO = Path(__file__).resolve().parents[3]
_FILES = ['core/security/tests/test_capped_read.py', 'core/security/tests/test_mac_key.py', 'core/security/tests/test_cc_trust_self_worktree.py', 'core/security/tests/test_codeql_trust_self_worktree.py', 'core/security/tests/test_launch_scratch.py', 'core/analysis/tests/test_reach_cache.py', 'core/security/tests/test_python_imports.py', 'core/security/tests/test_rule_of_two.py', 'core/security/tests/test_scratch_supervisor.py', 'core/analysis/tests/test_reach_cache_streaming.py']
_EXIT_FILES = [file for file in _FILES if Path(file).stem in {
    "test_capped_read", "test_mac_key", "test_codeql_trust_self_worktree"}]
_CASES = [(file, borrowed, "normal") for file in _FILES for borrowed in (False, True)]
_CASES += [(file, borrowed, outcome) for file in _EXIT_FILES
           for borrowed in (False, True) for outcome in ("error", "interrupt")]
pytestmark = pytest.mark.slow

_PLUGIN = r'''
import importlib
import json
import os
from pathlib import Path
import time
from types import ModuleType

import pytest

_BINDINGS = [
    ("core.security.capped_read", "os"),
    ("core.security._trust_common", "os"),
    ("core.security.mac_key", "os"),
    ("core.security.mac_key", "time"),
    ("core.security.env_sanitisation", "os"),
    ("core.security.python_imports", "os"),
    ("core.security.rule_of_two", "os"),
    ("core.security.scratch_supervisor", "os"),
    ("core.analysis._reach_cache", "os"),
    ("core.atomic_fs", "os"),
]
_owners = []
_originals = []
_shared = [(module, dict(vars(module))) for module in (os, time)]
_before = {}
_violations = set()
_restoration_failures = []
_native_collected = 0
_native_executed = 0
_native_failed = 0
_native_skipped = 0
_original_setattr = pytest.MonkeyPatch.setattr


def _changed():
    return [(module.__name__, name) for module, namespace in _shared
            for name, value in namespace.items() if vars(module).get(name) is not value]


def _state():
    return [getattr(module, binding) for module, binding in _owners]


def _watch(self, *args, **kwargs):
    result = _original_setattr(self, *args, **kwargs)
    _violations.update(_changed())
    return result


def pytest_configure(config):
    for name, binding in _BINDINGS:
        module = importlib.import_module(name)
        original = getattr(module, binding)
        _originals.append(original)
        if BORROWED:
            private = ModuleType(original.__name__)
            vars(private).update(vars(original))
            setattr(module, binding, private)
        _owners.append((module, binding))
    _owners_state = _state()
    config._owned_scope_bindings = _owners_state
    pytest.MonkeyPatch.setattr = _watch


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_collection_modifyitems(items):
    global _native_collected
    result = yield
    # Preserve native shuffled order; the owned failure runs after every native case.
    items[:] = [item for item in items if item.path.name != "test_owned_exit.py"] + [
        item for item in items if item.path.name == "test_owned_exit.py"]
    _native_collected = sum(item.path.resolve() == Path(TARGET).resolve() for item in items)
    return result


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    _before[item.nodeid] = _state()


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_teardown(item, nextitem):
    result = yield
    before = _before.pop(item.nodeid)
    after = _state()
    if any(a is not b for a, b in zip(before, after)):
        _restoration_failures.append(item.nodeid)
    return result


def pytest_runtest_logreport(report):
    global _native_executed, _native_failed, _native_skipped
    if Path(report.location[0]).name != Path(TARGET).name:
        return
    if report.when == "call":
        _native_executed += 1
        _native_failed += int(report.failed)
    elif report.when == "setup" and report.skipped:
        _native_skipped += 1


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_sessionfinish(session):
    result = yield
    restored = all(a is b for a, b in zip(_state(), session.config._owned_scope_bindings))
    data = dict(native_collected=_native_collected, native_executed=_native_executed,
                native_failed=_native_failed, native_skipped=_native_skipped,
                shared_mutations=sorted(_violations), shared_namespace_restored=not _changed(),
                teardown_failures=_restoration_failures, borrowed_bindings_restored=restored)
    Path(REPORT).write_text(json.dumps(data))
    if _violations or _restoration_failures or not restored or _changed():
        session.exitstatus = 1
    return result


def pytest_unconfigure(config):
    pytest.MonkeyPatch.setattr = _original_setattr
    for (module, binding), original in zip(_owners, _originals):
        setattr(module, binding, original)
'''

_OWNED_EXIT = r'''
import os
import pytest
from core.security import capped_read
from core.testing.module_bindings import patch_module_attribute

@pytest.fixture
def owned_window(monkeypatch):
    patch_module_attribute(monkeypatch, capped_read, "os", "getpid", lambda: -1)
    assert capped_read.os.getpid() == -1
    assert os.getpid() > 0
    yield


def test_owned_exit(owned_window):
    if OUTCOME == "error":
        raise RuntimeError("owned scope error")
    if OUTCOME == "interrupt":
        raise KeyboardInterrupt("owned scope interrupt")
'''


@pytest.mark.parametrize("file,borrowed,outcome", _CASES,
                         ids=[Path(file).stem + ("-borrowed-" if borrowed else "-ordinary-") + outcome
                              for file, borrowed, outcome in _CASES])
def test_real_native_fixture_scopes(tmp_path, file, borrowed, outcome):
    child = tmp_path / "child"
    child.mkdir()
    report = child / "restoration.json"
    plugin = child / "scope_observer.py"
    plugin.write_text("TARGET = " + repr(str(_REPO / file)) + "\nBORROWED = " + repr(borrowed)
                      + "\nREPORT = " + repr(str(report)) + "\n" + _PLUGIN)
    owned = child / "test_owned_exit.py"
    owned.write_text("OUTCOME = " + repr(outcome) + "\n" + _OWNED_EXIT)
    environment = dict(os.environ)
    for key, leaf in [("HOME", "home"), ("TMPDIR", "tmp"), ("XDG_CONFIG_HOME", "config"),
                      ("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache"), ("RAPTOR_OUT_DIR", "out")]:
        path = child / leaf
        path.mkdir()
        environment[key] = str(path)
    environment["PYTHONPATH"] = str(child) + os.pathsep + str(_REPO)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["RAPTOR_DIR"] = str(_REPO)
    tripwire = child / "tripwire"
    command = [sys.executable, "-m", "pytest", "-p", "core.testing.llm_tripwire",
               "-p", "scope_observer", "--llm-tripwire-dir=" + str(tripwire),
               str(_REPO / file), str(owned), "-c", str(_REPO / "pytest.ini"),
               "-q", "--tb=short", "--basetemp=" + str(child / "scratch"),
               "--junitxml=" + str(child / "results.xml")]
    completed = subprocess.run(command, cwd=_REPO, env=environment, capture_output=True,
                               text=True, timeout=120)
    (child / "pytest.log").write_text(completed.stdout + completed.stderr)
    assert report.is_file(), completed.stdout + completed.stderr
    observed = json.loads(report.read_text())
    assert observed["shared_mutations"] == [], observed
    assert observed["shared_namespace_restored"], observed
    assert observed["teardown_failures"] == [], observed
    assert observed["borrowed_bindings_restored"], observed
    assert observed["native_failed"] == 0, completed.stdout + completed.stderr
    assert observed["native_executed"] > 0, observed
    assert observed["native_executed"] + observed["native_skipped"] == observed["native_collected"], observed
    assert completed.returncode == {"normal": 0, "error": 1, "interrupt": 2}[outcome], completed.stdout + completed.stderr
    if outcome != "normal":
        assert "owned scope " + outcome in completed.stdout + completed.stderr
    assert not any(path.stat().st_size for path in tripwire.rglob("*.jsonl"))

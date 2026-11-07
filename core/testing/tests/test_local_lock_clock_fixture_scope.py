"""Local-import faults preserve caller clocks, locks and CLI trust state."""
import ast
import copy
import errno
import fcntl
from functools import lru_cache
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import time
from types import ModuleType

import pytest
from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'anchor': ['TestFlockFailureIsFailClosed', 'test_persistent_flock_failure_exits_1'],
  'attribute': 'flock',
  'binding': 'fcntl',
  'expected': "patch_module_attribute(monkeypatch, feasibility_mod._local_imports, 'fcntl', "
              "'flock', deny)",
  'file': 'core/analysis/tests/test_run_feasibility_cli.py',
  'line': 297,
  'original': "monkeypatch.setattr(fcntl, 'flock', deny)"},
 {'anchor': ['TestFlockFailureIsFailClosed', 'test_persistent_flock_failure_exits_1'],
  'attribute': 'sleep',
  'binding': 'time',
  'expected': "patch_module_attribute(monkeypatch, feasibility_mod._local_imports, 'time', "
              "'sleep', lambda s: None)",
  'file': 'core/analysis/tests/test_run_feasibility_cli.py',
  'line': 298,
  'original': "monkeypatch.setattr(time, 'sleep', lambda s: None)"},
 {'anchor': ['TestFlockFailureIsFailClosed', 'test_transient_flock_failure_recovers'],
  'attribute': 'flock',
  'binding': 'fcntl',
  'expected': "patch_module_attribute(monkeypatch, feasibility_mod._local_imports, 'fcntl', "
              "'flock', flaky)",
  'file': 'core/analysis/tests/test_run_feasibility_cli.py',
  'line': 333,
  'original': "monkeypatch.setattr(fcntl, 'flock', flaky)"},
 {'anchor': ['TestFlockFailureIsFailClosed', 'test_transient_flock_failure_recovers'],
  'attribute': 'sleep',
  'binding': 'time',
  'expected': "patch_module_attribute(monkeypatch, feasibility_mod._local_imports, 'time', "
              "'sleep', lambda s: None)",
  'file': 'core/analysis/tests/test_run_feasibility_cli.py',
  'line': 334,
  'original': "monkeypatch.setattr(time, 'sleep', lambda s: None)"},
 {'anchor': ['test_invalid_sweep_clock_preserves_every_entry'],
  'attribute': 'time',
  'binding': 'time',
  'expected': "patch_module_attribute(monkeypatch, _local_imports, 'time', 'time', lambda: now)",
  'file': 'core/inventory/tests/test_checklist_replacement.py',
  'line': 203,
  'original': "monkeypatch.setattr(time, 'time', lambda: now)"}]


@lru_cache(maxsize=None)
def _native(file):
    name = "local_import_native_" + file.replace("/", "_").replace(".", "_")
    loader = importlib.machinery.SourceFileLoader(name, str(_REPO/file))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as scope:
        scope.setitem(sys.modules, name, module)
        loader.exec_module(module)
    return module


def _namespace(owner, before):
    assert vars(owner).keys() == before.keys()
    assert all(vars(owner)[key] is value for key, value in before.items())


@lru_cache(maxsize=None)
def _statement(index):
    row = _SITES[index]
    tree = ast.parse((_REPO/row["file"]).read_text())
    parents = {c:n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    accepted = {ast.dump(ast.parse(row[key], mode="eval").body) for key in ("original", "expected")}
    matches = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or ast.dump(n) not in accepted:
            continue
        chain = []
        parent = parents.get(n)
        while parent:
            if isinstance(parent, (ast.FunctionDef, ast.ClassDef)):
                chain.append(parent.name)
            parent = parents.get(parent)
        if chain[::-1] == row["anchor"]:
            matches.append(n)
    assert len(matches) == 1
    return matches[0]


def _holder(mod):
    holder = getattr(mod, "_local_imports", None)
    if holder is None:
        holder = ModuleType("legacy_local_imports")
        holder.time, holder.fcntl = time, fcntl
    return holder


def _cli(native):
    generator = native.feasibility_mod.__wrapped__()
    try:
        module = next(generator)
    except BaseException:
        generator.close()
        raise
    return module, generator


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: str(i))
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_native_local_import_fault_owns_namespace(index, borrowed, outcome):
    row = _SITES[index]
    native = _native(row["file"])
    before_time, before_fcntl = vars(time).copy(), vars(fcntl).copy()
    failure = RuntimeError("local import") if outcome == "error" else KeyboardInterrupt("local import")
    caught = None
    generator = None
    with pytest.MonkeyPatch.context() as scope:
        if "feasibility" in row["file"]:
            module, generator = _cli(native)
            holder = _holder(module)
        else:
            module = None
            fixture = getattr(native, "_owned_sweep_imports", None)
            if fixture is not None:
                fixture.__wrapped__(scope)
            holder = getattr(native, "_local_imports", _holder(native))
        with pytest.MonkeyPatch.context() as inherited:
            original = getattr(holder, row["binding"])
            if borrowed:
                view = ModuleType(original.__name__)
                vars(view).update(vars(original))
                inherited.setattr(holder, row["binding"], view)
            original = getattr(holder, row["binding"])
            prior = vars(original).copy()
            try:
                try:
                    with pytest.MonkeyPatch.context() as fault:
                        token = lambda *a, **kw: None
                        call = copy.deepcopy(_statement(index))
                        call.args[-1] = ast.Name(id="token", ctx=ast.Load())
                        namespace = dict(vars(native), time=time, fcntl=fcntl, feasibility_mod=module,
                                         _local_imports=holder, monkeypatch=fault, token=token,
                                         patch_module_attribute=patch_module_attribute)
                        exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.Expr(call)], type_ignores=[])), row["file"], "exec"), namespace)
                        _namespace(time, before_time)
                        _namespace(fcntl, before_fcntl)
                        _namespace(original, prior)
                        assert getattr(getattr(holder, row["binding"]), row["attribute"]) is token
                        if outcome != "normal":
                            raise failure
                except BaseException as error:
                    caught = error
                _namespace(original, prior)
            finally:
                if generator is not None:
                    generator.close()
    _namespace(time, before_time)
    _namespace(fcntl, before_fcntl)
    assert caught is (None if outcome == "normal" else failure), repr(caught)


@pytest.mark.parametrize("prior", [None, "", "caller-token"])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_cli_loading_restores_marker_before_yield(prior, outcome, monkeypatch):
    native = _native("core/analysis/tests/test_run_feasibility_cli.py")
    if prior is None:
        monkeypatch.delenv("_RAPTOR_TRUSTED", raising=False)
    else:
        monkeypatch.setenv("_RAPTOR_TRUSTED", prior)
    original_path = sys.path
    original_entries = sys.path.copy()
    failure = RuntimeError("CLI body") if outcome == "error" else KeyboardInterrupt("CLI body")
    caught = None
    generator = None
    try:
        try:
            _, generator = _cli(native)
            assert ("_RAPTOR_TRUSTED" in os.environ, os.environ.get("_RAPTOR_TRUSTED")) == (prior is not None, prior)
            assert sys.path is original_path and sys.path == original_entries
            if outcome != "normal":
                raise failure
        except BaseException as error:
            caught = error
    finally:
        if generator is not None:
            generator.close()
    assert ("_RAPTOR_TRUSTED" in os.environ, os.environ.get("_RAPTOR_TRUSTED")) == (prior is not None, prior)
    assert sys.path is original_path and sys.path == original_entries
    assert caught is (None if outcome == "normal" else failure), repr(caught)


@pytest.mark.parametrize("prior", [None, "", "caller-token"])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
def test_failed_cli_loading_restores_marker_and_path(prior, error_type, monkeypatch):
    native = _native("core/analysis/tests/test_run_feasibility_cli.py")
    if prior is None:
        monkeypatch.delenv("_RAPTOR_TRUSTED", raising=False)
    else:
        monkeypatch.setenv("_RAPTOR_TRUSTED", prior)
    failure = error_type("loader failure")
    class Loader(importlib.machinery.SourceFileLoader):
        def exec_module(self, module):
            sys.path.insert(0, "owned-loader-entry")
            raise failure
    machinery = ModuleType("owned_machinery")
    vars(machinery).update(vars(importlib.machinery))
    machinery.SourceFileLoader = Loader
    patch_module_attribute(monkeypatch, native, "importlib", "machinery", machinery)
    original_path, entries = sys.path, sys.path.copy()
    with pytest.raises(error_type) as caught:
        _cli(native)
    assert caught.value is failure
    assert sys.path is original_path and sys.path == entries
    assert ("_RAPTOR_TRUSTED" in os.environ, os.environ.get("_RAPTOR_TRUSTED")) == (prior is not None, prior)


@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_real_cli_lock_retry_uses_private_imports(tmp_path, outcome):
    native = _native("core/analysis/tests/test_run_feasibility_cli.py")
    module, generator = _cli(native)
    original_time, original_fcntl = vars(time).copy(), vars(fcntl).copy()
    binary = tmp_path/"binary"
    binary.write_bytes(b"\x7fELF")
    findings = tmp_path/"findings.json"
    findings.write_text('{"findings": []}')
    locks, sleeps = [], []
    def lock(fd, operation):
        locks.append((fd, operation))
        if len(locks) == 1:
            raise OSError(errno.ENOLCK, "owned transient lock fault")
        return fcntl.flock(fd, operation)
    failure = RuntimeError("lock graph") if outcome == "error" else KeyboardInterrupt("lock graph")
    caught = None
    try:
        try:
            with pytest.MonkeyPatch.context() as scope:
                holder = _holder(module)
                patch_module_attribute(scope, holder, "fcntl", "flock", lock)
                patch_module_attribute(scope, holder, "time", "sleep", sleeps.append)
                patch_module_attribute(scope, module, "sys", "argv", ["raptor-run-feasibility", str(binary), str(findings), str(tmp_path/"out")])
                module.main()
                assert sleeps == [0.5]
                assert [op for _, op in locks] == [fcntl.LOCK_EX, fcntl.LOCK_EX, fcntl.LOCK_UN]
                for fd, _ in locks:
                    with pytest.raises(OSError) as closed:
                        os.fstat(fd)
                    assert closed.value.errno == errno.EBADF
                _namespace(time, original_time)
                _namespace(fcntl, original_fcntl)
                if outcome != "normal":
                    raise failure
        except BaseException as error:
            caught = error
    finally:
        generator.close()
    _namespace(time, original_time)
    _namespace(fcntl, original_fcntl)
    assert caught is (None if outcome == "normal" else failure), repr(caught)


@pytest.mark.parametrize("now", [float("nan"), float("inf"), -float("inf")], ids=["nan", "inf", "negative-inf"])
def test_real_retired_sweep_reads_private_clock(now, tmp_path):
    native = _native("core/inventory/tests/test_checklist_replacement.py")
    before = vars(time).copy()
    old = tmp_path/".checklist-stale-owned"
    old.mkdir()
    marker = old/"keep"
    marker.write_text("keep")
    with pytest.MonkeyPatch.context() as scope:
        fixture = getattr(native, "_owned_sweep_imports", None)
        if fixture is not None:
            fixture.__wrapped__(scope)
        holder = getattr(native, "_local_imports", _holder(native))
        calls = []
        patch_module_attribute(scope, holder, "time", "time", lambda: calls.append(1) or now)
        native.inv._sweep_retired_dirs(tmp_path)
        assert calls == [1]
        assert marker.read_text() == "keep"
        _namespace(time, before)
    _namespace(time, before)


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: str(i))
def test_unmodified_local_import_control(index):
    for module in (time, fcntl):
        _namespace(module, vars(module).copy())

"""Native availability fixtures own local imports and cached probe answers."""
import ast
import builtins
import copy
from contextlib import contextmanager
from functools import lru_cache
import importlib
import importlib.machinery
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
from types import ModuleType
from unittest import mock

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute
from core.testing.module_views import module_function_view

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'anchor': ['TestWslAdvisories', 'test_landlock_missing_names_the_remedies'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', return_value=None)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 259,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', return_value=None)"},
 {'anchor': ['TestWslAdvisories', 'test_host_consent_applied_replaces_refusal_with_posture'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', return_value=None)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 280,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', return_value=None)"},
 {'anchor': ['TestWslAdvisories', 'test_host_consent_probe_failure_keeps_the_refusal_advisory'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', return_value=None)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 302,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', return_value=None)"},
 {'anchor': ['TestWslAdvisories', 'test_host_consent_marker_ignored_when_landlock_present'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', return_value='/usr/bin/tool')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 317,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', return_value='/usr/bin/tool')"},
 {'anchor': ['TestWslAdvisories', 'test_landlock_present_no_landlock_line'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', return_value='/usr/bin/tool')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 326,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', return_value='/usr/bin/tool')"},
 {'anchor': ['TestWslAdvisories', 'test_rr_present_gets_perf_counter_note'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', which)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 336,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', which)"},
 {'anchor': ['TestWslAdvisories', 'test_docker_absent_gets_desktop_integration_hint'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', return_value=None)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 349,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', return_value=None)"},
 {'anchor': ['TestWslAdvisories', 'test_all_good_is_quiet'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', which)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 362,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', which)"},
 {'anchor': ['TestWslAdvisories', 'test_temp_root_on_interop_mount_gets_tmpdir_line'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', which)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 373,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', which)"},
 {'anchor': ['TestWslAdvisories', 'test_temp_root_on_interop_mount_gets_tmpdir_line'],
  'attribute': 'gettempdir',
  'binding': 'tempfile',
  'expected': "mock_module_attribute(wsl, 'tempfile', 'gettempdir', return_value='/mnt/c/Temp')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 376,
  'new_binding': 'tempfile',
  'original': "mock.patch('tempfile.gettempdir', return_value='/mnt/c/Temp')"},
 {'anchor': ['TestWslAdvisories', 'test_temp_root_advisory_escapes_hostile_tmpdir'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', which)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 392,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', which)"},
 {'anchor': ['TestWslAdvisories', 'test_temp_root_advisory_escapes_hostile_tmpdir'],
  'attribute': 'gettempdir',
  'binding': 'tempfile',
  'expected': "mock_module_attribute(wsl, 'tempfile', 'gettempdir', "
              "return_value='/mnt/c/\\x1b]0;pwned\\x07tmp')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 395,
  'new_binding': 'tempfile',
  'original': "mock.patch('tempfile.gettempdir', return_value='/mnt/c/\\x1b]0;pwned\\x07tmp')"},
 {'anchor': ['TestWslAdvisories', 'test_wsl1_line_replaces_wsl2_advisories'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', which)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 412,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', which)"},
 {'anchor': ['TestWslAdvisories', 'test_wsl1_line_absent_on_wsl2'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(wsl, 'shutil', 'which', return_value=None)",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 423,
  'new_binding': 'shutil',
  'original': "mock.patch('shutil.which', return_value=None)"},
 {'anchor': ['TestWarnTmpdirWindowsInterop', 'test_warns_once_per_process'],
  'attribute': 'gettempdir',
  'binding': 'tempfile',
  'expected': "mock_module_attribute(wsl, 'tempfile', 'gettempdir', return_value='/mnt/c/Temp')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'wsl',
  'line': 501,
  'new_binding': 'tempfile',
  'original': "mock.patch('tempfile.gettempdir', return_value='/mnt/c/Temp')"},
 {'anchor': ['TestAvailable', 'test_no_frida_python_no_cli'],
  'attribute': '__import__',
  'binding': 'builtins',
  'expected': "mock_module_attribute(self._mod, '_imports', '__import__', side_effect=fake_import)",
  'file': 'packages/frida/tests/test_substrate.py',
  'kind': 'frida',
  'line': 37,
  'new_binding': '_imports',
  'original': "patch('builtins.__import__', side_effect=fake_import)"},
 {'anchor': ['TestAvailable', 'test_no_frida_python_no_cli'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(self._mod, 'shutil', 'which', return_value=None)",
  'file': 'packages/frida/tests/test_substrate.py',
  'kind': 'frida',
  'line': 38,
  'new_binding': 'shutil',
  'original': "patch('shutil.which', return_value=None)"},
 {'anchor': ['TestAvailable', 'test_cli_only_sufficient'],
  'attribute': '__import__',
  'binding': 'builtins',
  'expected': "mock_module_attribute(self._mod, '_imports', '__import__', side_effect=fake_import)",
  'file': 'packages/frida/tests/test_substrate.py',
  'kind': 'frida',
  'line': 53,
  'new_binding': '_imports',
  'original': "patch('builtins.__import__', side_effect=fake_import)"},
 {'anchor': ['TestAvailable', 'test_cli_only_sufficient'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(self._mod, 'shutil', 'which', return_value='/usr/bin/frida')",
  'file': 'packages/frida/tests/test_substrate.py',
  'kind': 'frida',
  'line': 54,
  'new_binding': 'shutil',
  'original': "patch('shutil.which', return_value='/usr/bin/frida')"},
 {'anchor': ['TestAvailable', 'test_both_present'],
  'attribute': '__import__',
  'binding': 'builtins',
  'expected': "mock_module_attribute(self._mod, '_imports', '__import__', side_effect=fake_import)",
  'file': 'packages/frida/tests/test_substrate.py',
  'kind': 'frida',
  'line': 68,
  'new_binding': '_imports',
  'original': "patch('builtins.__import__', side_effect=fake_import)"},
 {'anchor': ['TestAvailable', 'test_both_present'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(self._mod, 'shutil', 'which', "
              "return_value='/usr/local/bin/frida')",
  'file': 'packages/frida/tests/test_substrate.py',
  'kind': 'frida',
  'line': 69,
  'new_binding': 'shutil',
  'original': "patch('shutil.which', return_value='/usr/local/bin/frida')"},
 {'anchor': ['TestAvailable', 'test_force_bypasses_cache'],
  'attribute': '__import__',
  'binding': 'builtins',
  'expected': "mock_module_attribute(self._mod, '_imports', '__import__', side_effect=fake_import)",
  'file': 'packages/frida/tests/test_substrate.py',
  'kind': 'frida',
  'line': 94,
  'new_binding': '_imports',
  'original': "patch('builtins.__import__', side_effect=fake_import)"},
 {'anchor': ['TestAvailable', 'test_force_bypasses_cache'],
  'attribute': 'which',
  'binding': 'shutil',
  'expected': "mock_module_attribute(self._mod, 'shutil', 'which', "
              "return_value='/usr/local/bin/frida')",
  'file': 'packages/frida/tests/test_substrate.py',
  'kind': 'frida',
  'line': 95,
  'new_binding': 'shutil',
  'original': "patch('shutil.which', return_value='/usr/local/bin/frida')"}]


@lru_cache(maxsize=None)
def _native(file):
    name = "owned_availability_" + file.replace("/", "_").replace(".", "_")
    loader = importlib.machinery.SourceFileLoader(name, str(_REPO / file))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as scope:
        scope.setitem(sys.modules, name, module)
        loader.exec_module(module)
    return module


def _namespace(owner, before):
    values = owner if isinstance(owner, dict) else vars(owner)
    assert values.keys() == before.keys()
    assert all(values[key] is value for key, value in before.items())


@contextmanager
def _seed(file, borrowed, builtin_shape, cache):
    native = _native(file)
    kind = "wsl" if file.startswith("core/") else "frida"
    canonical = importlib.import_module("core.startup.wsl" if kind == "wsl" else "packages.frida")
    with pytest.MonkeyPatch.context() as inherited:
        source = module_function_view(canonical) if borrowed else canonical
        calls = []
        real_import = builtins.__import__
        def caller_import(name, *args, **kwargs):
            calls.append(name)
            return real_import(name, *args, **kwargs)
        original_builtins = vars(source).get("__builtins__", builtins)
        values = dict(vars(original_builtins) if isinstance(original_builtins, ModuleType) else original_builtins)
        values["__import__"] = caller_import
        prior_builtins = values
        if builtin_shape == "module":
            prior_builtins = ModuleType("borrowed_builtins")
            vars(prior_builtins).update(values)
        inherited.setattr(source, "__builtins__", prior_builtins)
        if kind == "wsl":
            for name in ("_is_wsl_cache", "_is_wsl2_cache", "_tmpdir_warned"):
                inherited.setattr(source, name, cache)
            inherited.setattr(native, "wsl", source)
            inherited.setattr(native, "_host_platform_consumer", source)
            instance = None
        else:
            import packages
            inherited.setitem(sys.modules, "packages.frida", source)
            inherited.setattr(packages, "frida", source)
            inherited.setattr(source, "_available", cache)
            inherited.setattr(native, "available", source.available)
            instance = native.TestAvailable()
        owners = [builtins, shutil, tempfile, canonical, source, native, prior_builtins]
        if instance is not None:
            owners.append(instance)
        snapshots = [(owner, dict(owner if isinstance(owner, dict) else vars(owner))) for owner in owners]
        # The inherited patch also owns the unregistered cache writes made
        # by counterfactual xunit setup, including failed setup.
        yield native, source, instance, snapshots, calls


@contextmanager
def _open(native, instance, scope):
    if instance is None:
        fixture = getattr(native, "_owned_wsl_namespace", None)
        yield fixture.__wrapped__(scope) if fixture is not None else native.wsl
    else:
        fixture = getattr(type(instance), "_owned_availability", None)
        if fixture is None:
            instance.setup_method()
            try:
                yield instance._mod
            finally:
                instance.teardown_method()
        else:
            generator = fixture.__wrapped__(instance, scope)
            try:
                yield next(generator)
            finally:
                generator.close()


@lru_cache(maxsize=None)
def _statement(index):
    row = _SITES[index]
    tree = ast.parse((_REPO / row["file"]).read_text())
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    accepted = {ast.dump(ast.parse(row[key], mode="eval").body) for key in ("original", "expected")}
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or ast.dump(node) not in accepted:
            continue
        chain = []
        parent = parents.get(node)
        while parent:
            if isinstance(parent, (ast.ClassDef, ast.FunctionDef)):
                chain.append(parent.name)
            parent = parents.get(parent)
        if chain[::-1] == row["anchor"]:
            found.append(node)
    assert len(found) == 1, row
    return found[0]


def _override(index, native, instance, token):
    row = _SITES[index]
    call = copy.deepcopy(_statement(index))
    private = isinstance(call.func, ast.Name) and call.func.id == "mock_module_attribute"
    call.args = call.args[:3 if private else 1]
    call.keywords = [ast.keyword(arg="new", value=ast.Name(id="token", ctx=ast.Load()))]
    namespace = dict(vars(native), self=instance, token=token, mock=mock,
                     patch=mock.patch, mock_module_attribute=mock_module_attribute)
    return eval(compile(ast.fix_missing_locations(ast.Expression(call)), row["file"], "eval"), namespace)


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: _SITES[i]["file"] + ":" + str(_SITES[i]["line"]))
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("builtin_shape", ["dict", "module"])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_native_import_override_preserves_caller(index, borrowed, builtin_shape, outcome):
    row = _SITES[index]
    with _seed(row["file"], borrowed, builtin_shape, True) as state:
        native, source, instance, snapshots, _ = state
        inherited_import = builtins.__import__
        def token(*args, **kwargs):
            return inherited_import(*args, **kwargs) if row["binding"] == "builtins" else None
        failure = RuntimeError("owned import scope") if outcome == "error" else KeyboardInterrupt("owned import scope")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope, _open(native, instance, scope) as private:
                with _override(index, native, instance, token):
                    for owner, before in snapshots:
                        if owner is not native and owner is not instance:
                            _namespace(owner, before)
                    owner = getattr(private, row["new_binding"])
                    assert getattr(owner, row["attribute"]) is token
                    assert private is not source
                    if outcome != "normal":
                        raise failure
        except BaseException as error:
            caught = error
        for owner, before in snapshots:
            _namespace(owner, before)
        assert caught is (None if outcome == "normal" else failure), repr(caught)


_FILES = list(dict.fromkeys(row["file"] for row in _SITES))


@pytest.mark.parametrize("file", _FILES)
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("builtin_shape", ["dict", "module"])
@pytest.mark.parametrize("cache", [None, False, True])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_real_probe_graph_keeps_caches_and_imports_private(file, borrowed, builtin_shape, cache, outcome):
    with _seed(file, borrowed, builtin_shape, cache) as state:
        native, source, instance, snapshots, calls = state
        failure = RuntimeError("probe graph") if outcome == "error" else KeyboardInterrupt("probe graph")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope, _open(native, instance, scope) as private:
                assert private is not source
                function = private.is_wsl if instance is None else private.available
                original = source.is_wsl if instance is None else source.available
                assert function.__code__ is original.__code__
                assert function.__globals__ is vars(private)
                if instance is None:
                    scope.setattr(private, "_is_wsl_cache", None)
                    scope.setattr(private, "_is_wsl2_cache", None)
                    reads = []
                    scope.setattr(private, "_read_kernel_id", lambda: reads.append(1) or "microsoft-standard-WSL2")
                    patch_module_attribute(scope, private, "sys", "platform", "linux")
                    assert private.is_wsl() is True and private.is_wsl2() is True
                    assert private.is_wsl() is True and len(reads) == 2
                    imported = function.__builtins__["__import__"]("shutil")
                    assert imported is private.shutil and imported is not shutil
                    assert function.__builtins__["__import__"]("tempfile") is private.tempfile
                else:
                    patch_module_attribute(scope, private, "shutil", "which", lambda *a, **k: None)
                    real_import = private._imports.__import__
                    def no_sdk(name, *args, **kwargs):
                        if name == "frida":
                            raise ImportError("owned missing SDK")
                        return real_import(name, *args, **kwargs)
                    patch_module_attribute(scope, private, "_imports", "__import__", no_sdk)
                    assert native.available() is False
                    assert native.available() is False and private._available is False
                    private._available = True
                    assert native.available() is True
                    assert native.available(force=True) is False
                function.__builtins__["__import__"]("math")
                assert "math" in calls
                for owner, before in snapshots:
                    if owner is not native and owner is not instance:
                        _namespace(owner, before)
                if outcome != "normal":
                    raise failure
        except BaseException as error:
            caught = error
        for owner, before in snapshots:
            _namespace(owner, before)
        assert caught is (None if outcome == "normal" else failure), repr(caught)


@pytest.mark.parametrize("file", _FILES)
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("builtin_shape", ["dict", "module"])
def test_unmodified_probe_control(file, borrowed, builtin_shape):
    with _seed(file, borrowed, builtin_shape, True) as state:
        for owner, before in state[3]:
            _namespace(owner, before)


@pytest.mark.parametrize("file", _FILES)
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("builtin_shape", ["dict", "module"])
@pytest.mark.parametrize("stage", ["first", "second"])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
def test_partial_probe_fixture_publication_unwinds(file, borrowed, builtin_shape, stage, error_type):
    with _seed(file, borrowed, builtin_shape, True) as state:
        native, _, instance, snapshots, _ = state
        failure = error_type("probe publication")
        class Publish(pytest.MonkeyPatch):
            def setitem(self, mapping, key, value):
                super().setitem(mapping, key, value)
                selected = ("wsl" if stage == "first" else "_host_platform_consumer") if instance is None else "available"
                if mapping is vars(native) and key == selected and (instance is None or stage == "second"):
                    raise failure

            def setattr(self, target, name, value, raising=True):
                super().setattr(target, name, value, raising=raising)
                if instance is not None and target is instance and name == "_mod" and stage == "first":
                    raise failure
        caught = None
        try:
            with Publish.context() as scope, _open(native, instance, scope):
                pass
        except BaseException as error:
            caught = error
        for owner, before in snapshots:
            _namespace(owner, before)
        assert caught is failure, repr(caught)

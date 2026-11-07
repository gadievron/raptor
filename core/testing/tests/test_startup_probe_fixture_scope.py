"""Startup probes keep stdlib mocks local and retain their negative guard."""

import ast
import importlib
import importlib.metadata
import importlib.util
from pathlib import Path
from pkgutil import resolve_name
import shutil
import subprocess
from unittest import mock

import pytest

from core.testing.module_bindings import mock_module_attribute

ROOT = Path(__file__).resolve().parents[3]
CASES = [('core/startup/tests/test_check_tools.py', ('_run_check_tools',), 'core.startup.init.importlib.util.find_spec', 0), ('core/startup/tests/test_check_tools.py', ('TestSemgrepVersion', 'test_prefers_importlib_metadata'), 'shutil.which', 0), ('core/startup/tests/test_check_tools.py', ('TestSemgrepVersion', 'test_prefers_importlib_metadata'), 'importlib.metadata.version', 0), ('core/startup/tests/test_check_tools.py', ('TestSemgrepVersion', 'test_falls_back_to_cli_probe_when_not_pip_installed'), 'shutil.which', 0), ('core/startup/tests/test_check_tools.py', ('TestSemgrepVersion', 'test_falls_back_to_cli_probe_when_not_pip_installed'), 'importlib.metadata.version', 0), ('core/startup/tests/test_check_tools.py', ('TestSemgrepVersion', 'test_external_path_binary_uses_its_own_version'), 'shutil.which', 0), ('core/startup/tests/test_check_tools.py', ('TestSemgrepVersion', 'test_external_path_binary_uses_its_own_version'), 'importlib.metadata.version', 0), ('core/startup/tests/test_check_tools.py', ('TestCachedCliVersion', 'test_probe_parses_and_caches'), 'subprocess.run', 0), ('core/startup/tests/test_check_tools.py', ('TestCachedCliVersion', 'test_probe_parses_and_caches'), 'subprocess.run', 1), ('core/startup/tests/test_check_tools.py', ('TestCachedCliVersion', 'test_cache_invalidated_when_binary_changes'), 'subprocess.run', 0), ('core/startup/tests/test_check_tools.py', ('TestCachedCliVersion', 'test_cache_invalidated_when_binary_changes'), 'subprocess.run', 1), ('core/startup/tests/test_check_tools.py', ('TestCachedCliVersion', 'test_probe_failure_returns_none_and_not_cached'), 'subprocess.run', 0), ('core/startup/tests/test_check_tools.py', ('TestCachedCliVersion', 'test_unparseable_output_returns_none'), 'subprocess.run', 0), ('core/startup/tests/test_check_tools.py', ('TestCachedCliVersion', 'test_corrupt_cache_file_is_tolerated'), 'subprocess.run', 0), ('core/startup/tests/test_doctor.py', ('TestModuleDepVerification', '_run'), 'importlib.util.find_spec', 0), ('core/startup/tests/test_doctor.py', ('TestModuleDepVerification', '_run'), 'subprocess.run', 0), ('core/startup/tests/test_doctor.py', ('TestModuleProbeIsolation', 'test_planted_module_in_cwd_not_executed'), 'importlib.util.find_spec', 0)]


def _function(tree, anchor):
    for name in anchor:
        tree = next(n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name == name)
    return tree


def _native_call(file, anchor, target, index):
    function = _function(ast.parse((ROOT / file).read_text()), anchor)
    calls = []
    for n in ast.walk(function):
        if not isinstance(n, ast.Call):
            continue
        if isinstance(n.func, ast.Attribute) and n.func.attr == 'patch' and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == target:
            calls.append(n)
        elif 'TestJoernVersion' not in anchor and isinstance(n.func, ast.Name) and n.func.id == 'mock_module_attribute' and len(n.args) > 2 and isinstance(n.args[2], ast.Constant) and n.args[2].value == target.rsplit('.', 1)[-1]:
            calls.append(n)
    calls.sort(key=lambda n: (n.lineno, n.col_offset))
    expected = 2 if anchor[-1] in ('test_probe_parses_and_caches', 'test_cache_invalidated_when_binary_changes') else 1
    assert len(calls) == expected
    return calls[index]


def _shared():
    return (shutil.which, importlib.metadata.version, subprocess.run, importlib.util.find_spec)


@pytest.mark.parametrize('file,anchor,target,index', CASES)
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_native_probe_mock_is_private(file, anchor, target, index, finish, tmp_path):
    module = importlib.import_module(file[:-3].replace('/', '.'))
    from core.startup import init, doctor

    shared = _shared()
    owned = (init.shutil, init.importlib, init._semgrep_version, init._cached_cli_version,
             doctor._module_dep_warnings, doctor.subprocess)
    previous = vars(module).get('_probe_imports', None)
    patcher = pytest.MonkeyPatch()
    generator = None
    try:
        isolate = getattr(module, '_isolate_shutil_patch_targets', None)
        if isolate is not None:
            isolate.__wrapped__(patcher)
        fixture = getattr(module, '_owned_probe_imports', None)
        if fixture is not None:
            generator = fixture.__wrapped__(patcher)
            next(generator)
        assert all(a is b for a, b in zip(_shared(), shared, strict=True))
        imports = getattr(module, '_probe_imports', None)
        namespace = dict(mock=mock, mock_module_attribute=mock_module_attribute,
                         _mock_owner=resolve_name,
                         _probe_imports=imports, doctor=doctor,
                         proc=mock.Mock(), proc2=mock.Mock(), run_mock=mock.Mock(),
                         PackageNotFoundError=importlib.metadata.PackageNotFoundError,
                         module_present=True, spec_found=True, tmp_path=tmp_path)
        call = _native_call(file, anchor, target, index)
        with eval(compile(ast.Expression(call), file, 'eval'), namespace) as patched:
            assert all(a is b for a, b in zip(_shared(), shared, strict=True))
            if target == 'shutil.which':
                actual = imports.shutil.which
            elif target == 'importlib.metadata.version':
                actual = getattr(imports, 'importlib.metadata').version
            elif target == 'subprocess.run':
                actual = doctor.subprocess.run if file.endswith('test_doctor.py') else imports.subprocess.run
            else:
                actual = (getattr(imports, 'importlib.util').util.find_spec
                          if file.endswith('test_doctor.py') else init.importlib.util.find_spec)
            assert actual is patched
            if finish == 'error':
                raise RuntimeError('owned exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        patcher.undo()
        assert all(a is b for a, b in zip(_shared(), shared, strict=True))
        after = (init.shutil, init.importlib, init._semgrep_version, init._cached_cli_version,
                 doctor._module_dep_warnings, doctor.subprocess)
        assert all(a is b for a, b in zip(after, owned, strict=True))
        assert vars(module).get('_probe_imports', None) is previous


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_joern_global_no_subprocess_guard_is_retained(finish, tmp_path):
    from contextlib import nullcontext
    from core.startup import init

    file = 'core/startup/tests/test_check_tools.py'
    module = importlib.import_module('core.startup.tests.test_check_tools')
    call = _native_call(file, ('TestJoernVersion', 'test_reads_dist_version_without_subprocess'), 'subprocess.run', 0)
    function = _function(ast.parse((ROOT / file).read_text()),
                         ('TestJoernVersion', 'test_reads_dist_version_without_subprocess'))
    mirrors = [n for n in ast.walk(function) if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Name) and n.func.id == 'mock_module_attribute']
    assert len(mirrors) <= 1
    original = subprocess.run
    patcher = pytest.MonkeyPatch()
    generator = None
    try:
        module._isolate_shutil_patch_targets.__wrapped__(patcher)
        fixture = getattr(module, '_owned_probe_imports', None)
        if fixture is not None:
            generator = fixture.__wrapped__(patcher)
            next(generator)
        imports = getattr(module, '_probe_imports', None)
        executable = tmp_path / 'joern'
        executable.write_text('fixture-only; never executed\n')
        patcher.setenv('XDG_CACHE_HOME', str(tmp_path / 'cache'))
        patcher.setattr(init.shutil, 'which', lambda _name: str(executable))
        with eval(compile(ast.Expression(call), file, 'eval'), {'mock': mock}) as guard:
            context = (eval(compile(ast.Expression(mirrors[0]), file, 'eval'),
                            dict(mock_module_attribute=mock_module_attribute,
                                 _probe_imports=imports, sub=guard))
                       if mirrors else nullcontext())
            with context:
                assert subprocess.run is guard
                subprocess.run(['owned-negative-control'])
                guard.assert_called_once_with(['owned-negative-control'])
                guard.reset_mock()
                guard.return_value = mock.Mock(returncode=0, stdout='joern 1.2.3', stderr='')
                assert init._cached_cli_version('joern') == '1.2.3'
                guard.assert_called_once()
                assert guard.call_args.args[0] == [str(executable), '--version']
                if finish == 'error':
                    raise RuntimeError('owned exit')
                if finish == 'interrupt':
                    raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        patcher.undo()
        assert subprocess.run is original

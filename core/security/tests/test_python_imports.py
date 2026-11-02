"""Protected startup drops writable/undeclared imports, without executing them."""
import os
import sys
from types import SimpleNamespace

import pytest

from core.security import python_imports
from core.startup import install_guard


def test_ordinary_startup_preserves_import_paths(monkeypatch):
    monkeypatch.delenv('RAPTOR_INSTALL_PROTECTED', raising=False)
    original = list(sys.path)
    def unexpected():
        pytest.fail('ordinary imports must not inspect namespace state')
    monkeypatch.setattr(install_guard, 'verify_inside', unexpected)
    assert python_imports.harden_import_paths() == ()
    assert sys.path == original


def test_marker_without_namespace_cannot_activate_policy(monkeypatch):
    monkeypatch.setenv('RAPTOR_INSTALL_PROTECTED', '1')
    monkeypatch.setenv('PYTHONPYCACHEPREFIX', '/unused-test-cache')
    monkeypatch.setattr(sys, 'pycache_prefix', '/unused-test-cache')
    monkeypatch.setattr(sys, 'dont_write_bytecode', False)
    original = list(sys.path)
    def refused():
        raise install_guard.ProtectionError('no protected namespace')
    monkeypatch.setattr(install_guard, 'verify_inside', refused)
    with pytest.raises(install_guard.ProtectionError):
        python_imports.harden_import_paths()
    assert sys.path == original
    assert sys.pycache_prefix == '/unused-test-cache'
    assert sys.dont_write_bytecode is False
    assert os.environ['PYTHONPYCACHEPREFIX'] == '/unused-test-cache'


def test_only_declared_readonly_paths_survive(tmp_path, monkeypatch):
    code = tmp_path / 'installation'
    code.mkdir()
    output = code / 'out'
    output.mkdir()
    dependency = tmp_path / 'dependency'
    dependency.mkdir()
    foreign = tmp_path / 'foreign-readonly'
    foreign.mkdir()
    alias = tmp_path / 'library-alias'
    alias.symlink_to(dependency, target_is_directory=True)
    monkeypatch.setenv('RAPTOR_INSTALL_PROTECTED', '1')
    monkeypatch.setattr(install_guard, 'verify_inside', lambda: None)
    monkeypatch.setattr(install_guard, 'protected_paths', lambda: [code, dependency])
    monkeypatch.setattr(install_guard, 'writable_locations', lambda: [output])
    # Even a read-only remount of output is data, not an approved code root.
    monkeypatch.setattr(python_imports, '_read_only', lambda path: True)
    monkeypatch.setattr(sys, 'pycache_prefix', str(tmp_path/'cache'))
    monkeypatch.setattr(sys, 'dont_write_bytecode', False)
    monkeypatch.setenv('PYTHONPYCACHEPREFIX', str(tmp_path/'cache'))
    monkeypatch.setattr(sys, 'path', ['', '.', str(code), str(output), str(foreign),
                                    str(alias), str(dependency), str(tmp_path/'missing')])
    monkeypatch.setattr(sys, 'path_importer_cache', {str(output): object()})
    removed = python_imports.harden_import_paths()
    assert sys.path == [str(code), str(dependency)]
    assert str(output) in removed
    assert str(foreign) in removed
    assert '' in removed and '.' in removed
    assert sys.path_importer_cache == {}
    assert sys.pycache_prefix is None
    assert sys.dont_write_bytecode is True
    assert 'PYTHONPYCACHEPREFIX' not in os.environ


def test_readonly_check_uses_mount_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(os, 'statvfs', lambda path: SimpleNamespace(f_flag=os.ST_RDONLY))
    assert python_imports._read_only(tmp_path)
    monkeypatch.setattr(os, 'statvfs', lambda path: SimpleNamespace(f_flag=0))
    assert not python_imports._read_only(tmp_path)


def test_writable_shadow_module_is_not_executed(tmp_path, monkeypatch):
    import importlib
    dependency = tmp_path / 'dependency'
    dependency.mkdir()
    poison = tmp_path / 'scratch'
    poison.mkdir()
    name = '_raptor_import_path_probe'
    (dependency / (name + '.py')).write_text('VALUE = 42\n')
    (poison / (name + '.py')).write_text('raise AssertionError("writable shadow executed")\n')
    monkeypatch.setenv('RAPTOR_INSTALL_PROTECTED', '1')
    monkeypatch.setattr(install_guard, 'verify_inside', lambda: None)
    monkeypatch.setattr(install_guard, 'protected_paths', lambda: [dependency])
    monkeypatch.setattr(install_guard, 'writable_locations', lambda: [])
    monkeypatch.setattr(python_imports, '_read_only', lambda path: path == dependency)
    monkeypatch.setattr(sys, 'path', [str(poison), str(dependency)])
    monkeypatch.setattr(sys, 'path_importer_cache', dict(sys.path_importer_cache))
    monkeypatch.setattr(sys, 'pycache_prefix', None)
    monkeypatch.setattr(sys, 'dont_write_bytecode', False)
    try:
        python_imports.harden_import_paths()
        assert importlib.import_module(name).VALUE == 42
    finally:
        sys.modules.pop(name, None)


@pytest.fixture
def import_layout(tmp_path, monkeypatch):
    code = tmp_path / 'code'
    data = code / 'out'
    dependency = tmp_path / 'dependencies'
    data.mkdir(parents=True)
    dependency.mkdir()
    monkeypatch.setenv('RAPTOR_INSTALL_PROTECTED', '1')
    monkeypatch.setattr(install_guard, 'verify_inside', lambda: None)
    monkeypatch.setattr(install_guard, 'protected_paths', lambda: [code, dependency])
    monkeypatch.setattr(install_guard, 'writable_locations', lambda: [data])
    monkeypatch.setattr(python_imports, '_read_only', lambda path: True)
    monkeypatch.setattr(sys, 'path', list(sys.path))
    monkeypatch.setattr(sys, 'path_importer_cache', dict(sys.path_importer_cache))
    monkeypatch.setattr(sys, 'pycache_prefix', None)
    monkeypatch.setattr(sys, 'dont_write_bytecode', False)
    monkeypatch.delenv('PYTHONPYCACHEPREFIX', raising=False)
    return code, data, dependency


def test_writable_declared_dependency_is_rejected(import_layout, monkeypatch):
    code, _, dependency = import_layout
    monkeypatch.setattr(python_imports, '_read_only', lambda path: str(path) != str(dependency))
    sys.path[:] = [str(code), str(dependency)]
    assert python_imports.harden_import_paths() == (str(dependency),)
    assert sys.path == [str(code)]


@pytest.mark.parametrize('location', ['output', 'registry', 'scratch'])
def test_declared_data_is_excluded_even_when_readonly(import_layout, tmp_path, monkeypatch, location):
    code, output, _ = import_layout
    data = output if location == 'output' else tmp_path / location
    nested = data / 'nested'
    nested.mkdir(parents=True)
    monkeypatch.setattr(install_guard, 'protected_paths', lambda: [code, tmp_path])
    monkeypatch.setattr(install_guard, 'writable_locations', lambda: [data])
    sys.path[:] = [str(code), str(data), str(nested)]
    python_imports.harden_import_paths()
    assert sys.path == [str(code)]


def test_symlinks_cannot_launder_data_as_code(import_layout):
    code, data, dependency = import_layout
    (code / 'data-alias').symlink_to(data, target_is_directory=True)
    (data / 'code-alias').symlink_to(dependency, target_is_directory=True)
    sys.path[:] = [str(code/'data-alias'), str(data/'code-alias')]
    python_imports.harden_import_paths()
    assert sys.path == [str(dependency)]


def test_invalid_entries_fail_closed_without_losing_valid_code(import_layout):
    code, _, _ = import_layout
    loop = code / 'loop'
    loop.symlink_to(loop)
    sys.path[:] = [None, 42, '', '.', 'bad\x00path', str(code)+'/bad\x00path',
                   str(loop), str(code/'missing'), str(code)]
    python_imports.harden_import_paths()
    assert sys.path == [str(code)]


def test_cached_importer_for_removed_path_is_never_called(import_layout):
    import importlib
    code, data, _ = import_layout
    class PoisonImporter:
        def find_spec(self, *args, **kwargs):
            pytest.fail('removed path retained its cached importer')
    sys.path[:] = [str(data), str(code)]
    sys.path_importer_cache[str(data)] = PoisonImporter()
    python_imports.harden_import_paths()
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module('_raptor_removed_importer_probe')


def test_zip_imports_keep_protected_archive_and_reject_data_archive(import_layout):
    import importlib
    import zipfile
    _, data, dependency = import_layout
    name = '_raptor_zip_path_probe'
    good = dependency / 'library.zip'
    bad = data / 'library.zip'
    with zipfile.ZipFile(good, 'w') as archive:
        archive.writestr(name+'.py', 'VALUE = 42\n')
    with zipfile.ZipFile(bad, 'w') as archive:
        archive.writestr(name+'.py', 'raise AssertionError("data ZIP executed")\n')
    sys.path[:] = [str(bad), str(good)]
    try:
        python_imports.harden_import_paths()
        assert importlib.import_module(name).VALUE == 42
        assert sys.path == [str(good)]
    finally:
        sys.modules.pop(name, None)


def test_namespace_package_uses_only_protected_portion(import_layout):
    import importlib
    _, data, dependency = import_layout
    name = '_raptor_namespace_path_probe'
    for base in (data, dependency):
        (base/name).mkdir()
    (dependency/name/'safe.py').write_text('VALUE = 42\n')
    (data/name/'unsafe.py').write_text('raise AssertionError("data namespace executed")\n')
    sys.path[:] = [str(data), str(dependency)]
    try:
        python_imports.harden_import_paths()
        assert importlib.import_module(name+'.safe').VALUE == 42
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(name+'.unsafe')
    finally:
        for module in (name, name+'.safe', name+'.unsafe'):
            sys.modules.pop(module, None)


def test_hardening_is_idempotent(import_layout):
    code, data, _ = import_layout
    sys.path[:] = [str(data), str(code)]
    python_imports.harden_import_paths()
    assert python_imports.harden_import_paths() == ()
    assert sys.path == [str(code)]


def test_readonly_probe_errors_deny_path(monkeypatch, tmp_path):
    def denied(path):
        raise OSError('mount information unavailable')
    monkeypatch.setattr(os, 'statvfs', denied)
    assert not python_imports._read_only(tmp_path)


@pytest.mark.parametrize('force_empty_bootstrap', [False, True])
def test_forged_marker_in_fresh_helper_fails_with_actionable_message(tmp_path, force_empty_bootstrap):
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    if not force_empty_bootstrap:
        try:
            install_guard.verify_inside()
        except (OSError, RuntimeError, ValueError):
            pass  # The helper must reject this unprotected process state.
        else:
            pytest.skip('process already satisfies installation-protection checks; marker is not forged')
    env = dict(PATH=os.defpath, HOME=str(tmp_path), TMPDIR=str(tmp_path),
               RAPTOR_OUT_DIR=str(tmp_path/'out'), RAPTOR_REGISTRY_HOME=str(tmp_path/'registry'),
               _RAPTOR_TRUSTED='1', RAPTOR_INSTALL_PROTECTED='1')
    command = [sys.executable, '-I', str(root/'libexec/raptor-project-manager'), '--help']
    if force_empty_bootstrap:
        # Reproduce a fully writable host even when the test runner itself
        # exposes read-only stdlib mounts. Never rely on its mount layout.
        code = ('import sys; sys.path.insert(0, sys.argv[1]); '
                'from core.security import python_imports; '
                'python_imports._read_only = lambda path: False; '
                'import core.startup.process_init')
        command = [sys.executable, '-I', '-c', code, str(root)]
    result = subprocess.run(command,
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert 'restart through bin/raptor --protect-install' in result.stderr, result.stderr
    assert 'Traceback' not in result.stderr, result.stderr

"""Frida discovery must find installed packages without running their code."""
import json
from pathlib import Path
import sys

import pytest

from core.security.python_probe import run_python_probe
from packages.frida import sandboxed


from core.testing.module_bindings import patch_module_attribute


from types import ModuleType

_discovery_imports = ModuleType("discovery_fixture_imports")


@pytest.fixture(autouse=True)
def _owned_discovery_imports(monkeypatch):
    import packages.frida.sandboxed as owner
    import shutil
    from core.testing.module_views import scoped_function_imports

    with scoped_function_imports(owner, ('_find_frida_site',), {'shutil': shutil}) as imports:
        try:
            monkeypatch.setitem(globals(), "_discovery_imports", imports)
            yield
        finally:
            monkeypatch.undo()



def test_discovery_does_not_execute_target_frida(tmp_path, monkeypatch):
    marker = tmp_path/'executed'
    (tmp_path/'frida.py').write_text(
        f'from pathlib import Path\nPath({str(marker)!r}).write_text("bad")\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('PYTHONPATH', str(tmp_path))
    sandboxed._find_frida_site()
    assert not marker.exists()


def test_user_site_discovery_never_imports_package_init(tmp_path, monkeypatch):
    home = tmp_path/'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    executable = getattr(sys, '_base_executable', None) or sys.executable
    result = run_python_probe(executable,
        'import json, site; print(json.dumps(site.getusersitepackages()))', timeout=10)
    assert result.returncode == 0, result.stderr
    site = Path(json.loads(result.stdout))
    assert site.is_relative_to(home)
    package = site/'frida'
    package.mkdir(parents=True)
    marker = package/'executed'
    (package/'__init__.py').write_text(
        f'from pathlib import Path\nPath({str(marker)!r}).write_text("bad")\n'
        'raise RuntimeError("discovery must not initialize frida")\n')
    patch_module_attribute(monkeypatch, sandboxed, 'sys', 'executable', executable)
    assert sandboxed._find_frida_site() == str(site.resolve())
    assert not marker.exists()


def test_runner_finds_cli_bindings_for_explicit_attach(tmp_path, monkeypatch):
    from packages.frida import runner
    site = tmp_path/'installed-bindings'
    site.mkdir()
    (site/'frida.py').write_text('FIXTURE_BINDING = 42\n')
    monkeypatch.setattr(sandboxed, '_find_frida_site', lambda: str(site))
    monkeypatch.delitem(sys.modules, 'frida', raising=False)
    monkeypatch.setattr(sys, 'path', [])
    monkeypatch.setattr(sys, 'path_importer_cache', dict(sys.path_importer_cache))
    try:
        module = runner._import_frida()
        assert module.FIXTURE_BINDING == 42
        assert str(site) in sys.path
    finally:
        sys.modules.pop('frida', None)


@pytest.mark.parametrize('error', ['ImportError', 'RuntimeError'])
def test_runner_cleans_failed_binding_path(tmp_path, monkeypatch, error):
    from packages.frida import runner
    site = tmp_path/'broken-bindings'
    site.mkdir()
    (site/'frida.py').write_text(f'raise {error}("broken fixture bindings")\n')
    monkeypatch.setattr(sandboxed, '_find_frida_site', lambda: str(site))
    monkeypatch.delitem(sys.modules, 'frida', raising=False)
    monkeypatch.setattr(sys, 'path', [])
    with pytest.raises(runner.FridaUnavailable if error == 'ImportError' else RuntimeError):
        runner._import_frida()
    assert str(site) not in sys.path


@pytest.mark.parametrize('interpreter', [
    '/home/operator/pipx/venvs/frida/bin/python',
    '/Users/operator/pipx/venvs/frida/bin/python',
    '/Library/Frameworks/Python.framework/Versions/3.14/bin/python3',
])
def test_cli_interpreter_discovery_supports_linux_and_macos_paths(tmp_path, monkeypatch, interpreter):
    from types import SimpleNamespace
    from core.security import python_probe
    cli = tmp_path/'frida'
    cli.write_text('#!'+interpreter+'\n')
    site = tmp_path/'site-packages'
    (site/'frida').mkdir(parents=True)
    (site/'frida/__init__.py').write_text('')
    patch_module_attribute(monkeypatch, sandboxed, 'sys', 'executable', '/nonexistent-fixture-python')
    patch_module_attribute(monkeypatch, _discovery_imports, 'shutil', 'which', lambda name: str(cli) if name == 'frida' else None)
    patch_module_attribute(monkeypatch, sandboxed, 'os.path', 'isfile', lambda path: path == interpreter)
    def probe(executable, source, **kwargs):
        assert executable == interpreter
        assert kwargs['timeout'] == 5
        return SimpleNamespace(returncode=0, stdout=str(site/'frida/__init__.py').encode())
    monkeypatch.setattr(python_probe, 'run_python_probe', probe)
    assert sandboxed._find_frida_site() == str(site)

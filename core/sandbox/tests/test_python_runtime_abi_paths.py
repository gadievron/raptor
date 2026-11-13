"""HOME narrowing follows the running interpreter's library ABI suffix."""
import sysconfig
from types import SimpleNamespace

import pytest

from core.sandbox import python_paths
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize('abi_thread', ['', 't', None], ids=['gil', 'free-threaded', 'legacy'])
def test_home_runtime_uses_abi_library_directory(tmp_path, monkeypatch, abi_thread):
    home = tmp_path / 'home'
    (home / 'bin').mkdir(parents=True)
    suffix = abi_thread or ''
    library = home / 'lib' / ('python3.14' + suffix)
    library.mkdir(parents=True)
    opposite = home / 'lib' / ('python3.14' if suffix else 'python3.14t')
    opposite.mkdir()
    (home / 'pyvenv.cfg').write_text('home = /usr/bin\n')
    monkeypatch.setattr(python_paths, '_home_roots', lambda: (home,))
    monkeypatch.setattr(python_paths, 'sys', SimpleNamespace(
        prefix=str(home), exec_prefix=str(home), base_prefix='/usr',
        base_exec_prefix='/usr', executable=str(home / 'bin/python3'),
    ))
    original = sysconfig.get_config_var
    with scoped_function_imports(python_paths, ('python_runtime_tool_paths',),
                                 {'sysconfig': sysconfig}) as imports:
        imports.sysconfig.get_python_version = lambda: '3.14'
        imports.sysconfig.get_config_var = lambda name: abi_thread if name == 'abi_thread' else None
        paths = python_paths.python_runtime_tool_paths()
    assert sysconfig.get_config_var is original
    assert str(library) in paths
    assert str(opposite) not in paths
    assert str(home / 'pyvenv.cfg') in paths
    assert str(home / 'bin') in paths
    assert str(home) not in paths and str(home / 'lib') not in paths


def test_free_threaded_library_alias_cannot_expose_home(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    (home / 'lib').mkdir(parents=True)
    alias = home / 'lib/python3.14t'
    alias.symlink_to(home, target_is_directory=True)
    monkeypatch.setattr(python_paths, '_home_roots', lambda: (home,))
    monkeypatch.setattr(python_paths, 'sys', SimpleNamespace(prefix=str(home)))
    with scoped_function_imports(python_paths, ('python_runtime_tool_paths',),
                                 {'sysconfig': sysconfig}) as imports:
        imports.sysconfig.get_python_version = lambda: '3.14'
        imports.sysconfig.get_config_var = lambda name: 't' if name == 'abi_thread' else None
        paths = python_paths.python_runtime_tool_paths()
    assert str(home) not in paths and str(alias) not in paths

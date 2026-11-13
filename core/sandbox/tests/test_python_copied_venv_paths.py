"""Copied venv launchers retain narrow, nonexecuting runtime discovery."""

import pytest

from core.sandbox.python_paths import python_tool_paths


@pytest.mark.parametrize('name', ['python', 'python3', 'tool'])
def test_copied_venv_uses_configured_version(tmp_path, monkeypatch, name):
    home = tmp_path / 'home'
    binary = home / 'bin'
    binary.mkdir(parents=True)
    interpreter = binary / 'python3'
    interpreter.write_bytes(b'owned copy; never execute')
    selected = binary / name
    if name == 'python':
        selected.write_bytes(b'owned copy; never execute')
    elif name == 'tool':
        selected.write_text('#!' + str(interpreter) + '\n')
    (home / 'pyvenv.cfg').write_text('home = /usr/bin\nversion = 3.14.2\n')
    library = home / 'lib/python3.14'
    library.mkdir(parents=True)
    (library / 'site-packages').mkdir()
    shared = home / 'lib/libpython3.14.so.1.0'
    shared.write_bytes(b'owned shared runtime')
    (home / '.aws').mkdir()
    monkeypatch.setenv('HOME', str(home))
    paths = python_tool_paths(str(selected))
    assert str(library) in paths
    assert str(shared) in paths
    assert str(home / 'pyvenv.cfg') in paths
    assert str(home) not in paths
    assert str(home / 'lib') not in paths
    assert str(home / '.aws') not in paths


@pytest.mark.parametrize('configuration', [
    None, 'version = ../../secrets\n', 'version = 3.14/../../secrets\n',
    'version = 3.14\n', 'version = ٣.١٤.٢\n',
])
def test_unknown_or_malformed_version_does_not_guess_libraries(tmp_path, configuration):
    binary = tmp_path / 'venv/bin'
    binary.mkdir(parents=True)
    selected = binary / 'python3'
    selected.write_bytes(b'never executed')
    if configuration is not None:
        (binary.parent / 'pyvenv.cfg').write_text(configuration)
    library = binary.parent / 'lib/python3.14'
    library.mkdir(parents=True)
    assert str(library) not in python_tool_paths(str(selected))


def test_oversized_configuration_does_not_supply_version(tmp_path):
    binary = tmp_path / 'venv/bin'
    binary.mkdir(parents=True)
    selected = binary / 'python3'
    selected.write_bytes(b'never executed')
    (binary.parent / 'pyvenv.cfg').write_text('version = 3.14.2\n' + '#' * 5000)
    library = binary.parent / 'lib/python3.14'
    library.mkdir(parents=True)
    assert str(library) not in python_tool_paths(str(selected))


def test_configured_library_alias_cannot_expose_home(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    prefix = tmp_path / 'venv'
    (prefix / 'bin').mkdir(parents=True)
    (prefix / 'lib').mkdir()
    selected = prefix / 'bin/python3'
    selected.write_bytes(b'never executed')
    (prefix / 'pyvenv.cfg').write_text('version = 3.14.2\n')
    alias = prefix / 'lib/python3.14'
    alias.symlink_to(home, target_is_directory=True)
    paths = python_tool_paths(str(selected))
    assert str(alias) not in paths and str(home) not in paths


def test_versioned_binary_takes_precedence_over_configuration(tmp_path):
    binary = tmp_path / 'venv/bin'
    binary.mkdir(parents=True)
    selected = binary / 'python3.14'
    selected.write_bytes(b'never executed')
    (binary.parent / 'pyvenv.cfg').write_text('version = 3.13.9\n')
    expected = binary.parent / 'lib/python3.14'
    other = binary.parent / 'lib/python3.13'
    expected.mkdir(parents=True)
    other.mkdir()
    paths = python_tool_paths(str(selected))
    assert str(expected) in paths and str(other) not in paths


def test_configuration_symlink_does_not_supply_version(tmp_path):
    binary = tmp_path / 'venv/bin'
    binary.mkdir(parents=True)
    selected = binary / 'python3'
    selected.write_bytes(b'never executed')
    metadata = tmp_path / 'metadata'
    metadata.write_text('version = 3.14.2\n')
    (binary.parent / 'pyvenv.cfg').symlink_to(metadata)
    library = binary.parent / 'lib/python3.14'
    library.mkdir(parents=True)
    assert str(library) not in python_tool_paths(str(selected))

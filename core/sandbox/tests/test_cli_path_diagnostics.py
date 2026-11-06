"""CLI path diagnostics stay inert and validation remains atomic."""

import argparse
import logging
import os
from pathlib import Path
from uuid import uuid4

import pytest

from core.sandbox import cli, state
from core.testing.module_state import isolated_module_state
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'
FLAGS = {'readable': '--sandbox-readable-path', 'tool': '--sandbox-tool-path'}
FIELDS = {'readable': '_cli_sandbox_readable_paths', 'tool': '_cli_sandbox_tool_paths'}
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='owned POSIX control paths')


@pytest.fixture
def owned(tmp_path, caplog):
    previous = tmp_path / 'previous'
    previous.mkdir()
    replacements = {
        '_cli_sandbox_profile': None, '_cli_sandbox_disabled': False,
        '_cli_sandbox_disable_consent': None, '_cli_sandbox_audit': False,
        '_cli_sandbox_audit_verbose': False, '_cli_sandbox_audit_budget': None,
        '_cli_sandbox_floor': None,
        '_cli_sandbox_readable_paths': [str(previous)],
        '_cli_sandbox_tool_paths': [str(previous)],
    }
    with isolated_module_state(state, replacements), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / 'state')
        home = tmp_path / 'home'
        home.mkdir()
        patch.setenv('HOME', str(home))
        patch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        caplog.set_level(logging.WARNING, logger=cli.__name__)
        yield home, tuple(replacements)


def paths(owned, kind, layout='control'):
    home, _ = owned
    base = home / ('plain' if layout == 'plain' else CONTROL)
    if layout == 'long':
        base = base / ('a' * 100) / ('b' * 100)
    base.mkdir(parents=True)
    path = base / ('file' if kind == 'readable' else 'directory')
    if kind == 'readable':
        path.write_bytes(b'preserve owned file')
    else:
        path.mkdir()
    return path


def parser_and_args(kind, path):
    parser = argparse.ArgumentParser(prog='owned-cli')
    cli.add_cli_args(parser)
    args = parser.parse_args(['--sandbox', 'full', '--audit', '--audit-budget', '5', FLAGS[kind], str(path)])
    return parser, args


def snapshot(owned):
    _home, names = owned
    refs = {name: getattr(state, name) for name in names}
    values = {name: list(value) if isinstance(value, list) else value for name, value in refs.items()}
    return refs, values


def unchanged(before):
    refs, values = before
    for name, value in refs.items():
        assert getattr(state, name) is value
        assert getattr(state, name) == values[name]


def rejected(owned, endpoint, kind, path, capsys, caplog):
    parser, args = parser_and_args(kind, path)
    before = snapshot(owned)
    caught = None
    try:
        cli.apply_cli_args(args, parser=parser if endpoint == 'parser' else None)
    except (OSError, RuntimeError, ValueError, SystemExit) as error:
        caught = error
    unchanged(before)
    assert [r for r in caplog.records if r.name == cli.__name__] == []
    captured = capsys.readouterr()
    assert captured.out == ''
    if endpoint == 'parser':
        assert isinstance(caught, SystemExit)
        assert caught.code == 2
        message = captured.err.split('owned-cli: error: ', 1)[1].rstrip('\n')
        assert all(c.isprintable() or c == '\n' for c in captured.err)
    else:
        assert isinstance(caught, ValueError)
        assert captured.err == ''
        message = str(caught)
    return message


def safe(message):
    assert all(c.isprintable() for c in message)
    assert len(message) < 900


def path_warnings(caplog, kind):
    label = 'Sandbox read allowlist extended' if kind == 'readable' else 'Sandbox tool paths extended'
    return [r for r in caplog.records if r.name == cli.__name__ and label in r.getMessage()]


@pytest.mark.parametrize('kind', ['readable', 'tool'])
@pytest.mark.parametrize('layout', ['control', 'long'])
@pytest.mark.parametrize('shape', ['one', 'many'])
def test_setter_warning_preserves_complete_independent_list(owned, caplog, kind, layout, shape):
    path = paths(owned, kind, layout)
    values = [str(path)] * (20 if shape == 'many' else 1)
    expected = list(values)
    setter = cli.set_cli_readable_paths if kind == 'readable' else cli.set_cli_tool_paths
    setter(values)
    stored = getattr(state, FIELDS[kind])
    assert stored == expected
    assert stored is not values
    values.append('owned-unpassed-input')
    assert stored == expected
    entries = path_warnings(caplog, kind)
    assert len(entries) == 1 and entries[0].levelno == logging.WARNING
    assert entries[0].exc_info is None
    safe(logging.Formatter('%(message)s').format(entries[0]))


@pytest.mark.parametrize('kind', ['readable', 'tool'])
def test_ascii_many_path_warning_is_bounded(owned, caplog, kind):
    path = paths(owned, kind, 'plain')
    values = [str(path)] * 20
    setter = cli.set_cli_readable_paths if kind == 'readable' else cli.set_cli_tool_paths
    setter(values)
    assert getattr(state, FIELDS[kind]) == values
    entries = path_warnings(caplog, kind)
    assert len(entries) == 1
    message = entries[0].getMessage()
    assert message.isprintable()
    assert len(message) < 900
    assert '...[+' in message


@pytest.mark.parametrize('kind', ['readable', 'tool'])
@pytest.mark.parametrize('endpoint', ['library', 'parser'])
@pytest.mark.parametrize('layout', ['control', 'long'])
def test_missing_path_error_is_inert_and_atomic(owned, caplog, capsys, kind, endpoint, layout):
    path = paths(owned, kind, layout).parent / 'missing'
    message = rejected(owned, endpoint, kind, path, capsys, caplog)
    assert FLAGS[kind] in message
    assert ('does not exist' if kind == 'readable' else 'is not a directory') in message
    safe(message)


@pytest.mark.parametrize('endpoint', ['library', 'parser'])
@pytest.mark.parametrize('layout', ['control', 'long'])
def test_regular_file_remains_invalid_tool_directory(owned, caplog, capsys, endpoint, layout):
    path = paths(owned, 'readable', layout)
    message = rejected(owned, endpoint, 'tool', path, capsys, caplog)
    assert path.read_bytes() == b'preserve owned file'
    assert 'is not a directory' in message
    safe(message)


@pytest.mark.parametrize('kind', ['readable', 'tool'])
@pytest.mark.parametrize('endpoint', ['library', 'parser'])
@pytest.mark.parametrize('layout', ['control', 'long'])
def test_native_unknown_home_uses_validation_contract(owned, caplog, capsys, kind, endpoint, layout):
    path = '~raptor-owned-missing-' + uuid4().hex + '/' + CONTROL
    if layout == 'long':
        path += '/' + 'a' * 100 + '/' + 'b' * 100
    with pytest.raises(RuntimeError):
        Path(path).expanduser()
    message = rejected(owned, endpoint, kind, path, capsys, caplog)
    assert 'cannot inspect' in message
    assert FLAGS[kind] in message
    safe(message)


@pytest.mark.parametrize('kind', ['readable', 'tool'])
@pytest.mark.parametrize('endpoint', ['library', 'parser'])
@pytest.mark.parametrize('layout', ['control', 'long'])
@pytest.mark.parametrize('spelling', ['absolute', 'home'])
def test_valid_paths_keep_native_resolution_and_settings(owned, caplog, kind, endpoint, layout, spelling):
    path = paths(owned, kind, layout)
    home, _names = owned
    argument = path if spelling == 'absolute' else '~/' + str(path.relative_to(home))
    parser, args = parser_and_args(kind, argument)
    cli.apply_cli_args(args, parser=parser if endpoint == 'parser' else None)
    assert getattr(state, FIELDS[kind]) == [str(path.resolve())]
    assert state._cli_sandbox_profile == 'full'
    assert state._cli_sandbox_disabled is False
    assert state._cli_sandbox_audit is True
    assert state._cli_sandbox_audit_budget == 5
    if kind == 'readable':
        assert path.read_bytes() == b'preserve owned file'
    else:
        assert path.is_dir()
    entries = path_warnings(caplog, kind)
    assert len(entries) == 1
    safe(logging.Formatter('%(message)s').format(entries[0]))


@pytest.mark.parametrize('kind', ['readable', 'tool'])
@pytest.mark.parametrize('endpoint', ['library', 'parser'])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_path_protocol_cancellation_propagates(owned, caplog, capsys, kind, endpoint, error_type):
    error = error_type('owned cancellation')

    class CancelledPath(os.PathLike):
        def __fspath__(self):
            raise error

    parser, args = parser_and_args(kind, 'owned-placeholder')
    setattr(args, 'sandbox_readable_paths' if kind == 'readable' else 'sandbox_tool_paths', [CancelledPath()])
    before = snapshot(owned)
    with pytest.raises(error_type) as caught:
        cli.apply_cli_args(args, parser=parser if endpoint == 'parser' else None)
    assert caught.value is error
    unchanged(before)
    assert [r for r in caplog.records if r.name == cli.__name__] == []
    captured = capsys.readouterr()
    assert captured.out == captured.err == ''


@pytest.mark.parametrize('kind', ['readable', 'tool'])
@pytest.mark.parametrize('endpoint', ['library', 'parser'])
def test_plain_missing_path_keeps_exact_message(owned, caplog, capsys, kind, endpoint):
    home, _ = owned
    path = home / 'plain-missing'
    message = rejected(owned, endpoint, kind, path, capsys, caplog)
    label = 'does not exist' if kind == 'readable' else 'is not a directory'
    assert message == f'{FLAGS[kind]} {label}: {path} (resolved to {path.resolve()})'

"""rr replay's mechanical entry point must never fall back to host execution."""

import subprocess
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from core.sandbox import SandboxSetupError
from packages.binary_analysis import rr_replay as module

from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path/'home'
    home.mkdir()
    scratch = tmp_path/'scratch'
    scratch.mkdir()
    trace = tmp_path/'packed-trace'
    trace.mkdir()
    (trace/'version').write_text('fixture')
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setattr(module, 'sys', SimpleNamespace(platform='linux',
        stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr))
    patch_module_attribute(monkeypatch, module, "shutil", "which", lambda name, **kwargs: '/usr/bin/'+name)
    monkeypatch.setattr(module.RaptorConfig, 'get_safe_env', lambda: {
        'PATH': '/usr/bin:/bin', 'TMPDIR': str(scratch), 'RR_TMPDIR': '/host-only'})
    return home, trace, scratch


@pytest.mark.parametrize('interactive', [False, True])
def test_dispatch_scopes_recording_and_private_scratch(setup, monkeypatch, interactive):
    home, trace, scratch = setup
    calls = []
    def dispatch(command, **kwargs):
        calls.append((command, kwargs))
        assert command[1:3] == ['replay', '--serve-files']
        assert str(trace) in command
        assert command.index(str(trace)) < command.index('--')
        assert '-nx' in command and 'set auto-load safe-path /dev/null' in command
        assert kwargs['profile'] == 'rr'
        assert kwargs['target'] == str(trace)
        assert Path(kwargs['output']).parent == scratch
        assert Path(kwargs['output']).is_dir()
        assert kwargs['cwd'] == kwargs['output']
        assert str(home) not in kwargs['tool_paths']
        assert 'RR_TMPDIR' not in kwargs['env']
        if interactive:
            assert kwargs['stdin'] is module.sys.stdin
            assert 'input' not in kwargs
        else:
            assert kwargs['input'] == b'quit\n' and kwargs['capture_output']
        return subprocess.CompletedProcess(command, 0, b'ok', b'')
    monkeypatch.setattr(module, 'run', dispatch)
    result = module.replay(trace, commands=None if interactive else b'quit\n')
    assert result.returncode == 0
    assert len(calls) == 1
    assert not Path(calls[0][1]['output']).exists()
    assert list(scratch.iterdir()) == []


def test_setup_refusal_propagates_and_cleans_scratch(setup, monkeypatch):
    _, trace, scratch = setup
    def refuse(*args, **kwargs):
        raise SandboxSetupError('namespace unavailable')
    monkeypatch.setattr(module, 'run', refuse)
    with pytest.raises(SandboxSetupError, match='namespace unavailable'):
        module.replay(trace, commands=b'quit\n')
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize('override', [False, True])
def test_latest_lookup_resolves_only_selected_trace(setup, monkeypatch, override):
    home, trace, scratch = setup
    base = scratch if override else home/'.local'/'share'/'rr'
    base.mkdir(parents=True, exist_ok=True)
    (base/'latest-trace').symlink_to(trace, target_is_directory=True)
    monkeypatch.delenv('_RR_TRACE_DIR', raising=False)
    monkeypatch.delenv('XDG_DATA_HOME', raising=False)
    if override:
        monkeypatch.setenv('_RR_TRACE_DIR', str(base))
    def dispatch(command, **kwargs):
        assert str(trace) in command
        assert command.index(str(trace)) < command.index('--')
        return subprocess.CompletedProcess(command, 0, b'', b'')
    monkeypatch.setattr(module, 'run', dispatch)
    assert module.replay(commands=b'quit\n').returncode == 0


def test_home_alias_is_refused_before_dispatch(setup, monkeypatch):
    home, _, scratch = setup
    alias = scratch/'alias'
    alias.symlink_to(home, target_is_directory=True)
    def forbidden(*args, **kwargs):
        raise AssertionError('must not dispatch')
    monkeypatch.setattr(module, 'run', forbidden)
    with pytest.raises(SandboxSetupError, match='dedicated recording'):
        module.replay(alias, commands=b'quit\n')


def test_arbitrary_directory_is_not_a_recording(setup):
    _, _, scratch = setup
    with pytest.raises(ValueError, match='not an rr recording'):
        module.replay(scratch, commands=b'quit\n')


def test_nonstandard_gdb_is_pinned_and_its_runtime_is_visible(setup, monkeypatch):
    _, trace, scratch = setup
    prefix = scratch/'gdb-tool'
    executable = prefix/'bin'/'gdb'
    executable.parent.mkdir(parents=True)
    executable.write_text('fixture')
    resource = prefix/'share'/'gdb'
    resource.mkdir(parents=True)
    patch_module_attribute(monkeypatch, module, "shutil", "which", lambda name, **kwargs:
                        str(executable) if name == 'gdb' else '/usr/bin/rr')
    def dispatch(command, **kwargs):
        assert '--debugger='+str(executable) in command
        assert str(executable.parent) in kwargs['tool_paths']
        assert str(resource) in kwargs['tool_paths']
        return subprocess.CompletedProcess(command, 0, b'', b'')
    monkeypatch.setattr(module, 'run', dispatch)
    assert module.replay(trace, commands=b'quit\n').returncode == 0


def test_missing_gdb_is_actionable(setup, monkeypatch):
    _, trace, scratch = setup
    patch_module_attribute(monkeypatch, module, "shutil", "which", lambda name, **kwargs:
                        None if name == 'gdb' else '/usr/bin/rr')
    with pytest.raises(FileNotFoundError, match='GDB not installed'):
        module.replay(trace, commands=b'quit\n')
    assert list(scratch.iterdir()) == []


def test_gdb_runtime_must_not_grant_home(setup, monkeypatch):
    home, trace, _ = setup
    executable = home/'gdb'
    executable.write_text('fixture')
    patch_module_attribute(monkeypatch, module, "shutil", "which", lambda name, **kwargs:
                        str(executable) if name == 'gdb' else '/usr/bin/rr')
    with pytest.raises(SandboxSetupError, match='dedicated tool directory'):
        module.replay(trace, commands=b'quit\n')


@pytest.mark.parametrize('status', [0, 7])
@pytest.mark.parametrize('text', [False, True])
def test_fatal_replay_cannot_hide_behind_gdb_zero_status(setup, monkeypatch, status, text):
    _, trace, scratch = setup
    diagnostics = '[FATAL ./src/ReplayTask.cc:130:validate_regs()]\nregister mismatch\n'
    stderr = diagnostics if text else diagnostics.encode()
    def dispatch(command, **kwargs):
        return subprocess.CompletedProcess(command, status, b'', stderr)
    monkeypatch.setattr(module, 'run', dispatch)
    result = module.replay(trace, commands=b'continue\nquit\n')
    assert result.returncode == (status or 1)
    assert result.stderr == stderr
    assert list(scratch.iterdir()) == []

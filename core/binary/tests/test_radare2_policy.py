"""The interactive wrapper applies the same policy as other hostile parsers."""
import builtins
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

from core.testing.module_views import module_function_view

WRAPPER = Path(__file__).resolve().parents[3] / 'libexec/raptor-r2-sandboxed'
_WRAPPER_GLOBALS = None


@pytest.fixture
def launch(tmp_path, monkeypatch):
    from core import sandbox
    import shutil
    source = tmp_path / 'source'
    source.mkdir()
    binary = source / 'input'
    binary.write_bytes(b'owned')
    output = tmp_path / 'scratch'
    output.mkdir()
    tool = tmp_path / 'installed' / 'bin' / 'r2'
    tool.parent.mkdir(parents=True)
    tool.write_text('#!/bin/sh\nexit 0\n')
    tool.chmod(0o700)
    original = shutil.which
    def which(name, *args, **kwargs):
        return str(tool) if name == 'r2' else original(name, *args, **kwargs)

    private_shutil = module_function_view(shutil, bindings={'which': which})
    inherited_import = builtins.__import__

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'shutil' and level == 0:
            return private_shutil
        return inherited_import(name, globals, locals, fromlist, level)

    private_builtins = dict(vars(builtins), __import__=import_local)
    monkeypatch.setitem(globals(), '_WRAPPER_GLOBALS', {'__builtins__': private_builtins})
    monkeypatch.setattr(sys, 'path', sys.path.copy())
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    monkeypatch.setenv('OUTPUT_DIR', str(output))
    monkeypatch.delenv('R2_TARGET_DIR', raising=False)
    monkeypatch.setattr(sys, 'argv', [str(WRAPPER), '-2', '-q0', str(binary)])
    return sandbox, binary, output, tool


@pytest.mark.parametrize('fresh', [True, False])
def test_full_policy_and_stdio_are_preserved(launch, monkeypatch, fresh):
    from core.sandbox import context
    sandbox, binary, output, tool = launch
    monkeypatch.setattr(context, 'untrusted_fresh_procfs_required', lambda: fresh)
    calls = []
    def run(command, **options):
        calls.append(options)
        assert command[0] == '/usr/bin/env'
        assert command[9:] == [str(tool), '-N', '-2', '-q0', str(binary)]
        assert command[1] == 'TMPDIR=' + str(output)
        assert command[4] == 'HOME=' + str(output / '.home')
        assert options['target'] == options['output'] == options['cwd'] == str(output)
        assert options['readable_paths'] == [str(binary.parent)]
        assert str(tool.parent) in options['tool_paths']
        for name in ('restrict_reads', 'block_network', 'fake_home', 'strict_env',
                     'strip_trust_markers', 'exclude_tmp_baseline', '_untrusted_workload',
                     'sanitise_host_fingerprint'):
            assert options[name] is True, name
        assert options['require_fresh_procfs'] is fresh
        assert options['omit_proc_reads'] is not fresh
        assert options['stdin'] == 0 and options['capture_output'] is False
        assert options['timeout'] == 1800
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(sandbox, 'run', run)
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(WRAPPER), init_globals=_WRAPPER_GLOBALS, run_name='__main__')
    assert exc.value.code == 0 and len(calls) == 1


@pytest.mark.parametrize('kind', ['setup', 'floor'])
def test_isolation_refusal_exits_before_parser(launch, monkeypatch, capsys, kind):
    sandbox, _, _, _ = launch
    error = sandbox.SandboxFloorError if kind == 'floor' else sandbox.SandboxSetupError
    def refuse(*args, **kwargs):
        from core.sandbox.tiers import ContainmentTier
        kwargs = dict(achievable=ContainmentTier.BARE, floor=ContainmentTier.MOUNT_NS) if kind == 'floor' else {}
        raise error('owned refusal \x1b[2J', **kwargs)
    monkeypatch.setattr(sandbox, 'run', refuse)
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(WRAPPER), init_globals=_WRAPPER_GLOBALS, run_name='__main__')
    assert exc.value.code == 101
    stderr = capsys.readouterr().err
    assert 'owned refusal' in stderr and '\x1b' not in stderr


def test_target_hint_cannot_widen_reads(launch, monkeypatch, capsys):
    sandbox, binary, _, _ = launch
    monkeypatch.setenv('R2_TARGET_DIR', str(binary.parent.parent))
    monkeypatch.setattr(sandbox, 'run', lambda *a, **k: pytest.fail('parser started'))
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(WRAPPER), init_globals=_WRAPPER_GLOBALS, run_name='__main__')
    assert exc.value.code == 103
    assert 'must match' in capsys.readouterr().err


def test_loose_input_cannot_admit_home(launch, monkeypatch):
    from core.sandbox import python_paths
    sandbox, binary, _, _ = launch
    monkeypatch.setattr(python_paths, '_home_roots', lambda: (binary.parent,))
    monkeypatch.setattr(sandbox, 'run', lambda *a, **k: pytest.fail('parser started'))
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(WRAPPER), init_globals=_WRAPPER_GLOBALS, run_name='__main__')
    assert exc.value.code == 101

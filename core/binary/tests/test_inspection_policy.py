"""Parser inputs never grant the shared temporary base or account HOME."""

from pathlib import Path
import subprocess

import pytest

from core.binary._inspection_policy import inspection_command, inspection_options

from core.testing.module_bindings import patch_module_attribute


def test_private_reads_and_runtime_are_explicit(tmp_path, monkeypatch):
    from core.sandbox import context
    from core.sandbox import python_paths
    source = tmp_path / 'source'
    source.mkdir()
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    monkeypatch.setattr(python_paths, 'python_tool_paths', lambda tool: ['/owned/tool/lib'])
    monkeypatch.setattr(context, 'untrusted_fresh_procfs_required', lambda: True)
    options = inspection_options(source / 'binary', 'readelf', str(scratch))
    assert options['readable_paths'] == [str(source)]
    assert options['tool_paths'] == ['/owned/tool/lib']
    for name in ('block_network', 'restrict_reads', 'fake_home', 'strict_env',
                 'strip_trust_markers', 'exclude_tmp_baseline',
                 'require_fresh_procfs', '_untrusted_workload'):
        assert options[name] is True
    assert options['omit_proc_reads'] is False
    assert options['cwd'] == options['target'] == options['output'] == str(scratch)
    assert inspection_command(['nm', 'input'], str(scratch)) == [
        '/usr/bin/env', 'TMPDIR=' + str(scratch), 'TEMP=' + str(scratch),
        'TMP=' + str(scratch), 'HOME=' + str(scratch / '.home'),
        'XDG_CONFIG_HOME=' + str(scratch / '.home/.config'),
        'XDG_CACHE_HOME=' + str(scratch / '.home/.cache'),
        'XDG_DATA_HOME=' + str(scratch / '.home/.local/share'),
        'XDG_STATE_HOME=' + str(scratch / '.home/.local/state'), 'nm', 'input']


@pytest.mark.parametrize('kind', ['home', 'ancestor', 'shared', 'symlink'])
def test_broad_input_directory_refused(tmp_path, monkeypatch, kind):
    from core.sandbox import SandboxSetupError, python_paths
    from core.security import env_sanitisation
    home = tmp_path / 'account'
    home.mkdir()
    monkeypatch.setattr(python_paths, '_home_roots', lambda: (home,))
    monkeypatch.setattr(env_sanitisation, 'subprocess_tmpdir', lambda: str(tmp_path / 'tmp'))
    parent = {'home': home, 'ancestor': tmp_path, 'shared': tmp_path / 'tmp'}.get(kind)
    if kind == 'symlink':
        parent = tmp_path / 'alias'
        parent.symlink_to(home, target_is_directory=True)
    with pytest.raises(SandboxSetupError):
        inspection_options(parent / 'binary', 'readelf', str(tmp_path / 'scratch'))


def test_waiver_removes_proc_without_restoring_wide_reads(tmp_path, monkeypatch):
    from core.sandbox import context
    monkeypatch.setattr(context, 'untrusted_fresh_procfs_required', lambda: False)
    options = inspection_options(tmp_path / 'source' / 'binary', 'readelf', str(tmp_path / 'scratch'))
    assert options['require_fresh_procfs'] is False
    assert options['omit_proc_reads'] is True
    assert options['restrict_reads'] and options['_untrusted_workload']


@pytest.mark.parametrize('adapter', ['inspect', 'capture', 'stream', 'demangle'])
def test_adapters_apply_shared_policy_and_cleanup(tmp_path, monkeypatch, adapter):
    from core import sandbox
    from core.analysis import binary_oracle as oracle
    from core.binary.inspect import readelf
    import os
    source = tmp_path / 'source'
    source.mkdir()
    binary = source / 'binary'
    binary.write_bytes(b'owned input')
    calls = []
    def run(command, **options):
        assert command[0] == '/usr/bin/env'
        assert command[1:4] == ['TMPDIR=' + options['output'],
                                'TEMP=' + options['output'], 'TMP=' + options['output']]
        assert command[4] == 'HOME=' + options['output'] + '/.home'
        assert options['restrict_reads'] and options['fake_home']
        assert options['strip_trust_markers'] and options['exclude_tmp_baseline']
        assert Path(options['cwd']).is_dir()
        if adapter == 'demangle':
            assert options['input'] == '_Z3foov'
            assert not options['readable_paths']
        else:
            assert options['stdin'] == subprocess.DEVNULL
            assert options['readable_paths'] == [str(source)]
        calls.append(options)
        if options.get('pass_fds'):
            os.write(options['pass_fds'][0], b'owned stdout\n')
        return subprocess.CompletedProcess(command, 0, 'owned stdout\n', '')
    monkeypatch.setattr(sandbox, 'run', run)
    if adapter == 'inspect':
        assert readelf(binary, '-h').stdout == 'owned stdout\n'
    elif adapter == 'capture':
        assert oracle._run_status(['nm', str(binary)], binary=binary) == ('owned stdout\n', True)
    elif adapter == 'stream':
        assert list(oracle._stream(['objdump', str(binary)], 10, binary)) == ['owned stdout']
    else:
        patch_module_attribute(monkeypatch, oracle, "shutil", "which", lambda tool: '/usr/bin/c++filt')
        assert oracle._demangle_linkage_names(['_Z3foov']) == {'_Z3foov': 'owned stdout'}
    assert len(calls) == 1
    assert not Path(calls[0]['output']).exists()


@pytest.mark.parametrize('adapter', ['inspect', 'capture', 'stream', 'demangle'])
def test_isolation_refusal_is_never_converted_to_empty_evidence(tmp_path, monkeypatch, adapter):
    from core import sandbox
    from core.analysis import binary_oracle as oracle
    from core.binary.inspect import readelf
    def refuse(*args, **kwargs):
        raise sandbox.SandboxSetupError('owned isolation refusal')
    monkeypatch.setattr(sandbox, 'run', refuse)
    binary = tmp_path / 'source' / 'binary'
    with pytest.raises(sandbox.SandboxSetupError, match='owned isolation refusal'):
        if adapter == 'inspect':
            readelf(binary)
        elif adapter == 'capture':
            oracle._run_status(['nm', str(binary)], binary=binary)
        elif adapter == 'stream':
            list(oracle._stream(['objdump', str(binary)], 10, binary))
        else:
            patch_module_attribute(monkeypatch, oracle, "shutil", "which", lambda tool: '/usr/bin/c++filt')
            oracle._demangle_linkage_names(['_Z3foov'])

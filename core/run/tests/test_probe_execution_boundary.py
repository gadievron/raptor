"""Trusted probes must not discover executable configuration in the target cwd."""
import os
from pathlib import Path
import subprocess
import shlex
from types import SimpleNamespace

import pytest

from core.run import toolprobe
from core.startup import init as startup
from packages.fuzzing import capability, cargofuzz_runner


@pytest.fixture
def probe_fixture(tmp_path, monkeypatch):
    project = tmp_path / 'target'
    nested = project / 'nested'
    nested.mkdir(parents=True)
    (project / '.probe-hook').write_text(
        'printf executed > ' + shlex.quote(str(nested / 'probe-executed')) + '\n')
    tools = tmp_path / 'trusted-tools'
    tools.mkdir()
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    home = tmp_path / 'home'
    home.mkdir()
    rustup_home = tmp_path / 'rustup-home'
    rustup_home.mkdir()
    # Trusted fixture launchers model the upward configuration walk performed
    # by Maven/Yarn/rustup and user tool wrappers, even for metadata commands.
    source = '''#!/bin/sh
if [ -f "$HOME/.probe-hook" ]; then . "$HOME/.probe-hook"; fi
folder=$PWD
while :; do
    if [ -f "$folder/.probe-hook" ]; then . "$folder/.probe-hook"; fi
    [ "$folder" = / ] && break
    folder=${folder%/*}
    [ -n "$folder" ] || folder=/
done
case "$0" in
    *cargo-stable) printf 'cargo 1.2.3 stable\\n' ;;
    *rustup) printf 'nightly-fixture\\n' ;;
    *) printf 'fixture version 1.2.3 nightly\\n' ;;
esac
'''
    for name in ('fixture-tool', 'cargo-stable', 'rustup'):
        path = tools / name
        path.write_text(source)
        path.chmod(0o700)
    monkeypatch.chdir(nested)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('PATH', str(tools) + os.pathsep + os.defpath)
    monkeypatch.setenv('XDG_CACHE_HOME', str(tmp_path / 'cache'))
    monkeypatch.setenv('RUSTUP_HOME', str(rustup_home))
    monkeypatch.setattr(capability, 'exec_workdir', lambda: scratch)
    monkeypatch.setattr(cargofuzz_runner, 'exec_workdir', lambda: scratch)
    toolprobe.reset_probe_cache()
    yield SimpleNamespace(tools=tools, nested=nested, scratch=scratch)
    toolprobe.reset_probe_cache()


@pytest.mark.parametrize('consumer', [
    'shared', 'startup', 'cargo-version', 'cargo-list',
    'fuzz-version', 'fuzz-compiler', 'afl-shmem',
])
def test_probe_does_not_execute_target_ancestor_config(probe_fixture, consumer):
    fixture = probe_fixture
    tool = str(fixture.tools / 'fixture-tool')
    if consumer == 'shared':
        result = toolprobe.probe('fixture-tool')
        assert result is not None and result.returncode == 0
    elif consumer == 'startup':
        assert startup._cached_cli_version('fixture-tool') == '1.2.3'
    elif consumer == 'cargo-version':
        assert cargofuzz_runner.nightly_toolchain_arg(tool) == ''
    elif consumer == 'cargo-list':
        assert cargofuzz_runner.nightly_toolchain_arg(str(fixture.tools / 'cargo-stable')) == '+nightly'
    elif consumer == 'fuzz-version':
        assert '1.2.3' in capability._probe_version(tool, ['--version'])
    elif consumer == 'fuzz-compiler':
        assert capability._probe_clang_sanitiser(tool, 'address') is True
    else:
        assert capability._check_macos_afl_shmem(tool) is True
    assert not (fixture.nested / 'probe-executed').exists()
    assert list(fixture.scratch.iterdir()) == [], 'capability scratch leaked'


@pytest.mark.parametrize('consumer', ['shared', 'startup', 'cargo-version', 'fuzz-version'])
def test_neutral_probe_preserves_relative_executable_selection(probe_fixture, monkeypatch, consumer):
    fixture = probe_fixture
    relative = os.path.relpath(fixture.tools, fixture.nested)
    monkeypatch.setenv('PATH', relative + os.pathsep + os.defpath)
    if consumer == 'shared':
        result = toolprobe.probe('fixture-tool')
        assert result is not None and result.returncode == 0
        assert Path(result.path).is_absolute()
    elif consumer == 'startup':
        assert startup._cached_cli_version('fixture-tool') == '1.2.3'
    elif consumer == 'cargo-version':
        assert cargofuzz_runner.nightly_toolchain_arg(relative + '/fixture-tool') == ''
    else:
        assert '1.2.3' in capability._probe_version(relative + '/fixture-tool', ['--version'])
    assert not (fixture.nested / 'probe-executed').exists()


def test_cargo_probe_pins_relative_rustup_home(probe_fixture, monkeypatch):
    fixture = probe_fixture
    home = fixture.nested / 'selected-rustup-home'
    home.mkdir()
    monkeypatch.setenv('RUSTUP_HOME', 'selected-rustup-home')
    calls = []
    def capture(command, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(command, 0, 'nightly', '')
    monkeypatch.setattr(cargofuzz_runner.subprocess, 'run', capture)
    assert cargofuzz_runner.nightly_toolchain_arg(str(fixture.tools / 'fixture-tool')) == ''
    assert calls[0]['cwd'] == os.sep
    assert calls[0]['env']['RUSTUP_HOME'] == str(home)


@pytest.mark.parametrize('consumer', ['shared', 'startup'])
def test_probe_config_failure_never_inherits_ambient_secrets(probe_fixture, monkeypatch, consumer):
    from core.config import RaptorConfig
    def unavailable():
        raise RuntimeError('configuration unavailable')
    monkeypatch.setattr(RaptorConfig, 'get_safe_env', unavailable)
    monkeypatch.setenv('PROBE_PRIVATE_API_KEY', 'disposable-secret')
    calls = []
    def capture(command, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(command, 0, 'fixture 1.2.3', '')
    monkeypatch.setattr(toolprobe.subprocess, 'run', capture)
    if consumer == 'shared':
        assert toolprobe.probe('fixture-tool').returncode == 0
    else:
        assert startup._cached_cli_version('fixture-tool') == '1.2.3'
    assert calls[0]['cwd'] == os.sep
    assert calls[0]['env'] is not None
    assert 'PROBE_PRIVATE_API_KEY' not in calls[0]['env']


@pytest.mark.parametrize('consumer', ['shared', 'startup'])
def test_probe_strips_internal_dispatch_markers(probe_fixture, monkeypatch, consumer):
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    monkeypatch.setenv('CLAUDECODE', '1')
    calls = []
    def capture(command, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(command, 0, 'fixture 1.2.3', '')
    monkeypatch.setattr(toolprobe.subprocess, 'run', capture)
    if consumer == 'shared':
        assert toolprobe.probe('fixture-tool').returncode == 0
    else:
        assert startup._cached_cli_version('fixture-tool') == '1.2.3'
    for marker in ('CLAUDECODE', '_RAPTOR_TRUSTED', 'RAPTOR_DIR'):
        assert marker not in calls[0]['env']


@pytest.mark.parametrize('consumer', ['cargo-version', 'cargo-list', 'fuzz-version', 'fuzz-compiler', 'afl-shmem'])
def test_host_fuzz_probe_ignores_shared_home_configuration(probe_fixture, monkeypatch, consumer):
    fixture = probe_fixture
    poison = fixture.nested / 'shared-home'
    poison.mkdir()
    marker = fixture.nested / 'home-hook-executed'
    (poison / '.probe-hook').write_text('printf executed > ' + shlex.quote(str(marker)) + '\n')
    # Model the scrubber's host-shared HOME fallback without planting files
    # in the real /tmp. Production must replace this value with private HOME.
    from packages.fuzzing.env_hygiene import scrub_identity_env
    def scrub(env):
        env = scrub_identity_env(env)
        env['HOME'] = str(poison)
        return env
    monkeypatch.setattr(capability, 'scrub_identity_env', scrub)
    monkeypatch.setattr(cargofuzz_runner, 'scrub_identity_env', scrub)
    tool = str(fixture.tools / 'fixture-tool')
    if consumer == 'cargo-version':
        assert cargofuzz_runner.nightly_toolchain_arg(tool) == ''
    elif consumer == 'cargo-list':
        assert cargofuzz_runner.nightly_toolchain_arg(str(fixture.tools / 'cargo-stable')) == '+nightly'
    elif consumer == 'fuzz-version':
        assert '1.2.3' in capability._probe_version(tool, ['--version'])
    elif consumer == 'fuzz-compiler':
        assert capability._probe_clang_sanitiser(tool, 'address') is True
    else:
        assert capability._check_macos_afl_shmem(tool) is True
    assert not marker.exists()


def test_cargo_probe_retires_private_home_on_timeout(probe_fixture, monkeypatch):
    fixture = probe_fixture
    homes = []
    def timeout(command, **kwargs):
        home = Path(kwargs['env']['HOME'])
        homes.append(home)
        (home / 'owned-cache').write_text('fixture cache')
        assert home != Path('/tmp')
        raise subprocess.TimeoutExpired(command, 10)
    monkeypatch.setattr(cargofuzz_runner.subprocess, 'run', timeout)
    assert cargofuzz_runner.nightly_toolchain_arg(str(fixture.tools / 'fixture-tool')) is None
    assert homes and not homes[0].exists()

"""Strict scans refuse before work; default/full behavior stays unchanged."""
import importlib.util
from pathlib import Path
import sys

import pytest

from core.sandbox import preflight, probes, seccomp
from core.sandbox.errors import SandboxSetupError


from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def backends(monkeypatch):
    patch_module_attribute(monkeypatch, preflight, 'sys', 'platform', 'linux')
    calls = []
    flags = dict(network=True, mount=True, seccomp=True, seatbelt=True)
    for module, name, key in (
        (probes, 'check_net_available', 'network'),
        (probes, 'check_mount_available', 'mount'),
        (seccomp, 'check_seccomp_available', 'seccomp'),
        (probes, 'check_seatbelt_available', 'seatbelt'),
    ):
        def probe(key=key):
            calls.append(key)
            return flags[key]
        monkeypatch.setattr(module, name, probe)
    monkeypatch.setattr(probes, 'mount_unavailable_reason',
                        lambda: ('mounts refused', 'inspect the execution environment'))
    return flags, calls


@pytest.mark.parametrize('argv', [
    [], ['--sandbox=full'], ['--sandbox=none'], ['--no-sandbox'],
    ['--sandbox=network-only'], ['--sandbox=debug'],
    ['--sandbox=strict', '--help'], ['--sandbox=strict', '-h'],
])
def test_existing_profile_and_help_behavior_is_unchanged(backends, argv):
    _, calls = backends
    preflight.preflight_scan_cli(argv)
    assert calls == []


@pytest.mark.parametrize('argv', [['--sandbox', 'strict'], ['--sandbox=strict']])
def test_strict_checks_actual_backends(backends, argv):
    _, calls = backends
    preflight.preflight_scan_cli(argv)
    assert calls == ['network', 'mount', 'seccomp']


@pytest.mark.parametrize('backend', ['network', 'mount', 'seccomp'])
def test_strict_refuses_missing_backend(backends, backend):
    flags, _ = backends
    flags[backend] = False
    with pytest.raises(SandboxSetupError, match="sandbox profile 'strict'"):
        preflight.preflight_scan_cli(['--sandbox=strict'])


def test_strict_collects_multiple_missing_requirements(backends):
    flags, _ = backends
    flags.update(network=False, seccomp=False)
    with pytest.raises(SandboxSetupError) as error:
        preflight.preflight_scan_cli(['--sandbox=strict'])
    for name in ('unmet requirements', 'namespace', 'mount-namespace', 'seccomp'):
        assert name in str(error.value)


def test_separator_data_cannot_change_strict_policy(backends):
    flags, _ = backends
    flags['network'] = False
    with pytest.raises(SandboxSetupError):
        preflight.preflight_scan_cli(['--sandbox=strict', '--', '--no-sandbox', '--help'])


@pytest.mark.parametrize('available', [False, True])
def test_macos_uses_seatbelt_without_linux_requirements(backends, monkeypatch, available):
    flags, calls = backends
    patch_module_attribute(monkeypatch, preflight, 'sys', 'platform', 'darwin')
    flags['seatbelt'] = available
    if available:
        preflight.preflight_scan_cli(['--sandbox=strict'])
    else:
        with pytest.raises(SandboxSetupError, match='seatbelt'):
            preflight.preflight_scan_cli(['--sandbox=strict'])
    assert calls == ['seatbelt']


def _load(name, relative):
    path = Path(__file__).resolve().parents[3] / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cli_refuses_before_lifecycle_or_worker(backends, monkeypatch, capsys):
    cli = _load('strict_scan_cli_fixture', 'raptor.py')
    flags, _ = backends
    flags['network'] = False
    monkeypatch.setattr(cli, '_run_with_lifecycle',
                        lambda *a, **kw: pytest.fail('scanner worker started'))
    assert cli.mode_scan(['--repo', '/unused', '--sandbox=strict']) == 3
    output = capsys.readouterr()
    assert output.out == ''
    assert 'scan refused' in output.err


def test_direct_worker_refuses_before_target_or_output_work(backends, monkeypatch):
    scanner = _load('strict_scan_worker_fixture', 'packages/static-analysis/scanner.py')
    flags, _ = backends
    flags['network'] = False
    monkeypatch.setattr(sys, 'argv', ['scanner.py', '--repo', '/unused', '--sandbox=strict'])
    monkeypatch.setattr(scanner, 'clone_repository',
                        lambda *a, **kw: pytest.fail('target clone started'))
    monkeypatch.setattr(scanner, 'scratch_dir',
                        lambda *a, **kw: pytest.fail('scan scratch allocated'))
    monkeypatch.setattr(scanner, 'maybe_start_orphan_watchdog',
                        lambda *a, **kw: pytest.fail('worker work started'))
    with pytest.raises(SandboxSetupError):
        scanner.main()

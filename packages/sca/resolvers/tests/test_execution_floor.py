"""Dependency resolution can execute target code; enforce the untrusted floor."""
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import context, state, tiers
from core.sandbox.errors import SandboxFloorError
from packages.sca.resolvers import _run
from packages.sca.resolvers.gradle import GradleResolver


@pytest.fixture
def clean_policy(monkeypatch):
    # Override the resolver suite's broad consent fixture for these policy tests.
    monkeypatch.delenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', raising=False)
    monkeypatch.setattr(state, '_cli_sandbox_floor', None)
    monkeypatch.setattr(state, '_project_sandbox_floor', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    monkeypatch.setattr(context, '_host_consented_floor', lambda: None)


@pytest.mark.parametrize('lane', ['networked', 'offline', 'empty-hosts'])
@pytest.mark.parametrize('policy,refused', [
    ('default', True), ('flag-landlock', False), ('project-landlock', False),
    ('env-landlock', False), ('flag-raises-env', True), ('project-raises-env', True),
    ('flag-none', True),
])
def test_resolver_obeys_real_floor_resolution(tmp_path, monkeypatch, clean_policy, lane, policy, refused):
    monkeypatch.setattr(context, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(tiers, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(context, 'check_net_available', lambda: True)
    monkeypatch.setattr(context, 'check_seccomp_available', lambda: True)
    monkeypatch.setattr('core.sandbox.seccomp.check_seccomp_available', lambda: True)
    if policy in ('env-landlock', 'flag-raises-env', 'project-raises-env'):
        monkeypatch.setenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', '1')
    if policy.startswith('flag-'):
        monkeypatch.setattr(state, '_cli_sandbox_floor', {
            'flag-landlock': 'landlock', 'flag-raises-env': 'mount-ns', 'flag-none': 'none'}[policy])
    if policy.startswith('project-'):
        monkeypatch.setattr(state, '_project_sandbox_floor',
                            'landlock' if policy == 'project-landlock' else 'mount-ns')
    marker = tmp_path / 'executed'
    calls = []
    def reduced_backend(cmd, **kwargs):
        calls.append(kwargs)
        assert kwargs['_untrusted_workload'] is True
        assert kwargs['restrict_reads'] is True and kwargs['fake_home'] is True
        assert kwargs['strict_env'] is True and kwargs['strip_trust_markers'] is True
        assert kwargs['stdin'] == subprocess.DEVNULL and kwargs['start_new_session'] is True
        assert kwargs['target'] == str(tmp_path) and kwargs['output'] != str(tmp_path)
        if lane == 'networked':
            assert kwargs['proxy_hosts'] == ['registry.example']
            assert kwargs['require_proxy_netns'] is True
            assert kwargs['proxy_allowed_ports'] == [443]
        else:
            assert kwargs['block_network'] is True
        explicit, source = context._explicit_untrusted_floor()
        floor, _ = tiers.resolve_call_floor(operator_disabled=False,
            require_fresh_procfs=kwargs['require_fresh_procfs'],
            untrusted_workload=kwargs['_untrusted_workload'],
            waiver_active=context._degraded_untrusted_waiver(),
            explicit_floor=explicit, explicit_source=source)
        tiers.assert_floor(tiers.ContainmentTier.LANDLOCK_ONLY, floor, lane='resolver test backend')
        marker.write_text('executed only after floor enforcement')
        return subprocess.CompletedProcess(cmd, 0, '', '')
    monkeypatch.setattr(context, 'run', reduced_backend)
    def invoke():
        return _run(['/bin/true'], cwd=tmp_path, timeout=5,
                    proxy_hosts=[] if lane == 'empty-hosts' else ['registry.example'],
                    block_network=lane == 'offline')
    if refused:
        with pytest.raises(SandboxFloorError):
            invoke()
        assert not marker.exists()
    else:
        assert invoke().returncode == 0
        assert marker.exists()
    assert len(calls) == 1
    assert not Path(calls[0]['output']).exists(), 'per-call scratch was not retired'


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
def test_gradle_wrapper_refused_before_execution_without_isolation(tmp_path, monkeypatch, clean_policy, platform):
    monkeypatch.setattr(context, 'sys', SimpleNamespace(platform=platform))
    monkeypatch.setattr(tiers, 'sys', SimpleNamespace(platform=platform))
    monkeypatch.setattr(context, 'check_seccomp_available', lambda: True)
    monkeypatch.setattr('core.sandbox.seccomp.check_seccomp_available', lambda: True)
    monkeypatch.setattr(context, 'check_net_available', lambda: False)
    monkeypatch.setattr(context, 'check_seatbelt_available', lambda: False)
    monkeypatch.setattr(GradleResolver, 'is_available', lambda self: False)
    monkeypatch.setattr(GradleResolver, 'proxy_hosts', property(lambda self: ['registry.example']))
    (tmp_path / 'build.gradle').write_text('// target-supplied build code')
    wrapper = tmp_path / 'gradlew'
    wrapper.write_text('#!/bin/sh\nprintf executed > escaped\n')
    wrapper.chmod(0o700)
    def forbidden(*args, **kwargs):
        raise AssertionError('backend reached despite missing untrusted isolation')
    monkeypatch.setattr(context, 'run', forbidden)
    with pytest.raises(SandboxFloorError):
        GradleResolver().dry_run(tmp_path)
    assert not (tmp_path / 'escaped').exists()


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize('networked', [False, True])
def test_native_resolver_contains_target_script(tmp_path, monkeypatch, clean_policy, networked):
    if sys.platform == 'linux':
        from core.sandbox.probes import check_mount_available, check_net_available
        if not check_mount_available() or not check_net_available():
            pytest.skip('native Linux mount and network namespaces required')
    elif sys.platform == 'darwin':
        if not context.check_seatbelt_available():
            pytest.skip('native macOS Seatbelt required')
    else:
        pytest.skip('Linux or macOS required')
    source = tmp_path / 'source'
    source.mkdir()
    secret = tmp_path / 'operator-secret'
    secret.write_text('private')
    outside = tmp_path / 'outside-write'
    script = '''
if ( : < "$1" ) 2>/dev/null; then echo 'private read allowed'; exit 10; fi
# Linux may recreate this parent in private tmpfs; verify host state below.
( printf shadow > "$2" ) 2>/dev/null || :
[ -z "${_RAPTOR_TRUSTED-}${CLAUDECODE-}${RAPTOR_DIR-}" ] || exit 12
if read value; then exit 13; fi
printf scratch > "$HOME/owned-scratch"
printf contained
'''
    result = _run(['/bin/sh', '-c', script, 'fixture', str(secret), str(outside)],
                  cwd=source, timeout=30,
                  proxy_hosts=['registry.example'] if networked else [],
                  env={'PATH': '/usr/bin:/bin', '_RAPTOR_TRUSTED': '1',
                       'CLAUDECODE': '1', 'RAPTOR_DIR': str(source)})
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'contained'
    assert not outside.exists() and secret.read_text() == 'private'
    info = result.sandbox_info
    assert info['restrict_reads'] is True
    assert info['containment_tier'] == ('seatbelt' if sys.platform == 'darwin' else 'mount-ns')


@pytest.mark.parametrize('probe', ['availability', 'yarn-major'])
def test_version_probe_cannot_load_target_configuration(tmp_path, monkeypatch, probe):
    from packages.sca.resolvers import _check_tool
    from packages.sca.resolvers.yarn import _detect_major_version
    # A trusted fixture launcher models Maven/Yarn's upward configuration
    # discovery. The target config would execute before a version is printed.
    tools = tmp_path / 'trusted-tools'
    tools.mkdir()
    tool = tools / 'yarn'
    tool.write_text("""#!/bin/sh
folder=$PWD
while :; do
    if [ -f "$folder/.probe-hook" ]; then . "$folder/.probe-hook"; fi
    [ "$folder" = / ] && break
    folder=${folder%/*}
    [ -n "$folder" ] || folder=/
done
printf '1.22.0\\n'
""")
    tool.chmod(0o700)
    project = tmp_path / 'hostile-project'
    nested = project / 'nested'
    nested.mkdir(parents=True)
    (project / '.probe-hook').write_text('printf executed > "$PWD/probe-executed"\n')
    monkeypatch.chdir(nested)
    monkeypatch.setenv('PATH', str(tools) + ':/usr/bin:/bin')
    if probe == 'availability':
        assert _check_tool([str(tool), '--version']) is True
    else:
        assert _detect_major_version() == 1
    assert not (nested / 'probe-executed').exists()

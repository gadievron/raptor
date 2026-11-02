"""Repository build execution must carry the existing untrusted floor."""
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.build.build_detector import BuildSystem
from core.sandbox import context, state, tiers
from core.sandbox.errors import SandboxFloorError
from packages.codeql.database_manager import DatabaseManager


@pytest.fixture
def create(tmp_path, monkeypatch):
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.codeql_cli = '/usr/bin/codeql'
    manager.db_root = tmp_path / 'cache'
    manager.db_root.mkdir()
    repo = tmp_path / 'repo'
    repo.mkdir()
    monkeypatch.setattr(manager, 'get_cached_database', lambda *a, **k: None)
    monkeypatch.setattr(manager, 'compute_repo_hash', lambda *a, **k: 'abc')
    monkeypatch.setattr(manager, 'get_database_dir', lambda *a, **k: manager.db_root/'abc'/'db')
    monkeypatch.setattr(manager, 'supports_buildless', lambda *a, **k: (True, 'supported'))
    monkeypatch.setattr(manager, '_buildless_fallback', lambda *a, **k: None)
    monkeypatch.setattr(context, '_host_consented_floor', lambda: None)
    monkeypatch.setattr(state, '_cli_sandbox_floor', None)
    monkeypatch.setattr(state, '_project_sandbox_floor', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    monkeypatch.delenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', raising=False)
    def invoke(language='cpp', traced=True, command='make && true'):
        build = BuildSystem(type='make', command=command, working_dir=repo,
                            env_vars={}, confidence=1.0, detected_files=[])
        return manager.create_database(repo, language, build, traced_build=traced)
    return SimpleNamespace(manager=manager, repo=repo, invoke=invoke)


@pytest.mark.parametrize('language,traced,command,buildless_supported,executes', [
    ('cpp', True, 'make && true', True, True),
    ('cpp', False, 'make && true', True, False),
    ('java', False, 'make', True, False),
    ('java', False, '', False, True),
    ('go', False, '', True, True),
    ('javascript', False, '', True, False),
    ('javascript', False, 'make', True, True),
    ('python', True, '', True, False),
])
def test_only_actual_builds_receive_untrusted_policy(create, monkeypatch,
        language, traced, command, buildless_supported, executes):
    import core.sandbox
    monkeypatch.setattr(create.manager, 'supports_buildless',
                        lambda *a, **k: (buildless_supported, 'fixture'))
    calls = []
    def observe(cmd, **kwargs):
        calls.append(kwargs)
        cache_flags = [value for value in cmd if value.startswith('--common-caches=')]
        assert bool(cache_flags) is executes
        if executes:
            assert cache_flags == ['--common-caches='+str(Path(kwargs['output'])/'.home'/'.codeql')]
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='fixture extraction failed')
    monkeypatch.setattr(core.sandbox, 'run', observe)
    create.invoke(language, traced, command)
    assert len(calls) == 1
    policy = calls[0]
    if executes:
        assert policy['require_fresh_procfs'] is True
        assert policy['omit_proc_reads'] is False
        assert policy['restrict_reads'] is True
        assert policy['fake_home'] is True
        assert policy['writable_paths'] == [str(create.repo)]
        assert policy['target'] is None, 'target= would remount the source read-only'
    else:
        assert policy['target'] == str(create.repo)
        for key in ('require_fresh_procfs', 'omit_proc_reads', 'restrict_reads', 'fake_home', 'writable_paths'):
            assert key not in policy


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
@pytest.mark.parametrize('policy,refused', [
    ('default', True), ('flag', False), ('project', False), ('env', False),
    ('flag-over-env', True), ('disable', False),
])
def test_traced_build_obeys_degraded_backend_policy(create, monkeypatch, platform, policy, refused):
    import core.sandbox
    monkeypatch.setattr(context, 'sys', SimpleNamespace(platform=platform))
    monkeypatch.setattr(tiers, 'sys', SimpleNamespace(platform=platform))
    # An explicit floor of 'none' cannot consent untrusted work to bare.
    refused = refused or (platform == 'darwin' and policy in ('flag', 'project'))
    required = 'mount-ns' if platform == 'linux' else 'seatbelt'
    lowered = 'landlock' if platform == 'linux' else 'none'
    if policy in ('flag', 'flag-over-env'):
        monkeypatch.setattr(state, '_cli_sandbox_floor', required if policy == 'flag-over-env' else lowered)
    if policy == 'project':
        monkeypatch.setattr(state, '_project_sandbox_floor', lowered)
    if policy in ('env', 'flag-over-env'):
        monkeypatch.setenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', '1')
    monkeypatch.setattr(state, '_cli_sandbox_disabled', policy == 'disable')
    marker = create.repo/'executed'
    wrappers = []
    def reduced(cmd, **kwargs):
        wrappers.append(Path(cmd[cmd.index('--command')+1]))
        explicit, source = context._explicit_untrusted_floor()
        fresh = kwargs['require_fresh_procfs']
        assert kwargs['omit_proc_reads'] is (not fresh)
        floor, _ = tiers.resolve_call_floor(operator_disabled=state._cli_sandbox_disabled,
            require_fresh_procfs=fresh, untrusted_workload=False,
            waiver_active=context._degraded_untrusted_waiver(), explicit_floor=explicit, explicit_source=source)
        achievable = tiers.ContainmentTier.LANDLOCK_ONLY if platform == 'linux' else tiers.ContainmentTier.BARE
        tiers.assert_floor(achievable, floor, lane='fixture reduced backend')
        marker.write_text('executed after floor check')
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='fixture extraction failed')
    monkeypatch.setattr(core.sandbox, 'run', reduced)
    if refused:
        with pytest.raises(SandboxFloorError):
            create.invoke()
        assert not marker.exists()
    else:
        create.invoke()
        assert marker.exists()
    assert len(wrappers) == 1
    assert not wrappers[0].exists(), 'wrapper leaked after dispatch/refusal'


@pytest.mark.parametrize('toolchain_is_home', [False, True])
def test_toolchain_grants_are_scoped_and_wrapper_is_cleaned(create, monkeypatch, tmp_path, toolchain_is_home):
    import core.sandbox
    import core.build.toolchain
    home = tmp_path/'operator-home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    toolchain = home if toolchain_is_home else home/'jdk'
    toolchain.mkdir(exist_ok=True)
    monkeypatch.setattr(core.build.toolchain, 'apply_toolchain_env',
                        lambda env, names: env.update(JAVA_HOME=str(toolchain)))
    build = BuildSystem(type='make', command='make && true', working_dir=create.repo,
                        env_vars={}, env_detect=['JAVA_HOME'], confidence=1.0, detected_files=[])
    calls = []
    def observe(cmd, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='fixture extraction failed')
    monkeypatch.setattr(core.sandbox, 'run', observe)
    result = create.manager.create_database(create.repo, 'cpp', build, traced_build=True)
    if toolchain_is_home:
        assert not calls
        assert not result.success
        assert any('dedicated toolchain directory' in error for error in result.errors)
    else:
        assert len(calls) == 1
        assert str(toolchain) in calls[0]['tool_paths']
        assert str(toolchain) not in calls[0]['writable_paths']
        assert str(home) not in calls[0]['tool_paths']
    assert not list((create.manager.db_root/'tmp').glob('.raptor_codeql_build_*'))


def test_real_denied_kernel_refuses_before_buildless_retry(create, monkeypatch):
    import sys
    from core.sandbox.probes import check_net_available
    if sys.platform != 'linux' or check_net_available():
        pytest.skip('requires Linux with namespace creation denied')
    def unexpected_retry(*args, **kwargs):
        raise AssertionError('containment refusal must not retry buildless')
    monkeypatch.setattr(create.manager, '_buildless_fallback', unexpected_retry)
    with pytest.raises(SandboxFloorError):
        create.invoke()
    assert not list((create.manager.db_root/'tmp').glob('.raptor_codeql_build_*'))


@pytest.mark.parametrize('traced', [False, True])
def test_database_cache_inside_source_is_refused_only_for_builds(create, monkeypatch, traced):
    import core.sandbox
    create.manager.db_root = create.repo/'cache'
    create.manager.db_root.mkdir()
    calls = []
    def observe(cmd, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='fixture extraction failed')
    monkeypatch.setattr(core.sandbox, 'run', observe)
    result = create.invoke(traced=traced)
    if traced:
        assert not calls
        assert any('database cache outside the source tree' in error for error in result.errors)
        assert not (create.manager.db_root/'tmp').exists()
    else:
        assert len(calls) == 1
        assert 'writable_paths' not in calls[0]


def test_wrapper_alias_into_writable_source_is_refused(create, monkeypatch):
    import core.sandbox
    wrapper_target = create.repo/'wrapper-alias'
    wrapper_target.mkdir()
    (create.manager.db_root/'tmp').symlink_to(wrapper_target, target_is_directory=True)
    def forbidden(*args, **kwargs):
        raise AssertionError('wrapper alias must be refused before executing CodeQL')
    monkeypatch.setattr(core.sandbox, 'run', forbidden)
    result = create.invoke()
    assert not result.success
    assert any('database cache outside the source tree' in error for error in result.errors)
    assert not list(wrapper_target.iterdir())

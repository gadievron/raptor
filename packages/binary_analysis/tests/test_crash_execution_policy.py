"""Real crash consumers must enforce the target-execution floor before running."""
import subprocess
from types import SimpleNamespace

import pytest

from core.sandbox import context, state, tiers, SandboxFloorError, SandboxSetupError
from packages.binary_analysis import crash_analyser, debugger

_CONSUMERS = ['wrapper', 'wrapper-no-input', 'gdb', 'lldb', 'lldb-fallback', 'asan']


@pytest.fixture
def consumer(tmp_path, request):
    binary = tmp_path / 'target' / 'crashme'
    binary.parent.mkdir()
    binary.write_bytes(b'fixture')
    source = tmp_path / 'input'
    source.write_bytes(b'crash input')
    kind = request.param
    analyser = crash_analyser.CrashAnalyser.__new__(crash_analyser.CrashAnalyser)
    analyser.binary = binary
    if kind.startswith('wrapper'):
        obj = debugger.GDBDebugger(binary)
        invoke = lambda: obj.run_commands(['run', 'backtrace'],
            input_file=source if kind == 'wrapper' else None)
        seam = debugger
    else:
        method = {'gdb': '_run_gdb_analysis_internal', 'lldb': '_run_lldb_analysis',
                  'lldb-fallback': '_run_lldb_fallback', 'asan': '_run_asan_analysis'}[kind]
        invoke = lambda: getattr(analyser, method)(source)
        seam = crash_analyser
    return SimpleNamespace(kind=kind, invoke=invoke, seam=seam, root=binary.parent)


@pytest.mark.parametrize('consumer', _CONSUMERS, indirect=True)
@pytest.mark.parametrize('policy,refused', [
    ('default', True), ('flag-landlock', False), ('project-landlock', False),
    ('env-landlock', False), ('flag-raises-env', True), ('operator-disable', False),
])
def test_consumers_enforce_floor_and_disable_implicit_configuration(consumer, monkeypatch, policy, refused):
    monkeypatch.setattr(context, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(tiers, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(context, '_host_consented_floor', lambda: None)
    monkeypatch.setattr(state, '_cli_sandbox_floor', None)
    monkeypatch.setattr(state, '_project_sandbox_floor', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', policy == 'operator-disable')
    monkeypatch.delenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', raising=False)
    if policy in ('env-landlock', 'flag-raises-env'):
        monkeypatch.setenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', '1')
    if policy.startswith('flag-'):
        monkeypatch.setattr(state, '_cli_sandbox_floor',
                            'mount-ns' if policy == 'flag-raises-env' else 'landlock')
    if policy == 'project-landlock':
        monkeypatch.setattr(state, '_project_sandbox_floor', 'landlock')
    calls = []
    executed = []
    def reduced_backend(command, **kwargs):
        calls.append(kwargs)
        assert kwargs['block_network'] is True
        assert kwargs['restrict_reads'] is True
        assert kwargs['fake_home'] is True
        assert kwargs['strict_env'] is True
        assert kwargs['strip_trust_markers'] is True
        assert kwargs['start_new_session'] is True
        assert kwargs['omit_proc_reads'] is (not kwargs['require_fresh_procfs'])
        if consumer.kind != 'asan':
            assert kwargs['profile'] == 'debug'
            if command[0] == 'gdb':
                assert '-nx' in command
                assert command.index('set auto-load off') < command.index('-x')
                assert command.index('set startup-with-shell off') < command.index('-x')
            else:
                assert '--no-lldbinit' in command
                assert command.index('settings set target.load-script-from-symbol-file false') < command.index('-s')
        explicit, source = context._explicit_untrusted_floor()
        floor, _ = tiers.resolve_call_floor(operator_disabled=state._cli_sandbox_disabled,
            require_fresh_procfs=kwargs['require_fresh_procfs'], untrusted_workload=False,
            waiver_active=context._degraded_untrusted_waiver(),
            explicit_floor=explicit, explicit_source=source)
        tiers.assert_floor(tiers.ContainmentTier.LANDLOCK_ONLY, floor, lane='test debugger backend')
        executed.append(True)
        return subprocess.CompletedProcess(command, 0, 'backtrace', '')
    monkeypatch.setattr(consumer.seam, '_sandbox_run', reduced_backend)
    if refused:
        with pytest.raises(SandboxFloorError):
            consumer.invoke()
        assert not executed
    else:
        consumer.invoke()
        assert executed
    assert len(calls) == 1
    assert not list(consumer.root.glob('.raptor_*')), 'debugger files leaked after completion/refusal'


def test_macos_uses_private_scratch(monkeypatch, tmp_path):
    from packages.binary_analysis import _execution_policy as module
    monkeypatch.setattr(module, 'sys', SimpleNamespace(platform='darwin'))
    assert module.crash_execution_policy(tmp_path)['exclude_tmp_baseline'] is True


@pytest.mark.parametrize('consumer', _CONSUMERS, indirect=True)
def test_denied_kernel_refuses_real_consumer(consumer, monkeypatch):
    import sys
    from core.sandbox.probes import check_net_available
    if sys.platform != 'linux' or check_net_available():
        pytest.skip('requires a Linux host that denies namespace creation')
    monkeypatch.setattr(state, '_cli_sandbox_floor', None)
    monkeypatch.setattr(state, '_project_sandbox_floor', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    monkeypatch.setattr(context, '_host_consented_floor', lambda: None)
    monkeypatch.delenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', raising=False)
    with pytest.raises(SandboxFloorError):
        consumer.invoke()
    assert not list(consumer.root.glob('.raptor_*'))


@pytest.mark.parametrize('alias', [False, True])
def test_home_directory_grant_is_refused(tmp_path, monkeypatch, alias):
    from packages.binary_analysis._execution_policy import crash_execution_policy
    home = tmp_path/'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    directory = home
    if alias:
        directory = tmp_path/'alias'
        directory.symlink_to(home, target_is_directory=True)
    with pytest.raises(SandboxSetupError, match='dedicated target directory'):
        crash_execution_policy(directory)


def test_lldb_redirect_paths_cannot_inject_commands():
    from packages.binary_analysis._execution_policy import lldb_path
    assert lldb_path('a "quoted" path') == '\"a \\"quoted\\" path\"'
    with pytest.raises(ValueError, match='control characters'):
        lldb_path('target\nscript print("injected")')

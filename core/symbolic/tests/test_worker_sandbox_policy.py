"""Policy dispatch and refusal before symbolic target parsing."""
import pickle
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import context, state, tiers
from core.sandbox.errors import SandboxFloorError
from core.symbolic import _isolate as isolate


from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(autouse=True)
def clean_policy(monkeypatch):
    monkeypatch.delenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', raising=False)
    monkeypatch.setattr(state, '_cli_sandbox_floor', None)
    monkeypatch.setattr(state, '_project_sandbox_floor', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    monkeypatch.setattr(context, '_host_consented_floor', lambda: None)


@pytest.mark.parametrize('policy,refused', [
    ('default', True), ('flag-landlock', False), ('project-landlock', False),
    ('env-landlock', False), ('flag-raises-env', True), ('project-raises-env', True),
    ('flag-none', True), ('operator-disable', False),
])
def test_worker_obeys_untrusted_floor(tmp_path, monkeypatch, policy, refused):
    from core import sandbox
    monkeypatch.setattr(context, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(tiers, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(state, '_cli_sandbox_disabled', policy == 'operator-disable')
    if policy in ('env-landlock', 'flag-raises-env', 'project-raises-env'):
        monkeypatch.setenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', '1')
    if policy.startswith('flag-'):
        monkeypatch.setattr(state, '_cli_sandbox_floor', {
            'flag-landlock': 'landlock', 'flag-raises-env': 'mount-ns', 'flag-none': 'none'}[policy])
    if policy.startswith('project-'):
        monkeypatch.setattr(state, '_project_sandbox_floor',
                            'landlock' if policy == 'project-landlock' else 'mount-ns')
    executed = []
    binary = tmp_path / 'target'
    binary.write_bytes(b'owned fixture')
    def backend(command, **kwargs):
        assert kwargs['block_network'] and kwargs['restrict_reads'] and kwargs['fake_home']
        assert kwargs['strict_env'] and kwargs['strip_trust_markers'] and kwargs['start_new_session']
        assert kwargs['exclude_tmp_baseline'] is True
        assert kwargs['_untrusted_workload'] is True
        assert kwargs['omit_proc_reads'] is (not kwargs['require_fresh_procfs'])
        assert 'skip_pid_ns' not in kwargs and 'skip_mount_ns' not in kwargs
        assert kwargs['pass_fds'] == (90,)
        assert str(binary) in kwargs['tool_paths']
        # The target's sibling directory does not become a recursive grant.
        assert str(binary.parent) not in kwargs['tool_paths']
        assert pickle.loads(kwargs['input'])[2]['binary_path'] == binary
        explicit, source = context._explicit_untrusted_floor()
        floor, _ = tiers.resolve_call_floor(operator_disabled=state._cli_sandbox_disabled,
            require_fresh_procfs=kwargs['require_fresh_procfs'],
            untrusted_workload=kwargs['_untrusted_workload'],
            waiver_active=context._degraded_untrusted_waiver(),
            explicit_floor=explicit, explicit_source=source)
        tiers.assert_floor(tiers.ContainmentTier.LANDLOCK_ONLY, floor, lane='symbolic worker test')
        executed.append(True)
        return subprocess.CompletedProcess(command, 0, b'', b'')
    monkeypatch.setattr(sandbox, 'run', backend)
    call = lambda: isolate._run_confined(SimpleNamespace(fileno=lambda: 90),
        'core.symbolic._reach', '_find_reaching_input_impl',
        {'binary_path': binary}, str(tmp_path), 5)
    if refused:
        with pytest.raises(SandboxFloorError):
            call()
        assert not executed
    else:
        call()
        assert executed


def test_failed_private_scratch_never_starts_worker(monkeypatch):
    def fail(**kwargs):
        raise OSError('owned scratch failure')
    patch_module_attribute(monkeypatch, isolate, 'tempfile', 'mkdtemp', fail)
    monkeypatch.setattr(isolate.mp, 'get_context', lambda *a: pytest.fail('worker started'))
    result = isolate.run_isolated('core.symbolic._reach', '_find_reaching_input_impl', {}, timeout=1)
    assert result.metadata['sandbox_refused'] is True
    assert 'scratch unavailable' in result.reason


def test_missing_dependency_never_calls_implementation(monkeypatch):
    from core.symbolic import _engine, _availability
    monkeypatch.setattr(_availability, 'angr_available', lambda: False)
    def _owned_impl(**kwargs):
        pytest.fail('implementation ran in parent')
    result = _engine.dispatch_isolated(_owned_impl, {}, timeout=1, primitive="owned")
    assert result.metadata['unavailable_dep'] == 'angr'
    assert result.metadata['primitive'] == 'owned'


def test_broker_preserves_parent_policy_and_reports_refusal(monkeypatch):
    values = {name: getattr(state, name) for name in isolate._POLICY_STATE}
    values.update(_cli_sandbox_floor='mount-ns', _project_sandbox_floor='landlock')
    for name in values:
        monkeypatch.setattr(state, name, getattr(state, name))
    def refuse(*args):
        assert state._cli_sandbox_floor == 'mount-ns'
        assert state._project_sandbox_floor == 'landlock'
        raise SandboxFloorError('owned refusal', 'enable namespaces',
            achievable=tiers.ContainmentTier.LANDLOCK_ONLY, floor=tiers.ContainmentTier.MOUNT_NS)
    monkeypatch.setattr(isolate, '_run_confined', refuse)
    reader, writer = isolate.mp.Pipe(duplex=False)
    try:
        isolate._child_entry(writer, 'core.symbolic._reach', 'unused', {}, '/unused', 5, values)
        result = isolate._loads_result(reader.recv_bytes())
        assert result.metadata['sandbox_refused'] is True
        assert 'owned refusal' in result.reason
    finally:
        reader.close()
        writer.close()


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux denied-namespace check')
def test_unavailable_namespaces_refuse_before_symbolic_execution():
    if context.check_net_available():
        pytest.skip('requires a Linux host denying namespace creation')
    result = isolate.run_isolated('core.symbolic.tests.test_isolate', '_benign_result', {}, timeout=5)
    assert result.succeeded is False
    assert result.metadata.get('sandbox_refused') is True
    assert 'symbolic sandbox refused' in result.reason


@pytest.mark.parametrize('missing', [False, True])
def test_directory_or_missing_target_never_becomes_a_recursive_grant(tmp_path, monkeypatch, missing):
    from core import sandbox
    from core.sandbox.errors import SandboxSetupError
    monkeypatch.setattr(sandbox, 'run', lambda *a, **k: pytest.fail('target admitted'))
    target = tmp_path / 'missing' if missing else tmp_path
    with pytest.raises(SandboxSetupError, match='not a regular file'):
        isolate._run_confined(SimpleNamespace(fileno=lambda: 90), 'core.symbolic._reach',
                              'unused', {'binary_path': target}, str(tmp_path), 5)

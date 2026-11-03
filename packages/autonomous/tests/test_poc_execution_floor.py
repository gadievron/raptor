"""Generated PoC compilation and execution must obey the untrusted floor."""
import subprocess
import shlex
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import context, state, tiers
from core.sandbox.errors import SandboxFloorError
from packages.autonomous import exploit_validator as module


@pytest.fixture
def clean_policy(monkeypatch):
    monkeypatch.delenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', raising=False)
    monkeypatch.setattr(context, '_host_consented_floor', lambda: None)
    monkeypatch.setattr(state, '_cli_sandbox_floor', None)
    monkeypatch.setattr(state, '_project_sandbox_floor', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)


@pytest.fixture(params=['compile', 'compile-verify', 'execute', 'supervised-execute'])
def consumer(request, tmp_path, monkeypatch):
    workspace = tmp_path / 'work'
    workspace.mkdir()
    marker = workspace / 'executed'
    payload = workspace / 'owned-fixture'
    payload.write_text('#!/bin/sh\nprintf executed > ' + shlex.quote(str(marker)) + '\n')
    payload.chmod(0o700)
    validator = module.ExploitValidator(work_dir=workspace)
    if request.param == 'compile-verify':
        from packages.llm_analysis import exploit_verify
        monkeypatch.setattr(exploit_verify, 'exec_workdir', lambda: workspace)
        monkeypatch.setattr(module, '_detect_cxx_compiler', lambda: str(payload))
        invoke = lambda: exploit_verify.compile_verify('int main(){return 0;}', 'fixture.c', 'owned')
    elif request.param == 'compile':
        monkeypatch.setattr(module, '_detect_cxx_compiler', lambda: str(payload))
        invoke = lambda: validator.validate_exploit('int main(){return 0;}', 'fixture')
    elif request.param == 'execute':
        invoke = lambda: validator.safe_test_exploit(payload, payload)
    else:
        from packages.llm_analysis import exploit_verify
        monkeypatch.setattr(exploit_verify, 'exec_workdir', lambda: workspace)
        def compiled(self, *args, **kwargs):
            return module.ValidationResult(True, [], [], payload)
        monkeypatch.setattr(module.ExploitValidator, 'validate_exploit', compiled)
        invoke = lambda: exploit_verify.compile_and_execute('int main(){return 0;}', 'fixture.c', 'owned')
    return SimpleNamespace(invoke=invoke, marker=marker, phase=request.param)


@pytest.mark.parametrize('policy,refused', [
    ('default', True), ('flag-landlock', False), ('project-landlock', False),
    ('env-landlock', False), ('flag-raises-env', True), ('project-raises-env', True),
    ('flag-none', True), ('operator-disable', False),
])
def test_poc_consumer_obeys_real_floor_resolution(consumer, monkeypatch, clean_policy, policy, refused):
    import core.sandbox
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
    calls = []
    def reduced_backend(command, **kwargs):
        calls.append(kwargs)
        assert kwargs['_untrusted_workload'] is True
        assert kwargs['restrict_reads'] is True and kwargs['fake_home'] is True
        assert kwargs['block_network'] is True and kwargs['strict_env'] is True
        if consumer.phase != 'supervised-execute':
            assert kwargs['strip_trust_markers'] is True
            assert kwargs['stdin'] == subprocess.DEVNULL and kwargs['start_new_session'] is True
        else:
            assert kwargs['input'], 'supervisor waitstatus nonce must still be piped'
        assert kwargs['omit_proc_reads'] is (not kwargs['require_fresh_procfs'])
        if consumer.phase in ('compile', 'compile-verify'):
            assert kwargs['omit_etc_reads'] is True, 'existing /etc policy was widened'
        explicit, source = context._explicit_untrusted_floor()
        floor, _ = tiers.resolve_call_floor(operator_disabled=state._cli_sandbox_disabled,
            require_fresh_procfs=kwargs['require_fresh_procfs'],
            untrusted_workload=kwargs['_untrusted_workload'],
            waiver_active=context._degraded_untrusted_waiver(),
            explicit_floor=explicit, explicit_source=source)
        tiers.assert_floor(tiers.ContainmentTier.LANDLOCK_ONLY, floor, lane='PoC test backend')
        consumer.marker.write_text('after floor enforcement')
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(core.sandbox, 'run', reduced_backend)
    if refused:
        with pytest.raises(SandboxFloorError):
            consumer.invoke()
        assert not consumer.marker.exists()
    else:
        consumer.invoke()
        assert consumer.marker.exists()
    assert len(calls) == 1


def test_denied_kernel_never_executes_generated_poc(consumer, clean_policy):
    if sys.platform != 'linux' or context.check_net_available():
        pytest.skip('requires a Linux host that denies namespace creation')
    with pytest.raises(SandboxFloorError):
        consumer.invoke()
    assert not consumer.marker.exists()


@pytest.mark.slow
@pytest.mark.integration
@pytest.mark.parametrize('phase', ['compile', 'execute'])
def test_native_poc_consumer_meets_floor(tmp_path, monkeypatch, clean_policy, phase):
    import core.sandbox
    if sys.platform == 'linux':
        if not context.check_net_available() or not context.check_mount_available():
            pytest.skip('native Linux mount and network namespaces required')
    elif sys.platform == 'darwin':
        if not context.check_seatbelt_available():
            pytest.skip('native macOS Seatbelt required')
    else:
        pytest.skip('Linux or macOS required')
    work = tmp_path / 'work'
    work.mkdir()
    validator = module.ExploitValidator(work_dir=work)
    original = core.sandbox.run
    metadata = []
    replies = []
    def observe(command, **kwargs):
        result = original(command, **kwargs)
        replies.append(result)
        metadata.append(result.sandbox_info)
        return result
    monkeypatch.setattr(core.sandbox, 'run', observe)
    if phase == 'compile':
        try:
            module._detect_cxx_compiler()
        except RuntimeError:
            pytest.skip('C++ compiler required')
        result = validator.validate_exploit('int main(){return 0;}', 'owned-fixture')
        assert result.success, result.compilation_errors
        assert result.exploit_path.is_file()
    else:
        secret = tmp_path / 'private-canary'
        secret.write_text('private')
        outside = tmp_path / 'outside-write'
        payload = work / 'owned-payload'
        payload.write_text('''#!/bin/sh
if ( : < CANARY ) 2>/dev/null; then echo 'private read allowed'; exit 10; fi
# A Linux private tmpfs may accept this write; parent verifies host state.
( printf shadow > OUTSIDE ) 2>/dev/null || :
[ -z "${_RAPTOR_TRUSTED-}${CLAUDECODE-}${RAPTOR_DIR-}" ] || exit 12
if read value; then exit 13; fi
if ( : < /dev/tty ) 2>/dev/null; then exit 14; fi
printf scratch > "$HOME/owned-scratch"
printf contained
'''.replace('CANARY', shlex.quote(str(secret))).replace('OUTSIDE', shlex.quote(str(outside))))
        payload.chmod(0o700)
        monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
        monkeypatch.setenv('CLAUDECODE', '1')
        success, output = validator.safe_test_exploit(payload, payload)
        assert success is False, output
        assert replies[0].returncode == 0, output
        assert replies[0].stdout == 'contained', output
        assert output == replies[0].stdout + replies[0].stderr, output
        assert not outside.exists() and secret.read_text() == 'private'
    assert len(metadata) == 1
    assert metadata[0]['containment_tier'] == ('seatbelt' if sys.platform == 'darwin' else 'mount-ns')
    assert metadata[0]['restrict_reads'] is True


def test_macos_poc_uses_private_scratch_instead_of_shared_tmp(consumer, monkeypatch, clean_policy):
    import core.sandbox
    from packages.llm_analysis import exploit_verify
    native_python = sys.executable
    monkeypatch.setattr(module, 'sys', SimpleNamespace(platform='darwin'))
    monkeypatch.setattr(exploit_verify, 'sys', SimpleNamespace(platform='darwin', executable=native_python))
    monkeypatch.setattr(context, 'sys', SimpleNamespace(platform='darwin'))
    calls = []
    def capture(command, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(core.sandbox, 'run', capture)
    consumer.invoke()
    assert len(calls) == 1
    assert calls[0]['exclude_tmp_baseline'] is True
    assert calls[0]['_untrusted_workload'] is True


@pytest.mark.parametrize('status', [0, 10])
def test_native_assertion_accepts_setup_diagnostics_but_requires_payload_success(
        tmp_path, monkeypatch, clean_policy, status):
    import core.sandbox
    if sys.platform not in ('linux', 'darwin'):
        pytest.skip('Linux or macOS native assertion contract')
    monkeypatch.setattr(context, 'check_net_available', lambda: True)
    monkeypatch.setattr(context, 'check_mount_available', lambda: True)
    monkeypatch.setattr(context, 'check_seatbelt_available', lambda: True)
    def reply(command, **kwargs):
        result = subprocess.CompletedProcess(command, status, 'contained',
                                             'sandbox: mount_ns: private /etc copy in use\n')
        result.sandbox_info = {
            'containment_tier': 'seatbelt' if sys.platform == 'darwin' else 'mount-ns',
            'restrict_reads': True,
        }
        return result
    monkeypatch.setattr(core.sandbox, 'run', reply)
    if status:
        with pytest.raises(AssertionError):
            test_native_poc_consumer_meets_floor(tmp_path, monkeypatch, clean_policy, 'execute')
    else:
        test_native_poc_consumer_meets_floor(tmp_path, monkeypatch, clean_policy, 'execute')

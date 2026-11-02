"""Real consumer calls must carry the untrusted floor into degraded dispatch."""
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import context, state, tiers
from core.sandbox.errors import SandboxFloorError


@pytest.fixture
def consumer(tmp_path, monkeypatch, request):
    from packages.fuzzing import afl_runner, libfuzzer_runner, cargofuzz_runner, jazzer_runner
    from core.build import build_detector
    import core.sandbox
    source = tmp_path/'source'
    output = tmp_path/'output'
    corpus = tmp_path/'corpus'
    for path in (source, output, corpus):
        path.mkdir()
    binary = source/'fixture'
    binary.write_bytes(b'fixture')
    binary.chmod(0o700)
    (corpus/'seed').write_bytes(b'input')
    name = request.param
    if name == 'afl':
        instance = afl_runner._SandboxedAFLInstance(name='fixture', cmd=['/usr/bin/true'], env={},
            stdout_path=output/'stdout', stderr_path=output/'stderr', output_dir=output,
            readable_paths=[str(source), str(corpus)], timeout_s=5)
        def invoke():
            instance._run()
            if instance.error:
                raise instance.error
        seam = (afl_runner, '_sandbox_run')
    elif name == 'showmap':
        runner = afl_runner.AFLRunner.__new__(afl_runner.AFLRunner)
        runner.binary, runner.output_dir, runner.corpus_dir = binary, output, corpus
        runner.sandbox_rootfs = runner.binary_in_rootfs = runner._resolved_binary_mode = None
        runner.afl_fuzz, runner.input_mode = '/usr/bin/afl-fuzz', 'stdin'
        invoke = runner.run_showmap
        seam = (afl_runner, '_sandbox_run')
    elif name == 'libfuzzer':
        runner = libfuzzer_runner.LibFuzzerRunner(binary, output_dir=output, max_total_time=1)
        invoke = runner.run
        seam = (libfuzzer_runner, '_sandbox_run')
    elif name == 'cargo-build':
        runner = cargofuzz_runner.CargoFuzzRunner.__new__(cargofuzz_runner.CargoFuzzRunner)
        runner.crate_dir, runner.output_dir, runner._cargo_target_dir = source, output, output/'build'
        runner.build_timeout = 5
        runner._seed_run_cargo_home = lambda: None
        runner._build_command_for_build = lambda: ['/usr/bin/true']
        runner._build_readable_paths = runner._build_writable_paths = runner._rust_tool_paths = lambda: []
        runner._build_env = lambda: {}
        runner._locate_built_binary = lambda: binary
        invoke = runner._build_fuzz_target
        seam = (libfuzzer_runner, '_sandbox_run')
    elif name == 'jvm-build':
        runner = jazzer_runner.JazzerRunner.__new__(jazzer_runner.JazzerRunner)
        runner.project_dir, runner.output_dir, runner.build_timeout = source, output, 5
        runner.build_tool = 'maven'
        runner._build_readable_paths = runner._jvm_tool_paths = lambda: []
        invoke = lambda: runner._run_build(['/usr/bin/true'], env={}, writable_paths=[])
        seam = (libfuzzer_runner, '_sandbox_run')
    elif name == 'synthesized-build':
        detector = build_detector.BuildDetector(source)
        invoke = lambda: detector._dry_run(binary, language='c')
        seam = (build_detector, '_sandbox_run')
    else:
        from packages.fuzzing.coverage_bridge import _default_runner
        invoke = lambda: _default_runner([str(binary), str(corpus/'seed')], cwd=source)
        seam = (core.sandbox, 'run')
    return SimpleNamespace(invoke=invoke, seam=seam, marker=output/'executed', calls=[])


_CONSUMERS = ['afl', 'showmap', 'libfuzzer', 'cargo-build', 'jvm-build', 'synthesized-build', 'replay']


@pytest.mark.parametrize('consumer', _CONSUMERS, indirect=True)
@pytest.mark.parametrize('policy,refused', [
    ('default', True), ('flag-landlock', False), ('project-landlock', False),
    ('env-landlock', False), ('flag-raises-env', True), ('project-raises-env', True),
    ('flag-none', True), ('operator-disable', False),
])
def test_consumer_obeys_real_floor_resolution(consumer, monkeypatch, policy, refused):
    # Only replace the backend boundary: execute each real consumer's call,
    # then resolve and enforce its floor with the production policy engine.
    monkeypatch.setattr(context, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(tiers, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(context, '_host_consented_floor', lambda: None)
    monkeypatch.setattr(state, '_cli_sandbox_floor', None)
    monkeypatch.setattr(state, '_project_sandbox_floor', None)
    monkeypatch.setattr(state, '_cli_sandbox_disabled', policy == 'operator-disable')
    monkeypatch.delenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', raising=False)
    if policy in ('env-landlock', 'flag-raises-env', 'project-raises-env'):
        monkeypatch.setenv('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', '1')
    if policy.startswith('flag-'):
        monkeypatch.setattr(state, '_cli_sandbox_floor', {
            'flag-landlock': 'landlock', 'flag-raises-env': 'mount-ns', 'flag-none': 'none'}[policy])
    if policy.startswith('project-'):
        monkeypatch.setattr(state, '_project_sandbox_floor',
                            'landlock' if policy == 'project-landlock' else 'mount-ns')
    def reduced_backend(cmd, **kwargs):
        consumer.calls.append(kwargs)
        assert kwargs['restrict_reads'] is True
        fresh = kwargs.get('require_fresh_procfs')
        assert kwargs['omit_proc_reads'] is (not fresh)
        explicit, source = context._explicit_untrusted_floor()
        floor, _ = tiers.resolve_call_floor(operator_disabled=state._cli_sandbox_disabled,
            require_fresh_procfs=fresh, untrusted_workload=False,
            waiver_active=context._degraded_untrusted_waiver(),
            explicit_floor=explicit, explicit_source=source)
        tiers.assert_floor(tiers.ContainmentTier.LANDLOCK_ONLY, floor, lane='test reduced backend')
        consumer.marker.write_text('only after the floor check')
        return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
    monkeypatch.setattr(*consumer.seam, reduced_backend)
    if refused:
        with pytest.raises(SandboxFloorError):
            consumer.invoke()
        assert not consumer.marker.exists()
    else:
        consumer.invoke()
        assert consumer.marker.exists()
    assert len(consumer.calls) == 1


@pytest.mark.parametrize('consumer', _CONSUMERS, indirect=True)
def test_real_denied_kernel_refuses_consumer(consumer, monkeypatch):
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
    assert not consumer.marker.exists()

"""The seccomp unit guard belongs to its actual probe consumer."""
from contextlib import nullcontext
import subprocess

import pytest

from packages.exploit_feasibility.tests import test_sandboxed_probes as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_seccomp_guard_restores_namespace(failure):
    namespace = native.feas_context.subprocess
    popen = subprocess.Popen
    runner = native.feas_context._sandbox_run
    helper = native.patch_module_attribute
    entered = []

    def checked(patch, consumer, binding, name, value):
        assert consumer is native.feas_context
        assert (binding, name, value) == ('subprocess', 'Popen', native._forbidden_popen)
        private = helper(patch, consumer, binding, name, value)
        entered.append(private)
        assert consumer.subprocess is not namespace
        assert subprocess.Popen is popen
        return private

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, 'patch_module_attribute', checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                native.TestSamplerRouting().test_seccomp_probe_pins_sandbox_posture(body)
                assert native.feas_context.subprocess.Popen is native._forbidden_popen
                assert subprocess.Popen is popen
                if failure:
                    raise failure('owned body failure')
        assert len(entered) == 1
        assert native.feas_context.subprocess is namespace
        assert native.feas_context._sandbox_run is runner
        assert subprocess.Popen is popen
    assert native.patch_module_attribute is helper


def test_actual_seccomp_guard_rejects_bare_fallback():
    original = native.feas_context._seccomp_tools_dump_sandboxed
    namespace = native.feas_context.subprocess
    popen = subprocess.Popen
    reached = []

    def fallback(*args, **kwargs):
        result = original(*args, **kwargs)
        reached.append(result)
        native.feas_context.subprocess.Popen(['owned-forbidden-dispatch'])
        return result

    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native.feas_context, '_seccomp_tools_dump_sandboxed', fallback)
        with pytest.MonkeyPatch.context() as body:
            with pytest.raises(AssertionError, match='subprocess.Popen must not be called'):
                native.TestSamplerRouting().test_seccomp_probe_pins_sandbox_posture(body)
        assert len(reached) == 1
        assert reached[0].returncode == 0
        assert reached[0].stdout == 'no filter\n'
        assert native.feas_context.subprocess is namespace
        assert subprocess.Popen is popen
    assert native.feas_context._seccomp_tools_dump_sandboxed is original

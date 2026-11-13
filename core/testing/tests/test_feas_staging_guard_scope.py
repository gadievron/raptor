"""Executable-staging unit guards stay on the actual probe consumer."""
from contextlib import nullcontext
import subprocess

import pytest

from packages.exploit_feasibility.tests import test_sandboxed_probes as native

pytestmark = native.pytestmark

METHODS = ['test_maps_snapshot_stages_0444_binary',
           'test_seccomp_probe_stages_0444_binary',
           'test_executable_binary_not_staged']


def _invoke(method, tmp_path, body):
    case = native.TestExecutableStaging()
    if method == 'test_executable_binary_not_staged':
        getattr(case, method)(body)
    else:
        getattr(case, method)(tmp_path, body)


@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_staging_guard_restores_namespace(tmp_path, method, failure):
    namespace = native.feas_context.subprocess
    popen = subprocess.Popen
    runner = native.feas_context._sandbox_run
    helper = native.patch_module_attribute
    entered, dispatched = [], []

    def checked(patch, consumer, binding, name, value):
        assert consumer is native.feas_context
        assert (binding, name, value) == ('subprocess', 'Popen', native._forbidden_popen)
        private = helper(patch, consumer, binding, name, value)
        entered.append(private)
        assert subprocess.Popen is popen
        return private

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, 'patch_module_attribute', checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                setter = body.setattr

                def observed(target, name, value, *args, **kwargs):
                    if target is native.feas_context and name == '_sandbox_run':
                        callback = value

                        def run(*args, **kwargs):
                            assert subprocess.Popen is popen
                            dispatched.append(args[0])
                            return callback(*args, **kwargs)

                        value = run
                    return setter(target, name, value, *args, **kwargs)

                body.setattr = observed
                _invoke(method, tmp_path, body)
                assert len(entered) == len(dispatched) == 1
                assert native.feas_context.subprocess.Popen is native._forbidden_popen
                if failure:
                    raise failure('owned body failure')
        assert native.feas_context.subprocess is namespace
        assert native.feas_context._sandbox_run is runner
        assert subprocess.Popen is popen
    assert native.patch_module_attribute is helper


@pytest.mark.parametrize('method', METHODS)
def test_actual_staging_guard_rejects_bare_fallback(tmp_path, method):
    name = ('_seccomp_tools_dump_sandboxed' if 'seccomp' in method
            else '_live_maps_snapshot')
    original = getattr(native.feas_context, name)
    namespace = native.feas_context.subprocess
    popen = subprocess.Popen
    completed = []

    def fallback(*args, **kwargs):
        result = original(*args, **kwargs)
        completed.append(result)
        native.feas_context.subprocess.Popen(['owned-forbidden-dispatch'])
        return result

    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native.feas_context, name, fallback)
        with pytest.MonkeyPatch.context() as body:
            with pytest.raises(AssertionError, match='subprocess.Popen must not be called'):
                _invoke(method, tmp_path, body)
        assert len(completed) == 1
        if 'seccomp' in method:
            assert completed[0].returncode == 0
            assert completed[0].stdout == 'no filter\n'
        else:
            assert completed == [None]
        assert native.feas_context.subprocess is namespace
        assert subprocess.Popen is popen
    assert getattr(native.feas_context, name) is original

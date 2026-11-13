"""Dynamic harness no-bare guards remain effective and consumer-local."""
from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from core.audit.tests import test_dynamic_sweep as native


@pytest.mark.parametrize("route", ["c", "python"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_setup_failure_guard_restores_runner(tmp_path, route, failure):
    runner = subprocess.run
    binding = native._dynamic.subprocess
    scope = native.mock_module_attribute
    entered = []

    @contextmanager
    def checked(module, binding_name, name):
        assert module is native._dynamic
        assert (binding_name, name) == ("subprocess", "run")
        with scope(module, binding_name, name) as bare:
            entered.append(bare)
            assert module.subprocess is not binding
            assert module.subprocess.run is bare
            assert subprocess.run is runner
            yield bare
            assert not bare.called
            assert subprocess.run is runner
            if failure:
                raise failure("owned body failure")

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, "mock_module_attribute", checked)
        with expected:
            getattr(native.TestHarnessContainment(),
                    "test_" + route + "_harness_skips_on_sandbox_setup_error")(tmp_path)
        assert len(entered) == 1
        assert native._dynamic.subprocess is binding
        assert subprocess.run is runner
    assert native.mock_module_attribute is scope


@pytest.mark.parametrize("route", ["c", "python"])
def test_actual_guard_rejects_injected_bare_fallback(tmp_path, route):
    runner = subprocess.run
    module = native._dynamic
    name = "_run_" + route + "_harness"
    run = getattr(module, name)
    attempted = []
    guards = []
    scope = native.mock_module_attribute

    @contextmanager
    def tracked(*args, **kwargs):
        with scope(*args, **kwargs) as bare:
            guards.append(bare)
            yield bare

    def unsafe(*args, **kwargs):
        result = run(*args, **kwargs)
        attempted.append(result)
        module.subprocess.run(["owned-negative-bare-call"])
        return result

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(module, name, unsafe)
        patch.setattr(native, "mock_module_attribute", tracked)
        with pytest.raises(AssertionError) as caught:
            getattr(native.TestHarnessContainment(),
                    "test_" + route + "_harness_skips_on_sandbox_setup_error")(tmp_path)
        assert "called" in str(caught.value)
        assert len(guards) == 1
        guards[0].assert_called_once_with(["owned-negative-bare-call"])
        assert len(attempted) == 1
        assert attempted[0].ran is False
        assert "sandbox unavailable" in attempted[0].sanitizer_output
    assert getattr(module, name) is run
    assert subprocess.run is runner

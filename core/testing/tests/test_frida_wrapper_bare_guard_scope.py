"""Wrapper import-refusal guards remain effective without global call mocks."""
from contextlib import contextmanager, nullcontext
import subprocess
import sys

import pytest

from packages.frida import sandboxed
from packages.frida.tests import test_substrate as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_wrapper_guard_restores_consumer(failure):
    call = subprocess.call
    namespace = sandboxed.subprocess
    system = sandboxed.sys
    main = sandboxed.main
    scope = native.mock_module_attribute
    missing = object()
    core_sandbox = sys.modules.get("core.sandbox", missing)
    entered, results = [], []

    def observed():
        assert subprocess.call is call
        result = main()
        assert result == 1
        assert "Fatal: core.sandbox not importable" in sandboxed.sys.stderr.getvalue()
        results.append(result)
        return result

    @contextmanager
    def checked(module, binding, name, **kwargs):
        assert module is sandboxed
        assert (binding, name, kwargs) == ("subprocess", "call", {"return_value": 0})
        with scope(module, binding, name, **kwargs) as bare:
            entered.append(bare)
            assert module.subprocess is not namespace
            assert module.subprocess.call is bare
            assert subprocess.call is call
            yield bare
            bare.assert_not_called()
            assert results == [1]
            if failure:
                raise failure("owned body failure")

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(sandboxed, "main", observed)
        owner.setattr(native, "mock_module_attribute", checked)
        with expected:
            native.TestSandboxedMain().test_import_failure_hard_fails()
        assert len(entered) == 1
        assert sandboxed.subprocess is namespace
        assert sandboxed.sys is system
        assert sys.modules.get("core.sandbox", missing) is core_sandbox
        assert subprocess.call is call
    assert sandboxed.main is main
    assert native.mock_module_attribute is scope


def test_actual_wrapper_guard_rejects_injected_bare_fallback():
    call = subprocess.call
    main = sandboxed.main
    scope = native.mock_module_attribute
    entered, results = [], []

    @contextmanager
    def tracked(*args, **kwargs):
        with scope(*args, **kwargs) as bare:
            entered.append(bare)
            yield bare

    def unsafe():
        result = main()
        assert result == 1
        assert "Fatal: core.sandbox not importable" in sandboxed.sys.stderr.getvalue()
        results.append(result)
        sandboxed.subprocess.call(["owned-negative-bare-call"])
        return result

    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(sandboxed, "main", unsafe)
        owner.setattr(native, "mock_module_attribute", tracked)
        with pytest.raises(AssertionError, match="not have been called"):
            native.TestSandboxedMain().test_import_failure_hard_fails()
        assert results == [1]
        assert len(entered) == 1
        entered[0].assert_called_once_with(["owned-negative-bare-call"])
        assert subprocess.call is call
    assert sandboxed.main is main

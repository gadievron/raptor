"""Frida fallback environment fixtures do not change the global importer."""
import builtins
from contextlib import nullcontext
import os

import pytest

from packages.frida.tests import test_runner as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_fallback_fixture_restores_environment(failure):
    importer = builtins.__import__
    spawn_env = native.runner._spawn_env
    view = native.module_function_view
    missing = object()
    inherited = {name: os.environ.get(name, missing) for name in
                 ("ANTHROPIC_API_KEY", "RAPTOR_SESSION_TOKEN")}
    refusals = []
    results = []

    def checked(module, *, import_hook=None):
        assert module is native.runner

        def observed(name, *args, **kwargs):
            assert builtins.__import__ is importer
            try:
                return import_hook(name, *args, **kwargs)
            except ImportError as exc:
                assert name == "core.config"
                assert str(exc) == "simulated missing core.config"
                refusals.append(name)
                raise

        private = view(module, import_hook=observed)
        original = private._spawn_env
        assert original.__code__ is spawn_env.__code__

        def run():
            result = original()
            assert isinstance(result, dict)
            assert set(result) <= {"PATH", "HOME", "LANG", "TERM"}
            assert "PATH" in result
            results.append(result)
            if failure:
                raise failure("owned body failure")
            return result

        private._spawn_env = run
        return private

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, "module_function_view", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.test_spawn_env_strips_session_credential_without_config(patch)
        assert refusals == ["core.config", "core.config"]
        assert len(results) == 1
        assert native.runner._spawn_env is spawn_env
        assert builtins.__import__ is importer
        for name, value in inherited.items():
            restored = os.environ.get(name, missing)
            assert (restored is missing) if value is missing else restored == value
    assert native.module_function_view is view

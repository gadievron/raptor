"""Frida discovery fixtures retain the real probe without shared transports."""

from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from core.security import python_probe
from packages.frida import sandboxed
from packages.frida.tests import test_active as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_delegated_probe_owns_transport_and_imports(failure, monkeypatch, tmp_path):
    original_run = subprocess.run
    original_probe, original_probe_module = python_probe.run_python_probe, python_probe.subprocess
    original_find, original_sys = sandboxed._find_frida_site, sandboxed.sys
    real_scope = native.scoped_function_imports
    seen = []

    @contextmanager
    def inspect_scope(*args, **kwargs):
        with real_scope(*args, **kwargs) as imports:
            private = getattr(imports, "core.security.python_probe")
            assert subprocess.run is original_run
            assert python_probe.run_python_probe is original_probe
            assert python_probe.subprocess is original_probe_module
            assert private.run_python_probe is not original_probe
            assert private.run_python_probe.__code__ is original_probe.__code__
            assert private.run_python_probe.__globals__["safe_subprocess_env"] is python_probe.safe_subprocess_env
            assert sandboxed._find_frida_site is not original_find
            seen.append(private)
            yield imports
            if failure:
                raise failure("owned probe import scope failure")

    monkeypatch.setattr(native, "scoped_function_imports", inspect_scope)
    expected = pytest.raises(failure, match="owned probe import scope failure") if failure else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            native.TestSandboxedProbeEnvHygiene().test_find_frida_site_probe_uses_sanitised_env(tmp_path, patch)
    assert len(seen) == 1
    assert sandboxed._find_frida_site is original_find
    assert sandboxed.sys is original_sys
    assert subprocess.run is original_run
    assert python_probe.run_python_probe is original_probe
    assert python_probe.subprocess is original_probe_module

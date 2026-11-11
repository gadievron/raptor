"""Ghidra probe fixtures own mocked runners without invoking native tools."""

from contextlib import nullcontext
import subprocess

import pytest

from packages.ghidra import detect
from packages.ghidra.tests import test_detect_env_hygiene as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_probe_runner_binding_is_owned(failure):
    original_module, original_run = detect.subprocess, subprocess.run
    original_which = detect.shutil
    expected = pytest.raises(failure, match="owned probe scope failure") if failure else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            native.test_version_probe_uses_sanitised_env(patch)
            assert subprocess.run is original_run
            assert detect.subprocess is not original_module
            assert detect.subprocess.run is not original_run
            assert detect.subprocess.TimeoutExpired is subprocess.TimeoutExpired
            assert detect.get_ghidra_version() == "11.1.2"
            if failure:
                raise failure("owned probe scope failure")
    assert detect.subprocess is original_module
    assert subprocess.run is original_run
    assert detect.shutil is original_which

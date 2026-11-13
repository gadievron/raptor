"""Binary discovery failure recorders preserve unrelated process callers."""
from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from core.run.tests import test_validation_helper_stage_guards as native


@pytest.mark.parametrize("name", ["test_timeout_warns_and_returns_empty", "test_oserror_warns_and_returns_empty"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_discovery_failure_recorder_restores_scope(tmp_path, capsys, name, failure):
    runner = subprocess.run
    originals = []
    calls = []
    token = object()

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(subprocess, "run", unrelated)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                with contextmanager(native._private_discovery.__wrapped__)(patch) as install:
                    def checked(mod, fake_run):
                        originals.append((mod, mod._discover_executables))
                        install(mod, fake_run)
                        assert mod._discover_executables is not originals[-1][1]
                        assert subprocess.run is unrelated

                    getattr(native.TestBinaryDiscoveryFailuresAreLoud(), name)(tmp_path, capsys, patch, checked)
                    assert len(originals) == 1
                    assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                    assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                    if failure:
                        raise failure("owned body failure")
        assert all(mod._discover_executables is function for mod, function in originals)
        assert subprocess.run is unrelated
    assert subprocess.run is runner

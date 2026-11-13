"""Interrupt lifecycle recorders preserve unrelated process callers."""
from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from core.audit.tests import test_finalize_interrupt_lifecycle as native


@pytest.mark.parametrize("name", ["test_failed_interrupt_transition_is_surfaced", "test_clean_interrupt_transition_stays_quiet"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_interrupt_recorder_restores_scope(tmp_path, capsys, name, failure):
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
                with contextmanager(native._private_finalize_run.__wrapped__)(patch) as install:
                    def checked(mod, fake_run):
                        originals.append((mod, mod._finalize_run))
                        install(mod, fake_run)
                        assert mod._finalize_run is not originals[-1][1]
                        assert subprocess.run is unrelated

                    env = native.finalize_env.__wrapped__(tmp_path, patch)
                    getattr(native, name)(env, patch, capsys, checked)
                    assert len(originals) == 1
                    assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                    assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                    if failure:
                        raise failure("owned body failure")
        assert all(mod._finalize_run is function for mod, function in originals)
        assert subprocess.run is unrelated
    assert subprocess.run is runner

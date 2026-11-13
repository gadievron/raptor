"""Forecast completion recorders preserve unrelated process calls."""
from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from core.audit.tests import test_audit_forecast_cli as native


@pytest.mark.parametrize("name", [
    "test_finalize_run_records_forecast_vs_actual",
    "test_finalize_run_tolerates_partial_forecast",
    "test_finalize_run_contains_calibration_line_crash",
])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_forecast_completion_recorder_restores_scope(tmp_path, capsys, name, failure):
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

                    getattr(native, name)(tmp_path, patch, capsys, checked)
                    assert len(originals) == 1
                    assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                    assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                    if failure:
                        raise failure("owned body failure")
        assert all(mod._finalize_run is original for mod, original in originals)
        assert subprocess.run is unrelated
    assert subprocess.run is runner

"""Lifecycle timeout injection leaves unrelated process callers unchanged."""
from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from core.audit.tests import test_lifecycle_call_timeouts as native


@pytest.mark.parametrize("case", ["start", "interrupt", "complete", "fail"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_timeout_cases_restore_scoped_imports(tmp_path, capsys, case, failure):
    runner = subprocess.run
    context = native._timeout_calls
    loads = []
    calls = []
    token = object()

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    @contextmanager
    def checked(mod, patch, recorded):
        names = ("cmd_run", "_finalize_run", "_lifecycle_fail")
        original = {name: getattr(mod, name) for name in names}
        loads.append(mod)
        try:
            with context(mod, patch, recorded):
                assert subprocess.run is unrelated
                yield
                assert recorded
                count = len(recorded)
                assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                assert len(recorded) == count
                assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                if failure:
                    raise failure("owned body failure")
        finally:
            assert all(getattr(mod, name) is value for name, value in original.items())
            assert subprocess.run is unrelated

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(subprocess, "run", unrelated)
        owner.setattr(native, "_timeout_calls", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                if case == "start":
                    native.test_run_lifecycle_start_timeout_aborts(tmp_path, patch, capsys)
                elif case == "fail":
                    native.test_lifecycle_fail_swallows_timeout(tmp_path, patch)
                else:
                    out = native.finalize_env.__wrapped__(tmp_path, patch)
                    getattr(native, "test_" + case + "_timeout_surfaced")(out, patch, capsys)
        assert len(loads) == 1
        assert subprocess.run is unrelated
    assert subprocess.run is runner
    assert native._timeout_calls is context

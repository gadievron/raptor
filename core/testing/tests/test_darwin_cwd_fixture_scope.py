"""Emulated Darwin cwd recorders preserve unrelated process callers."""
from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from core.run.tests import test_tmp_reaper as native


@pytest.mark.parametrize("outcome", ["busy", "unavailable"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_darwin_fixture_restores_import_scope(tmp_path, outcome, failure):
    runner = subprocess.run
    scope = native.scoped_function_imports
    calls = []
    token = object()
    scopes = []

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    @contextmanager
    def checked(module, functions, imports):
        original = module._live_cwds
        scopes.append(module)
        try:
            with scope(module, functions, imports) as private:
                assert subprocess.run is unrelated
                yield private
                assert subprocess.run(["unrelated-owned-sentinel"], timeout=7) is token
                assert calls == [(["unrelated-owned-sentinel"], {"timeout": 7})]
                if failure:
                    raise failure("owned body failure")
        finally:
            assert module._live_cwds is original
            assert subprocess.run is unrelated

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(subprocess, "run", unrelated)
        owner.setattr(native, "scoped_function_imports", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.native_cwd_probe.__wrapped__(patch)
                native.test_darwin_cwd_probe_keeps_live_or_unverifiable_scratch(tmp_path, patch, outcome, None)
        assert len(scopes) == 1
        assert subprocess.run is unrelated
    assert native.scoped_function_imports is scope
    assert subprocess.run is runner

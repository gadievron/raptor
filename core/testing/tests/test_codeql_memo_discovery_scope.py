"""CodeQL memo fixtures own local CLI discovery and their captured aliases."""
from contextlib import contextmanager, nullcontext
import shutil

import pytest

from core.audit.tests import test_codeql_sweep_memo as native


@pytest.mark.parametrize("case", ["warm", "missing"])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_codeql_fixture_restores_discovery_and_aliases(tmp_path, caplog, case, outcome):
    lookup = shutil.which
    sweep = native.sweep_mod.run_codeql_sweep
    warm = native.sweep_mod.warm_codeql_memo
    alias, memo = native.run_codeql_sweep, native.sweep_mod._codeql_memo
    executable = tmp_path / "unrelated-tool"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    assert shutil.which(str(executable)) == str(executable)
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
            native._fresh_memo.__wrapped__(patch)
            with contextmanager(native._hermetic_codeql_cli.__wrapped__)(patch) as imports:
                if case == "warm":
                    native.TestWarmCodeqlMemo().test_warmup_prefills_and_sweeps_hit(tmp_path, patch)
                    assert imports.shutil.which("codeql") == native._FAKE_CODEQL
                else:
                    native.TestWarmupSandboxAndGuard().test_missing_codeql_cli_degrades_loudly(tmp_path, patch, caplog, imports)
                    assert imports.shutil.which("codeql") is None
                assert shutil.which is lookup
                assert shutil.which(str(executable)) == str(executable)
                assert native.run_codeql_sweep is native.sweep_mod.run_codeql_sweep
                assert native.run_codeql_sweep is not alias
                assert native.sweep_mod.warm_codeql_memo is not warm
                patch.setattr(native.sweep_mod, "warm_codeql_memo", lambda *args: None)
                patch.setattr(native, "run_codeql_sweep", lambda *args: None)
                if outcome:
                    raise outcome("owned body failure")
    assert shutil.which is lookup
    assert native.run_codeql_sweep is alias
    assert native.sweep_mod.run_codeql_sweep is sweep
    assert native.sweep_mod.warm_codeql_memo is warm
    assert native.sweep_mod._codeql_memo is memo

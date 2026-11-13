"""CodeQL confinement fixtures preserve caller memo state and tool discovery."""
from contextlib import contextmanager, nullcontext
import shutil

import pytest

from core.audit.run_memo import BoundedMemo
from core.audit.tests import test_codeql_sweep_confinement as native


@pytest.mark.parametrize("case", ["dispatch", "warm", "missing"])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_confinement_fixtures_restore_borrowed_state(tmp_path, case, outcome):
    lookup = shutil.which
    sweep, warm = native.sweep_mod.run_codeql_sweep, native.sweep_mod.warm_codeql_memo
    aliases = native.run_codeql_sweep, native.warm_codeql_memo
    warning_names = ("_warn_codeql_channel_down", "_warn_codeql_warmup_failed",
                     "_note_codeql_dispatch_error", "_note_codeql_dispatch_ok")
    warning_helpers = {name: getattr(native.sweep_mod, name) for name in warning_names}
    original_memo = native.sweep_mod._codeql_memo
    borrowed = BoundedMemo(4)
    payload = [{"caller": "inherited"}]
    borrowed.get_or_compute("inherited", lambda: payload)
    counts = borrowed.hit_count, borrowed.miss_count
    executable = tmp_path / "unrelated-tool"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native.sweep_mod, "_codeql_memo", borrowed)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                patch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
                with contextmanager(native._fresh_memo.__wrapped__)():
                    assert native.sweep_mod._codeql_memo is not borrowed
                    with contextmanager(native.hermetic_codeql_cli.__wrapped__)(patch) as imports:
                        recorder = native.sandbox_recorder.__wrapped__(patch)
                        if case == "dispatch":
                            native.TestDispatchConfinement().test_dispatch_analyze_gets_confined_runner(tmp_path, patch, recorder)
                        elif case == "warm":
                            native.TestWarmupConfinement().test_warmup_analyze_gets_confined_runner(tmp_path, patch, recorder)
                        else:
                            native.TestDispatchConfinement().test_missing_cli_keeps_bare_analyze(tmp_path, patch, recorder, imports)
                        assert shutil.which is lookup
                        assert shutil.which(str(executable)) == str(executable)
                        assert native.run_codeql_sweep is native.sweep_mod.run_codeql_sweep
                        assert native.warm_codeql_memo is native.sweep_mod.warm_codeql_memo
                        patch.setattr(native, "run_codeql_sweep", lambda *args: None)
                        patch.setattr(native.sweep_mod, "warm_codeql_memo", lambda *args: None)
                        if outcome:
                            raise outcome("owned body failure")
        assert native.sweep_mod._codeql_memo is borrowed
        assert borrowed.peek("inherited", touch=False)[0] is payload
        assert (borrowed.hit_count, borrowed.miss_count) == counts
    assert native.sweep_mod._codeql_memo is original_memo
    assert shutil.which is lookup
    assert native.sweep_mod.run_codeql_sweep is sweep
    assert native.sweep_mod.warm_codeql_memo is warm
    assert native.run_codeql_sweep is aliases[0]
    assert native.warm_codeql_memo is aliases[1]

    for name, original in warning_helpers.items():
        assert getattr(native.sweep_mod, name) is original

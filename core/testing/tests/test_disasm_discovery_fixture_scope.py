"""Synthetic disassembly fixtures own only their intended discovery lookup."""
from contextlib import contextmanager, nullcontext
import shutil

import pytest

from core.audit.tests import test_disasm_xcheck as native


@pytest.mark.parametrize("name", [
    "test_dropped_argument_refuted_on_materialized_register",
    "test_missing_objdump_is_skipped",
], ids=["objdump-present", "objdump-missing"])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_synthetic_fixture_restores_discovery_and_body_overrides(tmp_path, name, outcome):
    original_namespace, lookup = native.shutil, shutil.which
    extractor = native.dx._extract_window
    caches = native.dx._SPAWN_COUNTS, native.dx._WINDOW_MEMO
    executable = tmp_path / "unrelated-tool"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    assert shutil.which(str(executable)) == str(executable)
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            with contextmanager(native._fresh_channel_state.__wrapped__)(patch):
                binary = native.fake_binary.__wrapped__(tmp_path)
                getattr(native.TestRunSynthetic(), name)(binary, patch, tmp_path)
                assert shutil.which is lookup
                assert shutil.which(str(executable)) == str(executable)
                assert native.shutil is not original_namespace
                assert native.dx._extract_window is not extractor
                # Later body patches may remember the private bindings.
                patch.setattr(native.dx, "_extract_window", lambda *args: None)
                patch.setattr(native, "shutil", shutil)
                if outcome:
                    raise outcome("owned body failure")
    assert native.shutil is original_namespace
    assert shutil.which is lookup
    assert native.dx._extract_window is extractor
    assert native.dx._SPAWN_COUNTS is caches[0]
    assert native.dx._WINDOW_MEMO is caches[1]

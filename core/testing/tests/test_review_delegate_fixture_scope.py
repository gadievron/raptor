"""Annotation delegate fixtures preserve unrelated subprocess callers."""
from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from core.run.tests import test_review_cli as native


@pytest.mark.parametrize("name", ["test_note_derives_base_from_out", "test_edit_derives_base_from_out", "test_explicit_base_wins"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_annotation_delegate_restores_scope(tmp_path, name, failure):
    caller = subprocess.call
    originals = []
    calls = []
    token = object()

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(subprocess, "call", unrelated)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                with contextmanager(native._private_delegate.__wrapped__)(patch) as install:
                    def checked(mod, fake_call):
                        originals.append((mod, mod.cmd_note, mod.cmd_edit))
                        install(mod, fake_call)
                        assert subprocess.call is unrelated

                    getattr(native.TestNoteEditWriteBase(), name)(tmp_path, patch, checked)
                    assert len(originals) == 1
                    assert subprocess.call(["unrelated-owned-sentinel"], env={"OWNED": "1"}) is token
                    assert calls == [(["unrelated-owned-sentinel"], {"env": {"OWNED": "1"}})]
                    if failure:
                        raise failure("owned body failure")
        assert all(mod.cmd_note is note and mod.cmd_edit is edit for mod, note, edit in originals)
        assert subprocess.call is unrelated
    assert subprocess.call is caller

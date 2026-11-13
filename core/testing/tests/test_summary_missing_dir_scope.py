"""The missing-directory summary case reaches real evidence-open refusal."""
import builtins
from contextlib import nullcontext

import pytest

from core.sandbox.tests import test_summary as native


@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_missing_dir_preserves_state(tmp_path, caplog, failure):
    opener = builtins.open
    state_module = native.summary_mod._evidence
    handle = native.summary_mod._evidence_handle
    failures = native.summary_mod._evidence_write_failures
    failure_contents = failures.copy()
    open_evidence = native.summary_mod._get_evidence_handle_locked
    opened = []

    def observed(run_dir):
        assert run_dir == tmp_path / 'does-not-exist'
        assert not run_dir.exists()
        assert builtins.open is opener
        opened.append(run_dir)
        return open_evidence(run_dir)

    user = native._user_state_in_tmp.__wrapped__(tmp_path)
    next(user)
    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    try:
        with expected:
            with pytest.MonkeyPatch.context() as body:
                state = native._isolate_active_run.__wrapped__(body)
                next(state)
                try:
                    body.setattr(native.summary_mod, '_get_evidence_handle_locked', observed)
                    native.TestRecordDenial().test_swallows_oserror_silently(tmp_path, body)
                    assert opened == [tmp_path / 'does-not-exist']
                    assert native.summary_mod._evidence_open_failed is True
                    assert any(record.name == native.summary_mod.__name__
                               and 'FileNotFoundError' in record.getMessage()
                               for record in caplog.records)
                    assert builtins.open is opener
                    if failure:
                        raise failure('owned body failure')
                finally:
                    body.undo()
                    state.close()
        assert native.summary_mod._evidence is state_module
        assert native.summary_mod._evidence_handle is handle
        assert native.summary_mod._evidence_write_failures is failures
        assert failures == failure_contents
        assert native.summary_mod._get_evidence_handle_locked is open_evidence
        assert builtins.open is opener
    finally:
        user.close()

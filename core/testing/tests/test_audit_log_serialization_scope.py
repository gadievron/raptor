"""Audit encoding recorders belong only to the actual writer."""
from contextlib import contextmanager, nullcontext
import json

import pytest

from core.audit.tests import test_audit_log_serialization as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_encoding_recorder_preserves_other_json_callers(tmp_path, failure):
    dumps = json.dumps
    append = native.record.append_audit_log
    scope = native.scoped_function_imports
    entered = []

    @contextmanager
    def checked(module, functions, imports):
        assert module is native.record
        assert functions == ("append_audit_log",)
        with scope(module, functions, imports) as private:
            entered.append(private)
            assert module.append_audit_log is not append
            yield private
            assert json.dumps is dumps
            assert json.dumps({"unrelated": True}) == '{"unrelated": true}'
            assert private.json.dumps is not dumps
            if failure:
                raise failure("owned body failure")

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, "scoped_function_imports", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.test_identical_bytes_with_one_encoding(tmp_path, patch, {"action": "owned"})
        assert len(entered) == 1
        assert native.record.append_audit_log is append
        assert json.dumps is dumps
    assert native.scoped_function_imports is scope

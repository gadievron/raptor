"""Unavailable CodeQL adapter fixtures keep their import hook private."""
import builtins
from contextlib import nullcontext

import pytest

from core.audit.tests import test_codeql_validation as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_adapter_absence_fixture_preserves_importer(tmp_path, failure):
    importer = builtins.__import__
    validate = native.validate_dataflow_claim
    view = native.module_function_view
    entered = []
    refusals = []

    def checked(module, *, import_hook=None):
        assert module is native._validation

        def observed(name, *args, **kwargs):
            assert builtins.__import__ is importer
            try:
                return import_hook(name, *args, **kwargs)
            except ImportError as exc:
                assert name == "core.dataflow.codeql_augmented_run"
                assert str(exc) == "not installed"
                refusals.append(name)
                raise

        private = view(module, import_hook=observed)
        assert private.validate_dataflow_claim.__code__ is validate.__code__
        assert private.ValidationResult is module.ValidationResult
        entered.append(private)
        return private

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, "module_function_view", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.TestValidateDataflowClaim().test_import_error(tmp_path, patch)
                assert len(entered) == 1
                assert refusals == ["core.dataflow.codeql_augmented_run"]
                assert builtins.__import__ is importer
                assert native._validation.validate_dataflow_claim is validate
                if failure:
                    raise failure("owned body failure")
        assert native.validate_dataflow_claim is validate
        assert builtins.__import__ is importer
    assert native.module_function_view is view

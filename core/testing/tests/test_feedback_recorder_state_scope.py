"""Feedback-library fixtures preserve inherited recorder state on all exits."""
import builtins
from contextlib import nullcontext

import pytest

from core.testing.module_views import module_function_view
from packages.checker_synthesis import library
from packages.llm_analysis.tests import test_graduated_rule_feedback as native


@pytest.mark.parametrize("method", [
    "test_fp_verdict_records_is_tp_false", "test_tp_verdict_records_is_tp_true",
    "test_non_synthesized_rule_ignored", "test_no_verdict_records_nothing",
    "test_junk_verdict_shape_records_nothing",
])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_feedback_case_restores_recorder(method, failure):
    calls = native._FakeLibrary.calls
    real_library = library.RuleLibrary
    inherited = [("previous-owned-record", True)]
    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native._FakeLibrary, "calls", inherited)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                getattr(native.TestGraduatedRuleFeedback(), method)(body)
                assert native._FakeLibrary.calls is not inherited
                assert inherited == [("previous-owned-record", True)]
                if failure:
                    raise failure("owned body failure")
        assert native._FakeLibrary.calls is inherited
        assert inherited == [("previous-owned-record", True)]
        assert library.RuleLibrary is real_library
    assert native._FakeLibrary.calls is calls


@pytest.mark.parametrize("error", [ImportError, KeyboardInterrupt])
def test_actual_recorder_setup_restores_before_import_refusal(error):
    calls = native._FakeLibrary.calls
    real_library = library.RuleLibrary
    inherited = [("previous-owned-record", True)]
    importer = builtins.__import__
    attempted = []

    def refuse(name, *args, **kwargs):
        if name == "packages.checker_synthesis.library":
            assert native._FakeLibrary.calls is not inherited
            attempted.append(name)
            raise error("owned setup refusal")
        return importer(name, *args, **kwargs)

    private = module_function_view(native, import_hook=refuse)
    assert private._patch_library.__code__ is native._patch_library.__code__
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native._FakeLibrary, "calls", inherited)
        with pytest.raises(error, match="owned setup refusal"):
            with pytest.MonkeyPatch.context() as body:
                private._patch_library(body)
        assert attempted == ["packages.checker_synthesis.library"]
        assert native._FakeLibrary.calls is inherited
        assert inherited == [("previous-owned-record", True)]
        assert library.RuleLibrary is real_library
        assert builtins.__import__ is importer
    assert native._FakeLibrary.calls is calls

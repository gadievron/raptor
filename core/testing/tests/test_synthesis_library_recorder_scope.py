"""On-demand synthesis stubs preserve inherited library call records."""
import builtins
from contextlib import nullcontext

import pytest

from core.audit import checker_synthesis
from core.audit.tests import test_ondemand_synthesis as native
from core.testing.module_views import module_function_view
import packages.checker_synthesis as package


@pytest.mark.parametrize("method", ["test_confirmed_rule_returns_stamp_and_persists", "test_dual_control_failure_not_confirmed"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_synthesis_fixture_restores_library_recorder(tmp_path, method, failure):
    calls = native._StubLibrary.calls
    real_library = package.RuleLibrary
    builder = checker_synthesis._build_llm_callable
    inherited = [{"rule_id": "previous-owned-rule"}]
    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native._StubLibrary, "calls", inherited)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                getattr(native.TestSynthesizeVerificationRule(), method)(tmp_path, body)
                assert native._StubLibrary.calls is not inherited
                assert inherited == [{"rule_id": "previous-owned-rule"}]
                if failure:
                    raise failure("owned body failure")
        assert native._StubLibrary.calls is inherited
        assert inherited == [{"rule_id": "previous-owned-rule"}]
        assert package.RuleLibrary is real_library
        assert checker_synthesis._build_llm_callable is builder
    assert native._StubLibrary.calls is calls


@pytest.mark.parametrize("error", [ImportError, KeyboardInterrupt])
def test_actual_library_recorder_setup_restores_on_import_refusal(error):
    calls = native._StubLibrary.calls
    real_library = package.RuleLibrary
    importer = builtins.__import__
    inherited = [{"rule_id": "previous-owned-rule"}]
    attempted = []

    def refuse(name, *args, **kwargs):
        if name == "packages.checker_synthesis":
            assert native._StubLibrary.calls is not inherited
            attempted.append(name)
            raise error("owned setup refusal")
        return importer(name, *args, **kwargs)

    private = module_function_view(native, import_hook=refuse)
    assert private._stub_library.__code__ is native._stub_library.__code__
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native._StubLibrary, "calls", inherited)
        with pytest.raises(error, match="owned setup refusal"):
            with pytest.MonkeyPatch.context() as body:
                private._stub_library(body)
        assert attempted == ["packages.checker_synthesis"]
        assert native._StubLibrary.calls is inherited
        assert inherited == [{"rule_id": "previous-owned-rule"}]
        assert package.RuleLibrary is real_library
        assert builtins.__import__ is importer
    assert native._StubLibrary.calls is calls

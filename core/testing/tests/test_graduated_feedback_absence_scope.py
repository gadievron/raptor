"""Missing graduated feedback libraries use an owned negative module cache."""
import builtins
from contextlib import nullcontext
import sys
from types import ModuleType

import pytest

from packages.llm_analysis.tests import test_graduated_rule_feedback as native

_LIBRARY = "packages.checker_synthesis.library"


@pytest.mark.parametrize("inherited", ["absent", "negative", "loaded"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_missing_feedback_fixture_restores_registry(inherited, failure):
    importer = builtins.__import__
    table = sys.modules
    missing = object()
    binding = table.get(_LIBRARY, missing)
    factory = native._agent_stub
    calls = native._FakeLibrary.calls
    contents = list(calls)
    selected = missing if inherited == "absent" else None if inherited == "negative" else ModuleType(_LIBRARY)
    refusals = []

    def forbidden(*args, **kwargs):
        pytest.fail("negative module cache must prevent library construction")

    if isinstance(selected, ModuleType):
        selected.RuleLibrary = forbidden

    def observed_factory():
        agent = factory()
        record = agent._record_graduated_rule_feedback
        assert record.__func__ is native.AutonomousSecurityAgentV2._record_graduated_rule_feedback

        def observed(vuln):
            assert builtins.__import__ is importer
            assert table[_LIBRARY] is None
            try:
                return record(vuln)
            except ModuleNotFoundError as exc:
                assert exc.name == _LIBRARY
                assert "None in sys.modules" in str(exc)
                refusals.append(exc.name)
                if failure and len(refusals) == 2:
                    raise failure("owned body failure") from exc
                raise

        agent._record_graduated_rule_feedback = observed
        return agent

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        if selected is missing:
            owner.delitem(table, _LIBRARY, raising=False)
        else:
            owner.setitem(table, _LIBRARY, selected)
        owner.setattr(native, "_agent_stub", observed_factory)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.TestGraduatedRuleFeedback().test_missing_checker_synthesis_package_is_suppressed(patch)
        assert refusals == [_LIBRARY, _LIBRARY]
        assert table.get(_LIBRARY, missing) is selected
        assert builtins.__import__ is importer
        assert native._FakeLibrary.calls is calls and calls == contents
    assert sys.modules is table
    assert table.get(_LIBRARY, missing) is binding
    assert native._agent_stub is factory

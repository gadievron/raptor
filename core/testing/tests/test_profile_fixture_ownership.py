"""The native summary counter owns its profiling hook before installation."""

import ast
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

from core.analysis.summaries import FunctionSummary
from core.audit.llm_summaries import _ground_summary
from core.testing.module_views import module_function_view


@pytest.fixture
def native():
    path = Path(__file__).resolve().parents[3] / "core/audit/tests/test_summary_grounding_preparation.py"
    tree = ast.parse(path.read_text())
    function = next(node for node in tree.body if getattr(node, "name", None) == "test_empty_native_paths_do_not_split_source")
    module = ModuleType("owned_summary_counter")
    module.__dict__.update(sys=sys, pytest=pytest, FunctionSummary=FunctionSummary,
                           _ground_summary=_ground_summary)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), vars(module))
    return module


@pytest.fixture
def profile_owner():
    previous = sys.getprofile()
    if previous is not None:
        pytest.skip("profiling hook already owned")
    try:
        yield previous
    finally:
        sys.setprofile(previous)


@pytest.mark.parametrize("after_effect", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_setup_failure_restores_the_real_profile_hook(native, profile_owner, after_effect, error):
    failure = error("counter setup failed")
    installed = []

    def setter(hook):
        installed.append(hook)
        if hook is not None and not after_effect:
            raise failure
        sys.setprofile(hook)
        if hook is not None:
            raise failure

    view = module_function_view(native, bindings={
        "sys": SimpleNamespace(getprofile=sys.getprofile, setprofile=setter),
    })
    with pytest.raises(error) as caught:
        view.test_empty_native_paths_do_not_split_source()
    observed = sys.getprofile()
    assert caught.value is failure
    assert observed is profile_owner
    assert len(installed) == 2
    assert callable(installed[0])
    assert installed[1] is profile_owner


@pytest.mark.parametrize("after_effect", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_body_failure_retires_only_the_owned_hook(native, profile_owner, after_effect, error):
    failure = error("counter consumer failed")
    observed = []

    def grounded(summary, source):
        observed.append(sys.getprofile())
        if after_effect:
            _ground_summary(summary, source)
        raise failure

    view = module_function_view(native, bindings={"_ground_summary": grounded})
    with pytest.raises(error) as caught:
        view.test_empty_native_paths_do_not_split_source()
    restored = sys.getprofile()
    assert caught.value is failure
    assert restored is profile_owner
    assert len(observed) == 1 and callable(observed[0])


def test_existing_caller_hook_remains_owned_and_is_not_replaced(native, profile_owner):
    borrowed = lambda *args: None
    attempted = []

    def setter(hook):
        attempted.append(hook)
        raise AssertionError("native counter replaced an already-owned hook")

    view = module_function_view(native, bindings={
        "sys": SimpleNamespace(getprofile=sys.getprofile, setprofile=setter),
    })
    sys.setprofile(borrowed)
    with pytest.raises(pytest.skip.Exception, match="profiler already owned"):
        view.test_empty_native_paths_do_not_split_source()
    observed = sys.getprofile()
    assert observed is borrowed
    assert attempted == []


def test_normal_counter_preserves_native_assertions_and_caller_state(native, profile_owner):
    native.test_empty_native_paths_do_not_split_source()
    observed = sys.getprofile()
    assert observed is profile_owner

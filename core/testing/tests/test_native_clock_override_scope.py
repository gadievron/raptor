"""Actual native clock overrides preserve shared and borrowed namespaces."""
import ast
import copy
from pathlib import Path
import time
from types import ModuleType
from unittest.mock import patch

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute
from core.testing.module_views import module_function_view

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'anchor': ['TestAdaptiveThrottle', 'test_restore_after_cooldown'],
  'attribute': 'monotonic',
  'consumer': 'core.llm.throttle',
  'expected': "patch_module_attribute(monkeypatch, _clock_consumer, 'time', 'monotonic', clk)",
  'file': 'core/llm/tests/test_throttle.py',
  'kind': 'monkey',
  'line': 75,
  'original': "monkeypatch.setattr(time, 'monotonic', clk)"},
 {'anchor': ['TestAdaptiveThrottle', 'test_signal_resets_cooldown'],
  'attribute': 'monotonic',
  'consumer': 'core.llm.throttle',
  'expected': "patch_module_attribute(monkeypatch, _clock_consumer, 'time', 'monotonic', clk)",
  'file': 'core/llm/tests/test_throttle.py',
  'kind': 'monkey',
  'line': 85,
  'original': "monkeypatch.setattr(time, 'monotonic', clk)"},
 {'anchor': ['TestAdaptiveThrottle', 'test_recovery_ramps_one_doubling_per_interval'],
  'attribute': 'monotonic',
  'consumer': 'core.llm.throttle',
  'expected': "patch_module_attribute(monkeypatch, _clock_consumer, 'time', 'monotonic', clk)",
  'file': 'core/llm/tests/test_throttle.py',
  'kind': 'monkey',
  'line': 103,
  'original': "monkeypatch.setattr(time, 'monotonic', clk)"},
 {'anchor': ['TestAdaptiveThrottle', 'test_long_idle_credits_every_quiet_interval'],
  'attribute': 'monotonic',
  'consumer': 'core.llm.throttle',
  'expected': "patch_module_attribute(monkeypatch, _clock_consumer, 'time', 'monotonic', clk)",
  'file': 'core/llm/tests/test_throttle.py',
  'kind': 'monkey',
  'line': 118,
  'original': "monkeypatch.setattr(time, 'monotonic', clk)"},
 {'anchor': ['TestAdaptiveThrottle', 'test_signal_during_ramp_restarts_the_window'],
  'attribute': 'monotonic',
  'consumer': 'core.llm.throttle',
  'expected': "patch_module_attribute(monkeypatch, _clock_consumer, 'time', 'monotonic', clk)",
  'file': 'core/llm/tests/test_throttle.py',
  'kind': 'monkey',
  'line': 129,
  'original': "monkeypatch.setattr(time, 'monotonic', clk)"},
 {'anchor': ['TestUniqueRunSuffix', 'test_underscore_separator'],
  'attribute': 'strftime',
  'consumer': 'core.run.output',
  'expected': "mock_module_attribute(_clock_consumer, 'time', 'strftime', "
              "return_value='20260427_120000')",
  'file': 'core/run/tests/test_output.py',
  'kind': 'mock',
  'line': 235,
  'original': "patch('time.strftime', return_value='20260427_120000')"},
 {'anchor': ['TestUniqueRunSuffix', 'test_hyphen_separator'],
  'attribute': 'strftime',
  'consumer': 'core.run.output',
  'expected': "mock_module_attribute(_clock_consumer, 'time', 'strftime', "
              "return_value='20260427-120000')",
  'file': 'core/run/tests/test_output.py',
  'kind': 'mock',
  'line': 244,
  'original': "patch('time.strftime', return_value='20260427-120000')"},
 {'anchor': ['TestUniqueRunSuffix', 'test_default_separator_is_underscore'],
  'attribute': 'strftime',
  'consumer': 'core.run.output',
  'expected': "mock_module_attribute(_clock_consumer, 'time', 'strftime', "
              "return_value='20260427_120000')",
  'file': 'core/run/tests/test_output.py',
  'kind': 'mock',
  'line': 254,
  'original': "patch('time.strftime', return_value='20260427_120000')"},
 {'anchor': ['TestUniqueRunSuffix', 'test_uses_correct_strftime_format_for_separator'],
  'attribute': 'strftime',
  'consumer': 'core.run.output',
  'expected': "mock_module_attribute(_clock_consumer, 'time', 'strftime', side_effect=capture)",
  'file': 'core/run/tests/test_output.py',
  'kind': 'mock',
  'line': 267,
  'original': "patch('time.strftime', side_effect=capture)"},
 {'anchor': ['TestUniqueRunSuffix', 'test_two_pids_produce_distinct_suffixes'],
  'attribute': 'strftime',
  'consumer': 'core.run.output',
  'expected': "mock_module_attribute(_clock_consumer, 'time', 'strftime', "
              "return_value='20260427_120000')",
  'file': 'core/run/tests/test_output.py',
  'kind': 'mock',
  'line': 286,
  'original': "patch('time.strftime', return_value='20260427_120000')"},
 {'anchor': ['TestGetOutputDir', 'test_concurrent_same_second_invocations_get_distinct_dirs'],
  'attribute': 'strftime',
  'consumer': 'core.run.output',
  'expected': "mock_module_attribute(_clock_consumer, 'time', 'strftime', "
              "return_value='20260427-120000')",
  'file': 'core/run/tests/test_output.py',
  'kind': 'mock',
  'line': 80,
  'original': "patch('time.strftime', return_value='20260427-120000')"},
 {'anchor': ['_no_sleep'],
  'attribute': 'sleep',
  'consumer': 'core.llm.providers',
  'expected': "patch_module_attribute(monkeypatch, _clock_consumer, 'time', 'sleep', lambda _s: "
              'None)',
  'file': 'core/llm/tests/test_turn_consumed_gate.py',
  'kind': 'monkey',
  'line': 52,
  'original': "monkeypatch.setattr(time, 'sleep', lambda _s: None)"},
 {'anchor': ['test_transient_retry_logs_warning_with_elapsed'],
  'attribute': 'sleep',
  'consumer': 'core.llm.providers',
  'expected': "patch_module_attribute(monkeypatch, _clock_consumer, 'time', 'sleep', lambda _s: "
              'None)',
  'file': 'core/llm/tests/test_anthropic_retry_visibility.py',
  'kind': 'monkey',
  'line': 76,
  'original': "monkeypatch.setattr(time, 'sleep', lambda _s: None)"},
 {'anchor': ['test_harness_detects_planted_hang'],
  'attribute': 'monotonic',
  'consumer': 'self',
  'expected': "patch_module_attribute(monkeypatch, _clock_consumer, 'time', 'monotonic', lambda: "
              'next(clock))',
  'file': 'packages/sca/parsers/tests/test_never_raise_conformance.py',
  'kind': 'monkey',
  'line': 151,
  'original': "monkeypatch.setattr(time, 'monotonic', lambda: next(clock))"},
 {'anchor': ['TestRaiseOnStatusFalseTransient', 'test_transient_still_retries_before_returning'],
  'attribute': 'sleep',
  'consumer': 'core.http.urllib_backend',
  'expected': "mock_module_attribute(_clock_consumer, 'time', 'sleep')",
  'file': 'core/http/tests/test_urllib_backend.py',
  'kind': 'mock',
  'line': 1772,
  'original': "patch('time.sleep')"},
 {'anchor': ['test_http_error_cached_with_short_ttl_not_forever'],
  'attribute': 'time',
  'consumer': 'core.json.cache',
  'expected': "mock_module_attribute(_clock_consumer, 'time', 'time', return_value=time.time() + "
              '_TTL_TRANSIENT + 1)',
  'file': 'packages/sca/tests/test_python_modules.py',
  'kind': 'mock',
  'line': 378,
  'original': "patch.object(time, 'time', return_value=time.time() + _TTL_TRANSIENT + 1)"},
 {'anchor': ['test_prespawn_handshake_waits_for_pid_after_marker_creation'],
  'attribute': 'sleep',
  'consumer': 'self',
  'expected': "patch_module_attribute(monkeypatch, _clock_consumer, 'time', 'sleep', finish_write)",
  'file': 'packages/joern/tests/test_netns_forwarder_boot.py',
  'kind': 'monkey',
  'line': 311,
  'original': "monkeypatch.setattr(time, 'sleep', finish_write)"}]


def _statement(row):
    tree = ast.parse((_REPO / row["file"]).read_text())
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    accepted = {ast.dump(ast.parse(row[key], mode="eval").body) for key in ("original", "expected")}
    matches = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or ast.dump(node) not in accepted:
            continue
        chain = []
        parent = parents.get(node)
        while parent:
            if isinstance(parent, (ast.FunctionDef, ast.ClassDef)):
                chain.append(parent.name)
            parent = parents.get(parent)
        if chain[::-1] == row["anchor"]:
            matches.append(node)
    assert len(matches) == 1, row
    return copy.deepcopy(matches[0])


def _namespace(owner, before):
    assert vars(owner).keys() == before.keys(), owner.__name__
    assert all(vars(owner)[key] is value for key, value in before.items()), owner.__name__


def _consumer(row, shape):
    owner = ModuleType(row["consumer"])
    view = time
    if shape == "shallow":
        view = ModuleType(time.__name__)
        vars(view).update(vars(time))
    elif shape == "function-view":
        view = module_function_view(time)
    owner.time = view
    return owner


def _scope(row, scope, owner, token):
    call = _statement(row)
    private = isinstance(call.func, ast.Name) and call.func.id in {"patch_module_attribute", "mock_module_attribute"}
    # The real native test owns the chosen clock values and callback behavior.
    # Exercise this exact binding expression with a unique, inert replacement.
    if row["kind"] == "monkey":
        call.args[-1] = ast.Name(id="token", ctx=ast.Load())
    else:
        selector = 3 if private else (2 if isinstance(call.func, ast.Attribute) else 1)
        call.args = call.args[:selector]
        call.keywords = [ast.keyword(arg="new", value=ast.Name(id="token", ctx=ast.Load()))]
    namespace = dict(_clock_consumer=owner, time=time, monkeypatch=scope, token=token,
                     patch=patch, mock_module_attribute=mock_module_attribute,
                     patch_module_attribute=patch_module_attribute)
    return eval(compile(ast.fix_missing_locations(ast.Expression(call)), row["file"], "eval"), namespace)


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: _SITES[i]["file"] + ":" + str(_SITES[i]["line"]))
@pytest.mark.parametrize("shape", ["shared", "shallow", "function-view"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_clock_override_owns_namespace(index, shape, exit_mode):
    row = _SITES[index]
    owner = _consumer(row, shape)
    original = owner.time
    snapshots = [(time, vars(time).copy()), (original, vars(original).copy()), (owner, vars(owner).copy())]
    token = lambda *args, **kwargs: 0.0
    failure = RuntimeError("clock scope") if exit_mode == "error" else KeyboardInterrupt("clock scope")
    caught = None
    try:
        with pytest.MonkeyPatch.context() as scope:
            if row["kind"] == "mock":
                with _scope(row, scope, owner, token):
                    for module, before in snapshots[:2]:
                        _namespace(module, before)
                    assert getattr(owner.time, row["attribute"]) is token
                    assert owner.time is not original
                    if exit_mode != "normal":
                        raise failure
            else:
                _scope(row, scope, owner, token)
                for module, before in snapshots[:2]:
                    _namespace(module, before)
                assert getattr(owner.time, row["attribute"]) is token
                assert owner.time is not original
                if exit_mode != "normal":
                    raise failure
    except BaseException as error:
        caught = error
    for module, before in snapshots:
        _namespace(module, before)
    assert caught is (None if exit_mode == "normal" else failure), repr(caught)


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: str(i))
@pytest.mark.parametrize("shape", ["shared", "shallow", "function-view"])
def test_nested_native_clock_override_restores_outer_binding(index, shape):
    row = _SITES[index]
    owner = _consumer(row, shape)
    original = owner.time
    outer = lambda: 1.0
    inner = lambda: 2.0
    from contextlib import ExitStack
    with ExitStack() as stack:
        scope = stack.enter_context(pytest.MonkeyPatch.context())
        if row["kind"] == "mock":
            stack.enter_context(_scope(row, scope, owner, outer))
        else:
            _scope(row, scope, owner, outer)
        outer_view = owner.time
        before = vars(outer_view).copy()
        with ExitStack() as nested:
            patcher = nested.enter_context(pytest.MonkeyPatch.context())
            if row["kind"] == "mock":
                nested.enter_context(_scope(row, patcher, owner, inner))
            else:
                _scope(row, patcher, owner, inner)
            assert owner.time is not outer_view
            assert getattr(owner.time, row["attribute"]) is inner
            _namespace(outer_view, before)
        assert owner.time is outer_view
        assert getattr(owner.time, row["attribute"]) is outer
    assert owner.time is original


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: str(i))
@pytest.mark.parametrize("shape", ["shared", "shallow", "function-view"])
def test_unmodified_native_clock_control(index, shape):
    owner = _consumer(_SITES[index], shape)
    before = vars(owner).copy()
    inherited = vars(owner.time).copy()
    _namespace(owner, before)
    _namespace(owner.time, inherited)

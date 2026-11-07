"""Actual native tool-discovery overrides preserve shared and borrowed namespaces."""
import ast
import copy
from functools import lru_cache
from pathlib import Path
import shutil
from types import ModuleType
from unittest.mock import patch

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute
from core.testing.module_views import module_function_view

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'anchor': ['TestExecuteWitnessC', 'test_c_compiler_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1313,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestExecuteWitnessJs', 'test_js_node_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1591,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestExecuteWitnessGo', 'test_go_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1610,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestExecuteWitnessTs', 'test_ts_runner_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1774,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestExecuteWitnessRuby', 'test_ruby_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1794,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestExecuteWitnessPhp', 'test_php_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1814,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestExecuteWitnessRust', 'test_rustc_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1838,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestExecuteWitnessJava', 'test_javac_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1863,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestExecuteWitnessLua', 'test_lua_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1883,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestExecuteWitnessPerl', 'test_perl_not_found'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda cmd: None)',
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 1903,
  'original': "monkeypatch.setattr(shutil, 'which', lambda cmd: None)"},
 {'anchor': ['TestCompileSandboxParity', 'test_go_compile_routed_through_sandbox'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda name: f'/usr/bin/{name}')",
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 3610,
  'original': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}')"},
 {'anchor': ['TestCompileSandboxParity', 'test_rust_compile_routed_through_sandbox'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda name: f'/usr/bin/{name}')",
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 3643,
  'original': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}')"},
 {'anchor': ['TestCompileSandboxParity', 'test_javac_sandboxed_with_proc_none'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda name: f'/usr/bin/{name}')",
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 3683,
  'original': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}')"},
 {'anchor': ['TestSandboxFailClosed', 'test_c_compile_refuses'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda name: f'/usr/bin/{name}')",
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 4249,
  'original': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}')"},
 {'anchor': ['TestSandboxFailClosed', 'test_go_compile_refuses'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda name: f'/usr/bin/{name}')",
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 4268,
  'original': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}')"},
 {'anchor': ['TestSandboxFailClosed', 'test_rust_compile_refuses'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda name: f'/usr/bin/{name}')",
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 4286,
  'original': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}')"},
 {'anchor': ['TestSandboxFailClosed', 'test_java_refuses'],
  'attribute': 'which',
  'consumer': 'core.audit.dark_verify._execute',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda name: f'/usr/bin/{name}')",
  'file': 'core/audit/tests/test_dark_verify.py',
  'kind': 'monkey',
  'line': 4305,
  'original': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}')"},
 {'anchor': ['TestToolchainFallback', 'test_gcc_missing_falls_back_to_clang'],
  'attribute': 'which',
  'consumer': 'core.audit.compiler_sweep',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda name, *a, **k: None if name == 'gcc' else real_which(name, *a, **k))",
  'file': 'core/audit/tests/test_compiler_sweep.py',
  'kind': 'monkey',
  'line': 432,
  'original': "monkeypatch.setattr(shutil, 'which', lambda name, *a, **k: None if name == 'gcc' "
              'else real_which(name, *a, **k))'},
 {'anchor': ['TestToolchainFallback', 'test_both_missing_is_error'],
  'attribute': 'which',
  'consumer': 'core.audit.compiler_sweep',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda *a, **k: None)',
  'file': 'core/audit/tests/test_compiler_sweep.py',
  'kind': 'monkey',
  'line': 450,
  'original': "monkeypatch.setattr(shutil, 'which', lambda *a, **k: None)"},
 {'anchor': ['TestLayer2SweepEndToEnd', 'test_forged_refutation_is_inconclusive'],
  'attribute': 'which',
  'consumer': 'core.audit.compiler_sweep',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda n, *a, **k: None if n == 'gcc' else real_which(n, *a, **k))",
  'file': 'core/audit/tests/test_compiler_sweep.py',
  'kind': 'monkey',
  'line': 1922,
  'original': "monkeypatch.setattr(shutil, 'which', lambda n, *a, **k: None if n == 'gcc' else "
              'real_which(n, *a, **k))'},
 {'anchor': ['TestLayer2SweepEndToEnd', 'test_control_still_confirms'],
  'attribute': 'which',
  'consumer': 'core.audit.compiler_sweep',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda n, *a, **k: None if n == 'gcc' else real_which(n, *a, **k))",
  'file': 'core/audit/tests/test_compiler_sweep.py',
  'kind': 'monkey',
  'line': 1935,
  'original': "monkeypatch.setattr(shutil, 'which', lambda n, *a, **k: None if n == 'gcc' else "
              'real_which(n, *a, **k))'},
 {'anchor': ['TestDistinctNameQuotaEndToEnd', 'test_quota_exhaustion_is_inconclusive'],
  'attribute': 'which',
  'consumer': 'core.audit.compiler_sweep',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda n, *a, **k: None if n == 'gcc' else real_which(n, *a, **k))",
  'file': 'core/audit/tests/test_compiler_sweep.py',
  'kind': 'monkey',
  'line': 2550,
  'original': "monkeypatch.setattr(shutil, 'which', lambda n, *a, **k: None if n == 'gcc' else "
              'real_which(n, *a, **k))'},
 {'anchor': ['TestResolutionLimitEndToEnd', '_sweep'],
  'attribute': 'which',
  'consumer': 'core.audit.compiler_sweep',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda n, *a, **k: None if n == 'gcc' else real_which(n, *a, **k))",
  'file': 'core/audit/tests/test_compiler_sweep.py',
  'kind': 'monkey',
  'line': 2886,
  'original': "monkeypatch.setattr(shutil, 'which', lambda n, *a, **k: None if n == 'gcc' else "
              'real_which(n, *a, **k))'},
 {'anchor': ['TestBoundedResolutionEndToEnd', 'test_limit_is_inconclusive'],
  'attribute': 'which',
  'consumer': 'core.audit.compiler_sweep',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda n, *a, **k: None if n == 'gcc' else real_which(n, *a, **k))",
  'file': 'core/audit/tests/test_compiler_sweep.py',
  'kind': 'monkey',
  'line': 3499,
  'original': "monkeypatch.setattr(shutil, 'which', lambda n, *a, **k: None if n == 'gcc' else "
              'real_which(n, *a, **k))'},
 {'anchor': ['TestDegradation', 'test_no_preprocessor_degrades'],
  'attribute': 'which',
  'consumer': 'core.audit.preprocessor_view',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda *a, **k: None)',
  'file': 'core/audit/tests/test_preprocessor_view.py',
  'kind': 'monkey',
  'line': 466,
  'original': "monkeypatch.setattr(shutil, 'which', lambda *a, **k: None)"},
 {'anchor': ['TestGracefulEmptiness', 'test_git_absent'],
  'attribute': 'which',
  'consumer': 'core.audit.git_oracle',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda *a, **k: None)',
  'file': 'core/audit/tests/test_git_oracle.py',
  'kind': 'monkey',
  'line': 265,
  'original': "monkeypatch.setattr(shutil, 'which', lambda *a, **k: None)"},
 {'anchor': ['sandbox_calls'],
  'attribute': 'which',
  'consumer': 'core.analysis.binary_oracle',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              "lambda name, *a, **k: '/usr/bin/c++filt' if name == 'c++filt' else None)",
  'file': 'core/analysis/tests/test_binary_oracle_demangle_confinement.py',
  'kind': 'monkey',
  'line': 42,
  'original': "monkeypatch.setattr(shutil, 'which', lambda name, *a, **k: '/usr/bin/c++filt' if "
              "name == 'c++filt' else None)"},
 {'anchor': ['test_demangle_missing_tool_never_reaches_sandbox'],
  'attribute': 'which',
  'consumer': 'core.analysis.binary_oracle',
  'expected': "patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', "
              'lambda *a, **k: None)',
  'file': 'core/analysis/tests/test_binary_oracle_demangle_confinement.py',
  'kind': 'monkey',
  'line': 74,
  'original': "monkeypatch.setattr(shutil, 'which', lambda *a, **k: None)"},
 {'anchor': ['TestFindInstallDir', 'test_derives_from_analyzeHeadless'],
  'attribute': 'which',
  'consumer': 'packages.ghidra.session',
  'expected': "mock_module_attribute(_tool_lookup_consumer, 'shutil', 'which', "
              'return_value=str(headless))',
  'file': 'packages/ghidra/tests/test_session.py',
  'kind': 'mock',
  'line': 213,
  'original': "patch('shutil.which', return_value=str(headless))"},
 {'anchor': ['TestFindInstallDir', 'test_returns_none_when_not_found'],
  'attribute': 'which',
  'consumer': 'packages.ghidra.session',
  'expected': "mock_module_attribute(_tool_lookup_consumer, 'shutil', 'which', return_value=None)",
  'file': 'packages/ghidra/tests/test_session.py',
  'kind': 'mock',
  'line': 218,
  'original': "patch('shutil.which', return_value=None)"},
 {'anchor': ['TestFindInstallDir', 'test_returns_none_when_not_in_support'],
  'attribute': 'which',
  'consumer': 'packages.ghidra.session',
  'expected': "mock_module_attribute(_tool_lookup_consumer, 'shutil', 'which', "
              'return_value=str(headless))',
  'file': 'packages/ghidra/tests/test_session.py',
  'kind': 'mock',
  'line': 226,
  'original': "patch('shutil.which', return_value=str(headless))"}]


def _statement(row):
    return copy.deepcopy(_resolved_statement(row["file"], tuple(row["anchor"]), row["original"], row["expected"]))


@lru_cache(maxsize=None)
def _resolved_statement(file, anchor, original, expected):
    tree = ast.parse((_REPO / file).read_text())
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    accepted = {ast.dump(ast.parse(text, mode="eval").body) for text in (original, expected)}
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
        if tuple(chain[::-1]) == anchor:
            matches.append(node)
    assert len(matches) == 1, (file, anchor)
    return matches[0]


def _namespace(owner, before):
    assert vars(owner).keys() == before.keys(), owner.__name__
    assert all(vars(owner)[key] is value for key, value in before.items()), owner.__name__


def _consumer(row, shape):
    owner = ModuleType(row["consumer"])
    view = shutil
    if shape == "shallow":
        view = ModuleType(shutil.__name__)
        vars(view).update(vars(shutil))
    elif shape == "function-view":
        view = module_function_view(shutil)
    owner.shutil = view
    return owner


def _scope(row, scope, owner, token):
    call = _statement(row)
    private = isinstance(call.func, ast.Name) and call.func.id in {"patch_module_attribute", "mock_module_attribute"}
    # The real native test owns the chosen tool-discovery values and callback behavior.
    # Exercise this exact binding expression with a unique, inert replacement.
    if row["kind"] == "monkey":
        call.args[-1] = ast.Name(id="token", ctx=ast.Load())
    else:
        selector = 3 if private else (2 if isinstance(call.func, ast.Attribute) else 1)
        call.args = call.args[:selector]
        call.keywords = [ast.keyword(arg="new", value=ast.Name(id="token", ctx=ast.Load()))]
    namespace = dict(_tool_lookup_consumer=owner, shutil=shutil, monkeypatch=scope, token=token,
                     patch=patch, mock_module_attribute=mock_module_attribute,
                     patch_module_attribute=patch_module_attribute)
    return eval(compile(ast.fix_missing_locations(ast.Expression(call)), row["file"], "eval"), namespace)


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: _SITES[i]["file"] + ":" + str(_SITES[i]["line"]))
@pytest.mark.parametrize("shape", ["shared", "shallow", "function-view"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_tool_lookup_override_owns_namespace(index, shape, exit_mode):
    row = _SITES[index]
    owner = _consumer(row, shape)
    original = owner.shutil
    snapshots = [(shutil, vars(shutil).copy()), (original, vars(original).copy()), (owner, vars(owner).copy())]
    token = lambda *args, **kwargs: 0.0
    failure = RuntimeError("tool discovery scope") if exit_mode == "error" else KeyboardInterrupt("tool discovery scope")
    caught = None
    try:
        with pytest.MonkeyPatch.context() as scope:
            if row["kind"] == "mock":
                with _scope(row, scope, owner, token):
                    for module, before in snapshots[:2]:
                        _namespace(module, before)
                    assert getattr(owner.shutil, row["attribute"]) is token
                    assert owner.shutil is not original
                    if exit_mode != "normal":
                        raise failure
            else:
                _scope(row, scope, owner, token)
                for module, before in snapshots[:2]:
                    _namespace(module, before)
                assert getattr(owner.shutil, row["attribute"]) is token
                assert owner.shutil is not original
                if exit_mode != "normal":
                    raise failure
    except BaseException as error:
        caught = error
    for module, before in snapshots:
        _namespace(module, before)
    assert caught is (None if exit_mode == "normal" else failure), repr(caught)


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: str(i))
@pytest.mark.parametrize("shape", ["shared", "shallow", "function-view"])
def test_nested_native_tool_lookup_override_restores_outer_binding(index, shape):
    row = _SITES[index]
    owner = _consumer(row, shape)
    original = owner.shutil
    outer = lambda: 1.0
    inner = lambda: 2.0
    from contextlib import ExitStack
    with ExitStack() as stack:
        scope = stack.enter_context(pytest.MonkeyPatch.context())
        if row["kind"] == "mock":
            stack.enter_context(_scope(row, scope, owner, outer))
        else:
            _scope(row, scope, owner, outer)
        outer_view = owner.shutil
        before = vars(outer_view).copy()
        with ExitStack() as nested:
            patcher = nested.enter_context(pytest.MonkeyPatch.context())
            if row["kind"] == "mock":
                nested.enter_context(_scope(row, patcher, owner, inner))
            else:
                _scope(row, patcher, owner, inner)
            assert owner.shutil is not outer_view
            assert getattr(owner.shutil, row["attribute"]) is inner
            _namespace(outer_view, before)
        assert owner.shutil is outer_view
        assert getattr(owner.shutil, row["attribute"]) is outer
    assert owner.shutil is original


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: str(i))
@pytest.mark.parametrize("shape", ["shared", "shallow", "function-view"])
def test_unmodified_native_tool_lookup_control(index, shape):
    owner = _consumer(_SITES[index], shape)
    before = vars(owner).copy()
    inherited = vars(owner.shutil).copy()
    _namespace(owner, before)
    _namespace(owner.shutil, inherited)

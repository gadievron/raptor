"""Native temporary-root faults stay inside their fixture's lookup graph."""
import ast
import copy
from functools import lru_cache
import importlib
import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

import pytest

from core.testing.module_views import module_function_view

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'anchor': ['tmp_root'],
  'attribute': 'gettempdir',
  'call': "monkeypatch.setattr('tempfile.gettempdir', lambda: str(tmp_path))",
  'consumers': ['core.run.scratch', 'core.run.tmp_reaper'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: str(tmp_path))",
  'file': 'core/run/tests/test_scratch.py',
  'kind': 'string',
  'line': 31},
 {'anchor': ['tmp_root'],
  'attribute': 'gettempdir',
  'call': "monkeypatch.setattr('tempfile.gettempdir', lambda: str(tmp_path))",
  'consumers': ['core.run.tmp_reaper'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: str(tmp_path))",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'string',
  'line': 108},
 {'anchor': ['TestDirReaping', 'test_dir_with_answering_socket_kept_then_reaped'],
  'attribute': 'gettempdir',
  'call': "monkeypatch.setattr('tempfile.gettempdir', lambda: short_root)",
  'consumers': ['core.run.tmp_reaper'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: short_root)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'string',
  'line': 269},
 {'anchor': ['TestMultiRootSweep', 'roots'],
  'attribute': 'gettempdir',
  'call': "monkeypatch.setattr('tempfile.gettempdir', lambda: str(session))",
  'consumers': ['core.run.tmp_reaper'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: str(session))",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'string',
  'line': 1043},
 {'anchor': ['TestMultiRootSweep', 'test_gettempdir_at_system_root_dedupes'],
  'attribute': 'gettempdir',
  'call': "monkeypatch.setattr('tempfile.gettempdir', lambda: str(system))",
  'consumers': ['core.run.tmp_reaper'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: str(system))",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'string',
  'line': 1104},
 {'anchor': ['tmp_root'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))",
  'consumers': ['core.run.tmp_ownership'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))",
  'file': 'core/run/tests/test_tmp_ownership.py',
  'kind': 'object',
  'line': 30},
 {'anchor': ['TestSweep', 'test_never_raises_on_bad_tempdir'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path / 'gone'))",
  'consumers': ['core.run.tmp_ownership'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path / 'gone'))",
  'file': 'core/run/tests/test_tmp_ownership.py',
  'kind': 'object',
  'line': 144},
 {'anchor': ['_fresh'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(tmp_root))",
  'consumers': ['core.run.workdir'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_root))",
  'file': 'core/run/tests/test_workdir.py',
  'kind': 'object',
  'line': 61},
 {'anchor': ['TestLauncherNoOp', 'test_returns_none_when_tmpdir_is_a_launcher_session'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(session))",
  'consumers': ['core.run.workdir'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(session))",
  'file': 'core/run/tests/test_workdir.py',
  'kind': 'object',
  'line': 83},
 {'anchor': ['TestLauncherNoOp', 'test_returns_none_anywhere_inside_the_family'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(nested))",
  'consumers': ['core.run.workdir'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(nested))",
  'file': 'core/run/tests/test_workdir.py',
  'kind': 'object',
  'line': 91},
 {'anchor': ['TestLauncherNoOp', 'test_tempfile_paths_unchanged_under_launcher'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(session))",
  'consumers': ['core.run.workdir'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(session))",
  'file': 'core/run/tests/test_workdir.py',
  'kind': 'object',
  'line': 101},
 {'anchor': ['TestTempRootInteropAdvisory', 'test_fires_even_on_launcher_noop_path'],
  'attribute': 'gettempdir',
  'call': "monkeypatch.setattr(tempfile, 'gettempdir', lambda: str(fam))",
  'consumers': ['core.run.workdir'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: str(fam))",
  'file': 'core/run/tests/test_workdir.py',
  'kind': 'object',
  'line': 250},
 {'anchor': ['private_reaper_roots'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr('tempfile.tempdir', str(tmp_path))",
  'consumers': ['core.run.tmp_reaper',
                'core.run.tmp_ownership',
                'core.run.scratch',
                'core.run.workdir'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))",
  'file': 'core/run/tests/test_permission_cleanup.py',
  'kind': 'string',
  'line': 16},
 {'anchor': ['private_roots'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr('tempfile.tempdir', str(tmp_path))",
  'consumers': ['core.run.tmp_reaper', 'core.run.tmp_ownership', 'core.run.scratch'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))",
  'file': 'core/run/tests/test_retention_inputs.py',
  'kind': 'string',
  'line': 21},
 {'anchor': ['test_temp_text_success_transfers_closed_utf8_file'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(scratch.tempfile, 'tempdir', str(tmp_path))",
  'consumers': ['core.run.scratch'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))",
  'file': 'core/run/tests/test_scratch_setup_failures.py',
  'kind': 'object',
  'line': 81},
 {'anchor': ['test_standalone_caller_uses_python_selected_tmp_without_launcher'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(readonly_tmp))",
  'consumers': ['packages.codeql.temp_env'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(readonly_tmp))",
  'file': 'packages/codeql/tests/test_temp_env.py',
  'kind': 'object',
  'line': 48},
 {'anchor': ['tmp_root'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))",
  'consumers': ['packages.joern.server', 'core.run.tmp_ownership', 'packages.joern.client'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))",
  'file': 'packages/joern/tests/test_workspace_sweep.py',
  'kind': 'object',
  'line': 31},
 {'anchor': ['TestUdsDirFixtureByteBudget', 'test_multibyte_tmpdir_falls_back_within_byte_budget'],
  'attribute': 'gettempdir',
  'call': "monkeypatch.setattr(tempfile, 'gettempdir', lambda: fake_root)",
  'consumers': ['packages.joern.tests.conftest'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: fake_root)",
  'file': 'packages/joern/tests/test_uds_path_budget.py',
  'kind': 'object',
  'line': 79},
 {'anchor': ['test_deep_socket_storage_stays_owned_and_pin_closes_at_shutdown'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(base))",
  'consumers': ['core.llm.dispatcher.server'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(base))",
  'file': 'core/llm/dispatcher/tests/test_deep_tmp_storage.py',
  'kind': 'object',
  'line': 19},
 {'anchor': ['test_failed_server_setup_closes_deep_directory_pin'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(base))",
  'consumers': ['core.llm.dispatcher.server'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(base))",
  'file': 'core/llm/dispatcher/tests/test_deep_tmp_storage.py',
  'kind': 'object',
  'line': 43},
 {'anchor': ['test_compact_socket_uses_captured_service_base_not_later_environment'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(tempfile, 'tempdir', str(deep))",
  'consumers': ['core.llm.dispatcher.server'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(deep))",
  'file': 'core/llm/dispatcher/tests/test_service_tmp_base.py',
  'kind': 'object',
  'line': 22},
 {'anchor': ['TestSocketPathBudget', 'test_surrogate_tmpdir_falls_back_instead_of_crashing'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(_tempfile, 'tempdir', None)",
  'consumers': ['core.llm.dispatcher.server'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', None)",
  'file': 'core/llm/dispatcher/tests/test_lifecycle.py',
  'kind': 'object',
  'line': 498},
 {'anchor': ['TestSocketPathBudget', 'test_surrogate_tmpdir_within_budget_stays'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(_tempfile, 'tempdir', None)",
  'consumers': ['core.llm.dispatcher.server'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', None)",
  'file': 'core/llm/dispatcher/tests/test_lifecycle.py',
  'kind': 'object',
  'line': 546},
 {'anchor': ['test_launcher_restores_environment_and_keeps_controls_outside_work'],
  'attribute': 'tempdir',
  'call': "monkeypatch.setattr(boundary.tempfile, 'tempdir', str(long_base))",
  'consumers': ['packages.web._browser_sandbox'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(long_base))",
  'file': 'packages/web/tests/test_browser_sandbox_policy.py',
  'kind': 'object',
  'line': 80},
 {'attribute': 'tempdir',
  'call': '_tempfile.tempdir = None',
  'consumers': ['core.llm.dispatcher.server'],
  'expected': '_tempfile_owner.tempfile.tempdir = None',
  'file': 'core/llm/dispatcher/tests/test_lifecycle.py',
  'kind': 'assignment',
  'line': 451,
  'statement': '_tempfile.tempdir = None'},
 {'attribute': 'tempdir',
  'call': '_tempfile.tempdir = None',
  'consumers': ['core.llm.dispatcher.server'],
  'expected': '_tempfile_owner.tempfile.tempdir = None',
  'file': 'core/llm/dispatcher/tests/test_lifecycle.py',
  'kind': 'assignment',
  'line': 470,
  'statement': '_tempfile.tempdir = None'}]


@lru_cache(maxsize=None)
def _native(file):
    name = "private_tmp_native_" + file.replace("/", "_").replace(".", "_")
    loader = importlib.machinery.SourceFileLoader(name, str(_REPO / file))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()), pytest.MonkeyPatch.context() as scope:
        scope.setitem(sys.modules, name, module)
        loader.exec_module(module)
    return module


def _namespace(owner, before):
    assert vars(owner).keys() == before.keys(), owner.__name__
    assert all(vars(owner)[name] is value for name, value in before.items()), owner.__name__


def _snapshots(row, native, inherited, borrowed):
    owners = [importlib.import_module(name) for name in row["consumers"]]
    if borrowed:
        view = module_function_view(owners[0].tempfile)
        for owner in owners:
            inherited.setattr(owner, "tempfile", view)
        inherited.setitem(vars(native), "tempfile", view)
    modules = [tempfile, native, *owners, *[owner.tempfile for owner in owners]]
    return [(module, dict(vars(module))) for module in modules]


@lru_cache(maxsize=None)
def _statement_template(index):
    row = _SITES[index]
    tree = ast.parse((_REPO / row["file"]).read_text())
    original = ast.parse(row["call"]).body[0]
    changed = ast.parse(row["expected"]).body[0]
    fingerprints = {ast.dump(original), ast.dump(changed)}
    matches = [node for node in ast.walk(tree) if isinstance(node, type(original)) and ast.dump(node) in fingerprints]
    if row["kind"] != "assignment":
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        anchored = []
        for node in matches:
            chain = []
            parent = parents.get(node)
            while parent:
                if isinstance(parent, (ast.FunctionDef, ast.ClassDef)):
                    chain.append(parent.name)
                parent = parents.get(parent)
            if chain[::-1] == row["anchor"]:
                anchored.append(node)
        matches = anchored
    assert matches, row
    rank = sum(other["file"] == row["file"] and other["call"] == row["call"] and other["line"] < row["line"] and (row["kind"] == "assignment" or other.get("anchor") == row.get("anchor")) for other in _SITES)
    return sorted(matches, key=lambda node: (node.lineno, node.col_offset))[rank]


def _statement(index):
    # Fault injection mutates this tree; never publish the cached template.
    return copy.deepcopy(_statement_template(index))


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda index: _SITES[index]["file"] + ":" + str(_SITES[index]["line"]))
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_temporary_root_fault_owns_namespace(index, borrowed, exit_mode):
    row = _SITES[index]
    native = _native(row["file"])
    with pytest.MonkeyPatch.context() as inherited:
        snapshots = _snapshots(row, native, inherited, borrowed)
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                fixture = getattr(native, "_owned_tempfile_namespace", None)
                if fixture is not None:
                    fixture.__wrapped__(scope)
                namespace = dict(vars(native), monkeypatch=scope, patch=scope, patcher=scope)
                namespace.setdefault("tempfile", tempfile)
                namespace.setdefault("_tempfile", tempfile)
                namespace.setdefault("_tempfile_owner", importlib.import_module(row["consumers"][0]))
                statement = _statement(index)
                token = object()
                namespace["_owned_value"] = token
                if row["kind"] == "assignment":
                    target = statement.targets[0]
                    statement.value = ast.Name(id="_owned_value", ctx=ast.Load())
                    owner_expr = copy.deepcopy(target.value)
                    assigned_owner = eval(compile(ast.fix_missing_locations(ast.Expression(copy.deepcopy(owner_expr))), row["file"], "eval"), namespace)
                    # Counterfactual source contains an unregistered assignment.
                    # Save its exact inherited value before executing it.
                    scope.setattr(assigned_owner, row["attribute"], getattr(assigned_owner, row["attribute"]))
                else:
                    call = statement.value
                    call.args[-1] = ast.Name(id="_owned_value", ctx=ast.Load())
                    if isinstance(call.args[0], ast.Constant):
                        # Original string patches target the canonical stdlib.
                        owner_expr = ast.Name(id="tempfile", ctx=ast.Load())
                    else:
                        owner_expr = copy.deepcopy(call.args[0])
                exec(compile(ast.fix_missing_locations(ast.Module(body=[statement], type_ignores=[])), row["file"], "exec"), namespace)
                for owner, before in snapshots:
                    if owner is not native and owner not in [importlib.import_module(name) for name in row["consumers"]]:
                        _namespace(owner, before)
                actual = eval(compile(ast.fix_missing_locations(ast.Expression(owner_expr)), row["file"], "eval"), namespace)
                assert getattr(actual, row["attribute"]) is token
                if exit_mode != "normal":
                    raise RuntimeError("temporary scope exit") if exit_mode == "error" else KeyboardInterrupt("temporary scope exit")
        except BaseException as error:
            caught = error
        for owner, before in snapshots:
            _namespace(owner, before)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "temporary scope exit"


@pytest.mark.parametrize("index", list({row["file"]: index for index, row in enumerate(_SITES)}.values()), ids=lambda index: _SITES[index]["file"])
@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_temporary_namespace_control(index, borrowed):
    row = _SITES[index]
    native = _native(row["file"])
    with pytest.MonkeyPatch.context() as inherited:
        for owner, before in _snapshots(row, native, inherited, borrowed):
            _namespace(owner, before)

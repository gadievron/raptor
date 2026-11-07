"""Storage fault injections own consumer bindings and real allocations."""
import ast
import copy
from contextlib import ExitStack
from functools import lru_cache
import importlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile

import pytest

from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import module_function_view

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'anchor': ['test_rule_write_failure_removes_partial_file'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'consumers': ['core.run.scratch'],
  'expected': "patch_module_attribute(monkeypatch, _storage_fault_consumer, 'tempfile', "
              "'NamedTemporaryFile', Broken)",
  'file': 'core/audit/tests/test_temp_setup_cleanup.py',
  'kind': 'module',
  'line': 55,
  'original': "monkeypatch.setattr(tempfile, 'NamedTemporaryFile', Broken)"},
 {'anchor': ['TestExcerptTreeKeepalive', '_isolated'],
  'attribute': 'tempdir',
  'binding': 'tempfile',
  'consumers': ['core.audit.corpus.run_corpus'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))",
  'file': 'core/audit/corpus/tests/test_run_corpus.py',
  'kind': 'temp',
  'line': 1698,
  'original': "monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))"},
 {'anchor': ['TestAnonymousFd', 'test_unlinked_tempfile_branch'],
  'attribute': 'tempdir',
  'binding': 'tempfile',
  'consumers': ['core.sandbox.evidence'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))",
  'file': 'core/sandbox/tests/test_evidence.py',
  'kind': 'temp',
  'line': 320,
  'original': "monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))"},
 {'anchor': ['test_observe_reclaims_restricted_output'],
  'attribute': 'gettempdir',
  'binding': 'tempfile',
  'consumers': ['core.run.scratch', 'core.sandbox.observe_cli'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: str(tmp_path))",
  'file': 'core/sandbox/tests/test_scratch_owner_cleanup.py',
  'kind': 'temp',
  'line': 29,
  'original': "monkeypatch.setattr('tempfile.gettempdir', lambda: str(tmp_path))"},
 {'anchor': ['test_observe_keepalive_tracks_context_ownership'],
  'attribute': 'gettempdir',
  'binding': 'tempfile',
  'consumers': ['core.run.scratch', 'core.sandbox.observe_cli'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: str(tmp_path))",
  'file': 'core/sandbox/tests/test_scratch_owner_cleanup.py',
  'kind': 'temp',
  'line': 180,
  'original': "monkeypatch.setattr('tempfile.gettempdir', lambda: str(tmp_path))"},
 {'anchor': ['test_executable_fallback_is_kept_alive_until_scope_ends'],
  'attribute': 'gettempdir',
  'binding': 'tempfile',
  'consumers': ['core.run.scratch', 'core.sandbox.observe_cli'],
  'expected': "monkeypatch.setattr(_tempfile_owner.tempfile, 'gettempdir', lambda: str(tmp_path))",
  'file': 'core/sandbox/tests/test_scratch_owner_cleanup.py',
  'kind': 'temp',
  'line': 211,
  'original': "monkeypatch.setattr('tempfile.gettempdir', lambda: str(tmp_path))"},
 {'anchor': ['TestUnverifiableOwnerDirs', 'test_unremovable_dir_not_reported_reaped'],
  'attribute': 'rmtree',
  'binding': 'shutil',
  'consumers': ['core.atomic_fs'],
  'expected': "patch_module_attribute(monkeypatch, _storage_fault_consumer, 'shutil', 'rmtree', "
              'lambda *a, **kw: None)',
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'module',
  'line': 1538,
  'original': "monkeypatch.setattr(shutil, 'rmtree', lambda *a, **kw: None)"},
 {'anchor': ['TestMidSweepVanish', 'test_vanish_between_identity_check_and_rmtree_never_crashes'],
  'attribute': 'rmtree',
  'binding': 'shutil',
  'consumers': ['core.atomic_fs'],
  'expected': "patch_module_attribute(monkeypatch, _storage_fault_consumer, 'shutil', 'rmtree', "
              'racing_rmtree)',
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'module',
  'line': 1620,
  'original': "monkeypatch.setattr(shutil, 'rmtree', racing_rmtree)"},
 {'anchor': ['test_failed_retirement_is_not_reported_as_success'],
  'attribute': 'rmtree',
  'binding': 'shutil',
  'consumers': ['core.atomic_fs'],
  'expected': "patch_module_attribute(monkeypatch, _storage_fault_consumer, 'shutil', 'rmtree', "
              'blocked)',
  'file': 'core/inventory/tests/test_checklist_replacement.py',
  'kind': 'module',
  'line': 106,
  'original': "monkeypatch.setattr(shutil, 'rmtree', blocked)"},
 {'anchor': ['test_cleanup_refuses_unsafe_recursive_implementation'],
  'attribute': 'rmtree',
  'binding': 'shutil',
  'consumers': ['core.sandbox._spawn'],
  'expected': "patch_module_attribute(monkeypatch, _storage_fault_consumer, 'shutil', 'rmtree', "
              'unsafe)',
  'file': 'core/sandbox/tests/test_cleanup_stub_boundary.py',
  'kind': 'module',
  'line': 54,
  'original': "monkeypatch.setattr(shutil, 'rmtree', unsafe)"}]


@lru_cache(maxsize=None)
def _native(file):
    name = "owned_storage_" + file.replace("/", "_").replace(".", "_")
    loader = importlib.machinery.SourceFileLoader(name, str(_REPO / file))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as scope:
        scope.setitem(sys.modules, name, module)
        loader.exec_module(module)
    return module


def _namespace(owner, before):
    assert vars(owner).keys() == before.keys()
    assert all(vars(owner)[key] is value for key, value in before.items())


@lru_cache(maxsize=None)
def _statement(index):
    row = _SITES[index]
    tree = ast.parse((_REPO / row["file"]).read_text())
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    keys = {ast.dump(ast.parse(row[key], mode="eval").body) for key in ("original", "expected")}
    matches = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or ast.dump(node) not in keys:
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
    return matches[0]


def _site(index, native, owners, scope, value):
    call = copy.deepcopy(_statement(index))
    call.args[-1] = ast.Name(id="value", ctx=ast.Load())
    namespace = dict(vars(native), monkeypatch=scope, tempfile=tempfile, shutil=shutil,
                     _tempfile_owner=owners[0], _storage_fault_consumer=owners[0],
                     patch_module_attribute=patch_module_attribute, value=value)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.Expr(call)], type_ignores=[])), _SITES[index]["file"], "exec"), namespace)


def _fixture(native, scope):
    fixture = getattr(native, "_owned_storage_tempfile", None)
    if fixture is not None:
        fixture.__wrapped__(scope)


def _borrow(row, native, inherited, borrowed):
    owners = [importlib.import_module(name) for name in row["consumers"]]
    original = getattr(owners[0], row["binding"])
    if borrowed:
        view = module_function_view(original)
        for owner in owners:
            inherited.setattr(owner, row["binding"], view)
    modules = [native, tempfile, shutil, *owners, *[getattr(owner, row["binding"]) for owner in owners]]
    return owners, [(module, vars(module).copy()) for module in modules]


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: _SITES[i]["file"] + ":" + str(_SITES[i]["line"]))
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_native_storage_fault_keeps_caller_namespace(index, borrowed, outcome):
    row = _SITES[index]
    native = _native(row["file"])
    with pytest.MonkeyPatch.context() as inherited:
        owners, snapshots = _borrow(row, native, inherited, borrowed)
        token = lambda *a, **kw: None
        value = object() if row["attribute"] == "tempdir" else token
        failure = RuntimeError("storage fault") if outcome == "error" else KeyboardInterrupt("storage fault")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                _fixture(native, scope)
                _site(index, native, owners, scope, value)
                for owner, before in snapshots:
                    if owner is not native and owner not in owners:
                        _namespace(owner, before)
                for owner in owners:
                    assert getattr(getattr(owner, row["binding"]), row["attribute"]) is value
                if outcome != "normal":
                    raise failure
        except BaseException as error:
            caught = error
        for owner, before in snapshots:
            _namespace(owner, before)
        assert caught is (None if outcome == "normal" else failure), repr(caught)


@pytest.mark.parametrize("index", [i for i, row in enumerate(_SITES) if row["kind"] == "temp"], ids=lambda i: str(i))
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_real_temp_allocations_use_the_native_fault_view(index, borrowed, outcome, tmp_path):
    row = _SITES[index]
    native = _native(row["file"])
    with pytest.MonkeyPatch.context() as inherited:
        owners, snapshots = _borrow(row, native, inherited, borrowed)
        failure = RuntimeError("real allocation") if outcome == "error" else KeyboardInterrupt("real allocation")
        caught = None
        paths = []
        try:
            with ExitStack() as cleanup, pytest.MonkeyPatch.context() as scope:
                _fixture(native, scope)
                value = str(tmp_path) if row["attribute"] == "tempdir" else lambda: str(tmp_path)
                _site(index, native, owners, scope, value)
                for owner in owners:
                    assert owner.tempfile is not tempfile
                    directory = Path(owner.tempfile.mkdtemp(prefix="storage-view-"))
                    cleanup.callback(shutil.rmtree, directory, ignore_errors=True)
                    paths.append(directory)
                    assert directory.parent == tmp_path
                    fd, name = owner.tempfile.mkstemp(prefix="storage-fd-")
                    cleanup.callback(os.close, fd)
                    cleanup.callback(Path(name).unlink, missing_ok=True)
                    paths.append(Path(name))
                    os.write(fd, b"owned")
                    assert Path(name).parent == tmp_path
                    assert Path(name).read_bytes() == b"owned"
                for owner, before in snapshots:
                    if owner is not native and owner not in owners:
                        _namespace(owner, before)
                if outcome != "normal":
                    raise failure
        except BaseException as error:
            caught = error
        for owner, before in snapshots:
            _namespace(owner, before)
        assert paths and all(not path.exists() for path in paths)
        assert caught is (None if outcome == "normal" else failure), repr(caught)


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_shared_writer_tracks_real_descriptors_without_global_allocator_mock(borrowed, outcome, tmp_path):
    import core.atomic_fs as atomic
    native = _native("core/atomic_fs/tests/test_writer_consumers.py")
    with pytest.MonkeyPatch.context() as inherited:
        if borrowed:
            inherited.setattr(atomic, "os", module_function_view(atomic.os))
        snapshots = [(owner, vars(owner).copy()) for owner in (native, atomic, atomic.os, tempfile, os)]
        failure = RuntimeError("writer scope") if outcome == "error" else KeyboardInterrupt("writer scope")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                opened = native.descriptors(scope)
                _namespace(tempfile, snapshots[3][1])
                _namespace(os, snapshots[4][1])
                target = tmp_path / "state"
                atomic.write_text_atomically(target, "complete")
                assert opened, "the real writer allocation must reach the tracker"
                native.assert_closed(opened)
                assert target.read_text() == "complete"
                if outcome != "normal":
                    raise failure
        except BaseException as error:
            caught = error
        for owner, before in snapshots:
            _namespace(owner, before)
        assert caught is (None if outcome == "normal" else failure), repr(caught)


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda i: str(i))
@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_storage_fault_control(index, borrowed):
    row = _SITES[index]
    native = _native(row["file"])
    with pytest.MonkeyPatch.context() as inherited:
        _, snapshots = _borrow(row, native, inherited, borrowed)
        for owner, before in snapshots:
            _namespace(owner, before)

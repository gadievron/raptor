"""Cache fixtures own replacements and preserve inherited objects on every exit."""

import importlib
import importlib.util
import inspect
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[3]
CASES = [['packages/sca/resolvers/tests/conftest.py', 'packages.sca.resolvers', '_clear_check_tool_cache', ['_CHECK_TOOL_CACHE'], None, None], ['packages/sca/tests/conftest.py', 'packages.sca.resolvers', '_stub_resolver_tool_probes_at_session_start', ['_CHECK_TOOL_CACHE'], None, None], ['packages/sca/tests/conftest.py', 'packages.sca.resolvers', 'unstub_check_tool_cache', ['_CHECK_TOOL_CACHE'], None, None], ['packages/exploitability_validation/tests/conftest.py', 'core.project.trust', '_fresh_gate_pin_memo', ['_gate_pin_memo'], None, None], ['core/project/tests/test_trust_consumption.py', 'core.project.trust', 'setUp', ['_gate_pin_memo'], 'TrustProjectFixture', None], ['core/project/tests/test_trust_consumption.py', 'core.project.trust', 'setUp', ['_gate_pin_memo'], 'TestOneTargetRuleFollowsPin', None], ['core/inventory/tests/test_lookup.py', 'core.inventory.lookup', 'setUp', ['_INDEX_CACHE'], 'TestFileIndexCache', None], ['core/audit/tests/test_context.py', 'core.audit.context', '_owned_kernel_cache', ['_kernel_file_cache'], 'TestKernelMarkerSniff', 'setup_method'], ['core/concepts/tests/test_audit_bridge.py', 'core.concepts.audit_bridge', '_owned_study_list_cache', ['_study_list_cache'], 'TestStudyListStructuralContext', 'setup_method'], ['packages/static-analysis/tests/test_scanner_semgrep_parallel.py', 'packages.static-analysis.scanner', '_owned_dropped_registry_packs', ['_dropped_registry_packs'], 'TestDropUnreachableRegistryPacks', 'setup_method'], ['core/engagement/tests/conftest.py', 'core.inventory.checklist_frame_mac', '_isolated_frame_key', ['_warned_unstamped', '_warned_relocated', '_warned_key_paths', '_warned_absent_key'], None, None], ['core/sage/tests/test_rowmac.py', 'core.sage.rowmac', 'setUp', ['_warned_paths'], 'RowMacKeyTmpDirCase', None], ['core/sage/tests/test_rowmac_key_guard.py', 'core.sage.rowmac', 'setUp', ['_warned_paths'], '_KeyDirCase', None], ['core/audit/tests/test_disasm_xcheck.py', 'core.audit.disasm_xcheck', '_fresh_channel_state', ['_SPAWN_COUNTS', '_WINDOW_MEMO'], None, None]]


def _load(path, monkeypatch):
    name = "owned_cache_fixture_module"
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(module)
    return module


def _borrowed(original):
    if hasattr(original, "get_or_compute"):
        value = type(original)(original._max_entries)
        value.get_or_compute("borrowed", lambda: None)
        return value
    value = type(original)()
    if isinstance(value, dict):
        value["borrowed"] = None
    elif isinstance(value, set):
        value.add("borrowed")
    else:
        value.append("borrowed")
    return value


def _contents(value):
    if hasattr(value, "get_or_compute"):
        return dict(value._values), dict(value._key_locks), value.hit_count, value.miss_count
    return value.copy()


@pytest.mark.parametrize("case", CASES, ids=[str(i) for i in range(len(CASES))])
@pytest.mark.parametrize("mode", ["normal", "body_error", "interrupt", "publication_error"])
def test_cache_fixture_restores_borrowed_state(case, mode, tmp_path, monkeypatch):
    path, owner_name, method, names, class_name, legacy = case
    module = _load(path, monkeypatch)
    owner = (module._scanner_mod if owner_name == "packages.static-analysis.scanner"
             else importlib.import_module(owner_name))
    borrowed = {name: _borrowed(getattr(owner, name)) for name in names}
    before = {name: _contents(value) for name, value in borrowed.items()}
    for name, value in borrowed.items():
        monkeypatch.setattr(owner, name, value)
    instance = getattr(module, class_name)() if class_name else None
    target = instance if instance is not None else module
    function = getattr(target, method, None)
    if function is None:
        function = getattr(target, legacy)
    function = getattr(function, "__wrapped__", function)
    if instance is not None and not inspect.ismethod(function):
        function = function.__get__(instance, type(instance))
    owned = pytest.MonkeyPatch()
    generator = None
    class Failure(Exception):
        pass
    real_setattr = pytest.MonkeyPatch.setattr
    def publish(patcher, obj, name, value, *args, **kwargs):
        real_setattr(patcher, obj, name, value, *args, **kwargs)
        if mode == "publication_error" and obj is owner and name in names:
            raise Failure("after cache publication")
    try:
        with patch.object(pytest.MonkeyPatch, "setattr", publish):
            try:
                kwargs = {key: value for key, value in {
                    "monkeypatch": owned, "tmp_path": tmp_path,
                }.items() if key in inspect.signature(function).parameters}
                generator = function(**kwargs)
                if inspect.isgenerator(generator):
                    next(generator)
                for name in names:
                    getattr(owner, name).clear()
                if mode in {"body_error", "interrupt"}:
                    raise Failure if mode == "body_error" else KeyboardInterrupt
            except (Failure, KeyboardInterrupt):
                pass
            finally:
                if inspect.isgenerator(generator):
                    generator.close()
                if instance is not None:
                    if hasattr(instance, "doCleanups"):
                        instance.doCleanups()
                    elif hasattr(instance, "teardown_method"):
                        instance.teardown_method()
                owned.undo()
        for name in names:
            assert getattr(owner, name) is borrowed[name], name
            assert _contents(borrowed[name]) == before[name], name
    finally:
        owned.undo()


@pytest.mark.parametrize("case", [CASES[0], CASES[2]], ids=["resolver", "unstub"])
@pytest.mark.parametrize("interrupt", [False, True])
def test_resolver_cache_body_patch_unwinds_before_borrowed_restore(
        case, interrupt, tmp_path, monkeypatch):
    path, owner_name, method, _, _, _ = case
    module = _load(path, monkeypatch)
    owner = importlib.import_module(owner_name)
    borrowed = {("borrowed", "--version"): False}
    monkeypatch.setattr(owner, "_CHECK_TOOL_CACHE", borrowed)
    owned = pytest.MonkeyPatch()
    function = getattr(module, method).__wrapped__
    kwargs = {"monkeypatch": owned} if "monkeypatch" in inspect.signature(function).parameters else {}
    generator = function(**kwargs)
    try:
        next(generator)
        owned.setattr(owner, "_CHECK_TOOL_CACHE", {})
        if interrupt:
            raise KeyboardInterrupt
    except KeyboardInterrupt:
        pass
    finally:
        generator.close()
        owned.undo()
    assert owner._CHECK_TOOL_CACHE is borrowed
    assert borrowed == {("borrowed", "--version"): False}

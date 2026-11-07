"""Native discovery overrides preserve shared namespaces and inherited caches."""

import ast
from contextlib import ExitStack
import concurrent.futures
import ctypes
import ctypes.util
from functools import lru_cache
import importlib
import json
import os
import platform
from pathlib import Path
from pkgutil import resolve_name
import shutil
from unittest.mock import Mock

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute
from core.testing.module_views import scoped_function_imports


ROOT = Path(__file__).resolve().parents[3]
SITES = json.loads((Path(__file__).parent / "data/remaining_discovery_sites.json").read_text())


def _native_call(site):
    tree = ast.parse((ROOT / site["file"]).read_text())
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    matches = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or ast.unparse(node) != site["new"]:
            continue
        names = []
        parent = node
        while id(parent) in parents:
            parent = parents[id(parent)]
            if isinstance(parent, (ast.FunctionDef, ast.ClassDef)):
                names.append(parent.name)
        if list(reversed(names)) == site["anchor"]:
            matches.append(node)
    assert len(matches) == 1, site
    return matches[0]


def _unchanged(owner, before):
    assert vars(owner).keys() == before.keys(), owner.__name__
    assert all(vars(owner)[key] is value for key, value in before.items()), owner.__name__


@pytest.mark.parametrize("site", SITES, ids=[f"{x['file']}:{x['line']}" for x in SITES])
@pytest.mark.parametrize("finish", ["normal", "error", "interrupt"])
def test_native_override_restores_lookup_owners(site, finish, tmp_path):
    native = importlib.import_module(site["file"][:-3].replace("/", "."))
    owners = [resolve_name(name) for name in (
        "core.analysis.binary_oracle_edges", "core.audit.capabilities", "core.audit.context",
        "core.llm.cc_adapter", "core.sandbox.tracer", "core.sandbox.probes", "core.sandbox.seccomp",
        "core.sandbox._spawn", "packages.describe.package_manager", "packages.joern.prereqs",
        "packages.codeql", "core.recall.score", "core.run.toolprobe",
    )]
    # Import all lazy stdlib branches before recording borrowed namespaces.
    for attribute in ("ProcessPoolExecutor", "ThreadPoolExecutor"):
        getattr(concurrent.futures, attribute)
    stdlib = [shutil, ctypes, ctypes.util, os, os.path, concurrent, concurrent.futures, platform]
    borrowed = [*stdlib, *owners, native]
    if site["file"].endswith("test_budget_terminal.py"):
        borrowed.append(resolve_name("core.audit.orchestrator"))
    if site["file"].endswith("test_install_guard.py"):
        borrowed.append(native.guard)
    snapshots = [(owner, dict(vars(owner))) for owner in borrowed]
    scope = pytest.MonkeyPatch()
    replacement = Mock(name="owned discovery", return_value=None)
    namespace = dict(vars(native), monkeypatch=scope, replacement=replacement,
                     mock_module_attribute=mock_module_attribute, patch_module_attribute=patch_module_attribute)
    try:
        with ExitStack() as stack:
            stack.callback(scope.undo)
            fixture = (getattr(native, "_owned_discovery_imports", None)
                       or getattr(native, "_owned_catalog_discovery", None)
                       or getattr(native, "_owned_package_manager_cache", None))
            if fixture is not None:
                generator = fixture.__wrapped__(scope)
                next(generator)
                stack.callback(generator.close)
                namespace.update(vars(native))
            if site["file"].endswith("test_budget_terminal.py"):
                namespace['orch'] = resolve_name('core.audit.orchestrator')
                namespace['imports'] = stack.enter_context(scoped_function_imports(
                    namespace['orch'], ('_run_audit_body',), {'concurrent.futures': concurrent.futures}))
            if site["file"].endswith("test_install_guard.py"):
                namespace['imports'] = stack.enter_context(scoped_function_imports(
                    native.guard, ('precompile',), {'concurrent.futures': concurrent.futures}))
            namespace.update(boe=owners[0], sc=owners[6], probes=owners[5])
            if site['anchor'][-1] == 'test_no_unshare':
                from core.sandbox import state
                from core.testing.module_state import isolated_module_state
                stack.enter_context(isolated_module_state(state, {
                    '_net_available_cache': None, '_unshare_path_cache': None,
                }))
                namespace['imports'] = stack.enter_context(scoped_function_imports(
                    owners[5], ('_resolve_sandbox_binary',), {'os': os}))
            if site['helper'] == '_validate_path_lookup':
                namespace['scanner'] = native._make_scanner(str(tmp_path))
            node = ast.parse(ast.unparse(_native_call(site)), mode='eval').body
            if site['helper'] == '_owned_toolchain_discovery':
                node.args = [node.args[0], ast.Name(id='replacement', ctx=ast.Load())]
            elif site['helper'] in ('_missing_tool_discovery', '_validate_path_lookup'):
                node.keywords = [ast.keyword(arg='new', value=ast.Name(id='replacement', ctx=ast.Load()))]
            elif site['kind'] == 'monkey':
                node.args = node.args[:4] + [ast.Name(id='replacement', ctx=ast.Load())]
            else:
                node.args = node.args[:3]
                node.keywords = [ast.keyword(arg='new', value=ast.Name(id='replacement', ctx=ast.Load()))]
            value = eval(compile(ast.fix_missing_locations(ast.Expression(node)), site['file'], 'eval'), namespace)
            if site['kind'] == 'mock':
                assert stack.enter_context(value) is replacement
            # Borrowed stdlib functions remain untouched while the override is active.
            for owner, before in snapshots[:len(stdlib)]:
                _unchanged(owner, before)
            if site['helper'] == '_owned_toolchain_discovery':
                assert all(owner.shutil.which is replacement for owner in owners[-3:])
            elif site['helper'] == '_missing_tool_discovery':
                assert owners[1].shutil.which is replacement
                assert owners[9].shutil.which is replacement
            elif site['helper'] == '_validate_path_lookup':
                scanner = namespace['scanner']
                assert '_phase_validate' in vars(scanner)
                assert type(scanner)._phase_validate is not scanner._phase_validate
            else:
                offset = int(site['kind'] == 'monkey')
                owner = eval(compile(ast.Expression(node.args[offset]), site['file'], 'eval'), namespace)
                binding, attribute = (ast.literal_eval(arg) for arg in node.args[offset + 1:offset + 3])
                view = getattr(owner, binding, None)
                if view is None:
                    view = owner
                    for part in binding.split('.'):
                        view = getattr(view, part)
                assert getattr(view, attribute) is replacement
            if site['anchor'][-1] == 'test_no_unshare':
                with pytest.raises(FileNotFoundError):
                    owners[5]._resolve_sandbox_binary('unshare')
            if finish == 'error':
                raise RuntimeError('discovery exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('discovery exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        scope.undo()
        for owner, before in snapshots:
            _unchanged(owner, before)


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_doctor_retains_warm_borrowed_package_manager_cache(finish, monkeypatch, capsys):
    from packages.describe import package_manager as pm
    from core.startup.tests import test_doctor as native

    borrowed = lru_cache(maxsize=1)(pm.detect_package_manager.__wrapped__)
    monkeypatch.setattr(pm, 'detect_package_manager', borrowed)
    with pytest.MonkeyPatch.context() as prime:
        patch_module_attribute(prime, pm, 'shutil', 'which', lambda name: name == 'dnf')
        assert borrowed() == 'dnf'
    before = borrowed.cache_info()
    scope = pytest.MonkeyPatch()
    fixture = native._owned_package_manager_cache.__wrapped__(scope)
    try:
        next(fixture)
        native.TestOutputShape().test_install_hint_attached_to_missing_tool_warning(capsys, scope)
        assert pm.detect_package_manager is not borrowed
        assert borrowed.cache_info() == before
        if finish == 'error':
            raise RuntimeError('cache exit')
        if finish == 'interrupt':
            raise KeyboardInterrupt('cache exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        fixture.close()
        scope.undo()
    assert pm.detect_package_manager is borrowed
    assert borrowed.cache_info() == before
    assert borrowed() == 'dnf'


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_catalog_fixture_retains_inherited_cache(finish, monkeypatch):
    from core.audit import context
    from core.audit.tests import test_context as native

    inherited = 'inherited catalog'
    monkeypatch.setattr(context, '_tool_catalog_cache', inherited)
    scope = pytest.MonkeyPatch()
    fixture = native._owned_catalog_discovery.__wrapped__(scope)
    try:
        next(fixture)
        patch_module_attribute(scope, native._discovery_imports, 'shutil', 'which', lambda name: None)
        assert 'Semgrep' not in context._get_tool_catalog()
        if finish == 'error':
            raise RuntimeError('cache exit')
        if finish == 'interrupt':
            raise KeyboardInterrupt('cache exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        fixture.close()
        scope.undo()
    assert context._tool_catalog_cache is inherited


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_scanner_lookup_is_bound_only_to_owned_instance(finish, tmp_path):
    from packages.web.tests import test_scanner_boundaries as native

    scanner = native._make_scanner(str(tmp_path / 'owned'))
    sibling = native._make_scanner(str(tmp_path / 'sibling'))
    original = type(scanner)._phase_validate
    assert '_phase_validate' not in vars(scanner)
    try:
        with native._validate_path_lookup(scanner, return_value='/owned/claude'):
            assert type(scanner)._phase_validate is original
            assert sibling._phase_validate.__func__ is original
            assert '_phase_validate' in vars(scanner)
            if finish == 'error':
                raise RuntimeError('instance exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('instance exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    assert '_phase_validate' not in vars(scanner)
    assert scanner._phase_validate.__func__ is original


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_missing_tools_ignore_warm_joern_paths(finish, monkeypatch):
    from core.audit.tests import test_capabilities as native
    from packages.joern import prereqs

    inherited = {
        '_resolved_joern': '/owned/joern', '_joern_resolved': True,
        '_resolved_joern_parse': '/owned/joern-parse', '_joern_parse_resolved': True,
        '_resolved_java': '/owned/java', '_java_resolved': True,
    }
    for key, value in inherited.items():
        monkeypatch.setattr(prereqs, key, value)
    monkeypatch.setattr(prereqs, '_java_version', lambda: prereqs.MIN_JAVA_VERSION)
    monkeypatch.setattr(prereqs, 'meets_min_version', lambda: True)
    assert prereqs.check_prereqs() == []
    native.TestProbeCapabilities().test_all_tools_missing()
    try:
        with native._missing_tool_discovery(return_value=None):
            assert prereqs._joern_path() is None
            assert prereqs._joern_parse_path() is None
            if finish == 'error':
                raise RuntimeError('cache exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('cache exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    assert all(getattr(prereqs, key) is value for key, value in inherited.items())


@pytest.mark.parametrize('module_name,fixture_name', [
    ('core.audit.tests.test_context', '_owned_catalog_discovery'),
    ('core.audit.tests.test_validate', '_owned_discovery_imports'),
    ('core.orchestration.tests.test_agentic_passes', '_owned_discovery_imports'),
])
@pytest.mark.parametrize('exception', [RuntimeError, KeyboardInterrupt])
def test_discovery_fixture_publication_failure_unwinds(module_name, fixture_name, exception):
    native = importlib.import_module(module_name)
    from core.audit import context
    from core.llm import cc_adapter

    snapshots = [(owner, dict(vars(owner))) for owner in (native, context, cc_adapter)]
    scope = pytest.MonkeyPatch()
    original = scope.setitem

    def fail(mapping, key, value):
        result = original(mapping, key, value)
        if mapping is vars(native) and key == '_discovery_imports':
            raise exception('publication interrupted')
        return result

    scope.setitem = fail
    try:
        generator = getattr(native, fixture_name).__wrapped__(scope)
        with pytest.raises(exception, match='publication interrupted'):
            next(generator)
        for owner, before in snapshots:
            _unchanged(owner, before)
    finally:
        scope.undo()


@pytest.mark.parametrize('loader_name', [
    'core.testing.tests.test_host_interface_fixture_scope',
    'core.testing.tests.test_os_boundary_fixture_scope',
    'core.testing.tests.test_remaining_module_fixture_scope',
])
@pytest.mark.parametrize('inherited', ['absent', 'none', 'module'])
def test_native_guard_reload_preserves_module_identity(loader_name, inherited, monkeypatch):
    import pickle
    import sys
    from types import ModuleType
    from core.startup import install_guard
    from core.startup.tests import test_install_guard as native

    original = native.guard._compile_bytecode
    if inherited == 'absent':
        monkeypatch.delitem(sys.modules, 'install_guard', raising=False)
    else:
        monkeypatch.setitem(sys.modules, 'install_guard', None if inherited == 'none' else ModuleType('caller_guard'))
    before = ('install_guard' in sys.modules, sys.modules.get('install_guard'))
    loader = importlib.import_module(loader_name)
    # Bypass the inventory cache to exercise the actual native-file load again.
    reloaded = loader._native.__wrapped__('core/startup/tests/test_install_guard.py')
    assert ('install_guard' in sys.modules, sys.modules.get('install_guard')) == before
    assert reloaded.guard is native.guard is install_guard
    assert pickle.loads(pickle.dumps(original)) is original


def test_pathname_socket_uses_short_owned_directory(short_socket_dir, tmp_path, monkeypatch):
    import tempfile
    from core.sandbox.tests import test_sandbox as native

    deep = tmp_path / ('ambient-' + 'x' * 110)
    deep.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(deep))
    case = native.TestFdIsolation('test_pass_fds_pathname_socket_rejected_even_declared')
    case._owned_short_socket_directory.__wrapped__(case, short_socket_dir)
    before = list(short_socket_dir.iterdir())
    case.test_pass_fds_pathname_socket_rejected_even_declared()
    assert list(short_socket_dir.iterdir()) == before

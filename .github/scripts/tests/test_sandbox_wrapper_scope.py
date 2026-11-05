"""Mutations prove wrapper selection keeps affected checks and excludes others."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
import sys

import pytest

with patch.object(sys, "path", sys.path.copy()):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import sandbox_wrapper_scope as scope
    from sandbox_wrapper_tests import registry_errors


@pytest.fixture
def tree(tmp_path, monkeypatch):
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(tmp_path / 'summary'))
    def write(name, text):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    registry = {'wrappers': [], 'native': []}
    write('core/shared/helper.py', 'VALUE = 1\n')
    write('core/shared/common.py', 'VALUE = 1\n')
    write('core/unrelated/module.py', 'VALUE = 1\n')
    for name in ('one', 'two'):
        write(f'core/{name}/wrapper.py', 'from core.sandbox import run\nfrom core.shared import common\n'
              + ('from core.shared import helper\n' if name == 'one' else '')
              + 'def dispatch():\n    return run(["true"])\n')
        test = f'core/{name}/tests/test_wrapper.py'
        write(test, f'from core.{name} import wrapper\ndef test_contract():\n    pass\ndef test_native():\n    pass\n')
        registry['wrappers'].append({'source': f'core/{name}/wrapper.py', 'entrypoints': ['dispatch'],
                                      'contracts': [test + '::test_contract']})
        registry['native'].append({'id': name, 'platforms': {
            platform: {'tests': [test + '::test_native'], 'expected': 1}
            for platform in ('linux', 'darwin')}})
    assert registry_errors(tmp_path, registry) == []
    write('.github/sandbox-wrapper-tests.json', json.dumps(registry))
    return tmp_path, registry


def selected(tree, changed):
    root, registry = tree
    matrix = scope.select(root, registry, changed)['include']
    if not matrix:
        return set(), set()
    assert {m['platform'] for m in matrix} == {'linux', 'darwin'}
    assert matrix[0]['contracts'] == matrix[1]['contracts']
    return set(matrix[0]['contracts']), set(matrix[0]['families'])


@pytest.mark.parametrize('changed', ['core/one/wrapper.py', 'core/shared/helper.py', 'core/one/tests/test_wrapper.py'])
def test_specific_wrapper_and_shared_dependency_select_only_affected_cases(tree, changed):
    contracts, families = selected(tree, [changed])
    assert contracts == {'core/one/tests/test_wrapper.py::test_contract'}
    assert families == {'one'}


def test_shared_dependency_selects_both(tree):
    contracts, families = selected(tree, ['core/shared/common.py'])
    assert len(contracts) == 2 and families == {'one', 'two'}


@pytest.mark.parametrize('changed', ['.github/workflows/tests.yml', 'docs/guide.md', 'core/unrelated/module.py'])
def test_unrelated_changes_do_not_start_platform_runners(tree, changed):
    assert selected(tree, [changed]) == (set(), set())


@pytest.mark.parametrize('changed', ['core/one/tests/fixtures/probe.json', 'core/one/tests/fixtures/probe.py'])
def test_fixture_resources_select_their_owner(tree, changed):
    root, _ = tree
    path = root / changed
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('fixture')
    contracts, families = selected(tree, [changed])
    assert len(contracts) == 1 and families == {'one'}


def test_parent_initializer_and_conftest_dependencies(tree):
    root, _ = tree
    (root / 'core/one/__init__.py').write_text('VALUE = 1\n')
    (root / 'core/one/tests/conftest.py').write_text('from core.shared import helper\n')
    for changed in ['core/one/__init__.py', 'core/one/tests/conftest.py']:
        contracts, families = selected(tree, [changed])
        assert len(contracts) == 1 and families == {'one'}


@pytest.mark.parametrize('changed', [None, ['core/sandbox/context.py'], ['uv.lock'], ['conftest.py'], ['libexec/new-wrapper']])
def test_full_coverage_inputs_keep_both_platforms_and_every_case(tree, changed):
    contracts, families = selected(tree, changed)
    assert len(contracts) == 2 and families == {'one', 'two'}


def test_deleted_module_falls_back_to_full(tree):
    root, _ = tree
    (root / 'core/shared/helper.py').unlink()
    assert selected(tree, ['core/shared/helper.py'])[1] == {'one', 'two'}


def test_unparseable_dependency_falls_back_to_full(tree):
    root, _ = tree
    (root / 'core/shared/helper.py').write_text('def broken(')
    assert selected(tree, ['core/one/wrapper.py'])[1] == {'one', 'two'}


@pytest.mark.parametrize('code', [
    'import importlib\nimportlib.import_module(name)\n',
    'from importlib import import_module as load\nload(name)\n',
    'from importlib.util import spec_from_file_location\nspec_from_file_location("name", path)\n',
])
def test_opaque_dynamic_import_broadens_runtime_changes(tree, code):
    root, _ = tree
    path = root / 'core/one/wrapper.py'
    path.write_text(path.read_text() + code)
    assert selected(tree, ['core/unrelated/module.py'])[1] == {'one'}


def test_literal_dynamic_import_with_module_alias_is_followed(tree):
    root, _ = tree
    path = root / 'core/one/wrapper.py'
    path.write_text(path.read_text().replace('from core.shared import helper', 'import importlib as loader\nloader.import_module("core.shared.helper")'))
    assert selected(tree, ['core/shared/helper.py'])[1] == {'one'}


def test_native_platform_exclusion_does_not_become_a_request(tree):
    root, registry = tree
    registry['native'][0]['platforms']['darwin'] = {'reason': 'owned Linux probe'}
    matrix = scope.select(root, registry, ['core/one/wrapper.py'])['include']
    assert matrix[0]['families'] == ['one']
    assert matrix[1]['families'] == []


def test_new_unregistered_caller_fails_before_any_skipping(tree, monkeypatch):
    root, _ = tree
    (root / 'core/unrelated/module.py').write_text('from core.sandbox import run\ndef new():\n    run(["true"])\n')
    monkeypatch.chdir(root)
    monkeypatch.setenv('EVENT', 'push')
    with pytest.raises(SystemExit, match='unregistered sandbox wrapper'):
        scope.main()


def test_cli_always_runs_census_but_skips_unrelated_platform_work(tree, monkeypatch):
    root, _ = tree
    monkeypatch.chdir(root)
    monkeypatch.setenv('EVENT', 'push')
    monkeypatch.setattr(scope, 'changed_paths', lambda *args: ['.github/workflows/tests.yml'])
    output = root / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    scope.main()
    assert 'run=false\n' in output.read_text()


def _lazy_package(root, *, mutate=False):
    package = root / 'core/lazy'
    package.mkdir()
    code = '''_LAZY_EXPORTS = {"chosen": ("core.shared.helper", "VALUE"), "other": ("core.unrelated.module", "VALUE")}
def __getattr__(name):
    spec = _LAZY_EXPORTS.get(name)
    if spec is None:
        raise AttributeError(name)
    module_name, attribute = spec
    import importlib
    value = getattr(importlib.import_module(module_name), attribute)
    globals()[name] = value
    return value
'''
    if mutate:
        code += '_LAZY_EXPORTS["chosen"] = unknown\n'
    (package / '__init__.py').write_text(code)
    path = root / 'core/one/wrapper.py'
    path.write_text(path.read_text().replace('from core.shared import helper', 'from core.lazy import chosen'))


def test_lazy_reexport_tracks_requested_target_without_importing_unused_exports(tree):
    root, _ = tree
    _lazy_package(root)
    assert selected(tree, ['core/shared/helper.py'])[1] == {'one'}
    assert selected(tree, ['core/unrelated/module.py'])[1] == set()


def test_mutable_lazy_table_is_opaque_and_cannot_justify_skipping(tree):
    root, _ = tree
    _lazy_package(root, mutate=True)
    assert selected(tree, ['core/unrelated/module.py'])[1] == {'one'}


def test_shared_opaque_fixture_forces_full_runtime_coverage(tree):
    root, _ = tree
    (root / 'conftest.py').write_text('import importlib\ndef fixture():\n    importlib.import_module(unknown)\n')
    contracts, families = selected(tree, ['core/one/wrapper.py'])
    assert len(contracts) == 2 and families == {'one', 'two'}


def test_lazy_submodule_export_remains_finite_and_keeps_unrelated_runners_idle(tree):
    root, _ = tree
    _lazy_package(root)
    path = root / 'core/lazy/__init__.py'
    text = path.read_text().replace('("core.shared.helper", "VALUE")', '("core.shared.helper", None)')
    text = text.replace('value = getattr(importlib.import_module(module_name), attribute)',
                        'module = importlib.import_module(module_name)\n    value = module if attribute is None else getattr(module, attribute)')
    path.write_text(text)
    assert selected(tree, ['core/shared/helper.py'])[1] == {'one'}
    assert selected(tree, ['core/unrelated/module.py']) == (set(), set())


@pytest.mark.parametrize('invalid', ['(None, "VALUE")', '("core.shared.helper", 1)', '("core.shared.helper", "VALUE", "extra")'],
                         ids=['invalid-module', 'invalid-attribute', 'invalid-arity'])
def test_invalid_lazy_submodule_maps_still_broaden_conservatively(tree, invalid):
    root, _ = tree
    _lazy_package(root)
    path = root / 'core/lazy/__init__.py'
    path.write_text(path.read_text().replace('("core.shared.helper", "VALUE")', invalid))
    assert selected(tree, ['core/unrelated/module.py'])[1] == {'one'}


@pytest.mark.parametrize('changed,reason', [
    (None, 'unavailable change history'),
    (['core/sandbox/context.py'], 'shared sandbox or test-harness'),
    (['core/missing/module.py'], 'deleted Python modules'),
    (['docs/guide.md'], 'No platform runners'),
    (['core/unrelated/module.py'], 'do not affect registered'),
    (['core/one/wrapper.py'], 'Scoped coverage'),
], ids=['unknown-history', 'shared-input', 'deletion', 'irrelevant', 'unrelated-runtime', 'dependency-match'])
def test_explanations_preserve_selection(tree, changed, reason):
    root, registry = tree
    explanations = []
    expected = scope.select(root, registry, changed)
    assert scope.select(root, registry, changed, explanations=explanations) == expected
    assert any(reason in explanation for explanation in explanations)


def test_shared_import_fallback_names_the_opaque_source(tree):
    root, registry = tree
    (root / 'conftest.py').write_text('import importlib\nimportlib.import_module(unknown)\n')
    explanations = []
    matrix = scope.select(root, registry, ['core/unrelated/module.py'], explanations=explanations)
    assert len(matrix['include']) == 2 and all(cell['full'] for cell in matrix['include'])
    assert explanations == ['Full coverage: computed imports in shared pytest dependencies: conftest.py']


def test_unreadable_dependency_reports_a_full_fallback(tree):
    root, registry = tree
    (root / 'core/shared/helper.py').write_text('def broken(')
    explanations = []
    result = scope.select(root, registry, ['core/one/wrapper.py'], explanations=explanations)
    assert all(cell['full'] for cell in result['include'])
    assert explanations == ['Full coverage: wrapper dependencies could not be analysed (SyntaxError).']


def test_selection_summary_escapes_changed_paths(tree, monkeypatch):
    root, _ = tree
    monkeypatch.chdir(root)
    monkeypatch.setenv('EVENT', 'push')
    monkeypatch.setattr(scope, 'changed_paths', lambda *args: ['docs/<owned>&.md'])
    summary = root / 'summary'
    output = root / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(summary))
    scope.main()
    assert 'run=false\n' in output.read_text()
    assert 'No platform runners' in summary.read_text()
    assert 'docs/&lt;owned&gt;&amp;.md' in summary.read_text()
    assert '<owned>' not in summary.read_text()

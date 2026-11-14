"""Mutations prove wrapper selection keeps affected checks and excludes others."""
from __future__ import annotations

import json
from copy import deepcopy
import re
from collections import Counter
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


@pytest.mark.parametrize('changed', [None, ['core/sandbox/context.py'], ['uv.lock'], ['pyproject.toml'], ['conftest.py'], ['libexec/new-wrapper']])
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


@pytest.mark.parametrize('cell', [
    {'reason': 'owned Linux probe'},
    {'reason': 'owned Linux probe', 'tests': None},
    {'reason': 'owned Linux probe', 'tests': []},
], ids=['absent-tests', 'null-tests', 'empty-tests'])
def test_native_platform_exclusion_does_not_become_a_request(tree, cell):
    root, registry = tree
    registry['native'][0]['platforms']['darwin'] = cell
    matrix = scope.select(root, registry, ['core/one/wrapper.py'])['include']
    assert matrix[0]['families'] == ['one']
    assert matrix[1]['families'] == []


@pytest.mark.parametrize('module', ['core.sandbox', 'core.ｓａｎｄｂｏｘ'], ids=['ordinary-import', 'normalized-import'])
def test_new_unregistered_caller_fails_before_any_skipping(tree, monkeypatch, module):
    root, _ = tree
    (root / 'core/unrelated/module.py').write_text(f'from {module} import run\ndef new():\n    run(["true"])\n')
    monkeypatch.chdir(root)
    monkeypatch.setenv('EVENT', 'push')
    monkeypatch.setattr(scope, 'changed_paths', lambda *args: pytest.fail('selection ran before registration'))
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


def _counted_repo(root):
    checks, reads = Counter(), Counter()

    class CountedPath(type(root)):
        def is_file(self):
            checks[self.relative_to(root).as_posix()] += 1
            return super().is_file()

        def read_text(self, *args, **kwargs):
            reads[self.relative_to(root).as_posix()] += 1
            return super().read_text(*args, **kwargs)

    return CountedPath(root), checks, reads


def test_module_resolution_reuses_shared_prefixes_and_returns_owned_results(tree):
    root, _ = tree
    repo, checks, _ = _counted_repo(root)
    graph = scope.Dependencies(repo)
    checks.clear()
    expected = {'core/one/wrapper.py'}
    first = graph.resolve('core.one.wrapper')
    assert first == expected
    before = checks.copy()
    first.clear()
    assert graph.resolve('core.one.wrapper') == expected
    assert checks == before
    graph.resolve('core.one.missing')
    assert checks['core/__init__.py'] == 1
    assert checks['core/one/__init__.py'] == 1
    assert max(checks.values()) == 1


def test_lazy_initializer_is_read_once_when_resolution_precedes_traversal(tree):
    root, _ = tree
    _lazy_package(root)
    repo, _, reads = _counted_repo(root)
    graph = scope.Dependencies(repo)
    assert 'core/shared/helper.py' in graph.resolve('core.lazy.chosen')
    assert 'core/unrelated/module.py' in graph.resolve('core.lazy.other')
    assert graph.direct('core/lazy/__init__.py')[1] is False
    assert reads['core/lazy/__init__.py'] == 1


def test_shared_ancestor_hooks_are_checked_once_per_analysis(tree):
    root, _ = tree
    repo, checks, _ = _counted_repo(root)
    graph = scope.Dependencies(repo)
    checks.clear()
    seeds = graph.collection_inputs('core/one/tests/test_wrapper.py')
    seeds.update(graph.collection_inputs('core/two/tests/test_wrapper.py'))
    graph.closure(seeds)
    assert checks['conftest.py'] == 1
    assert checks['core/conftest.py'] == 1
    assert checks['core/__init__.py'] == 1


@pytest.mark.parametrize('changed', ['module', 'initializer', 'exports'])
def test_new_analysis_sees_new_files_and_changed_lazy_exports(tree, changed):
    root, _ = tree
    _lazy_package(root)
    old = scope.Dependencies(root)
    old.resolve('core.shared.new')
    old.resolve('core.lazy.chosen')
    if changed == 'module':
        path = 'core/shared/new.py'
        (root / path).write_text('VALUE = 2\n')
        module = 'core.shared.new'
    elif changed == 'initializer':
        path = 'core/__init__.py'
        (root / path).write_text('VALUE = 2\n')
        module = 'core.one.wrapper'
    else:
        path = 'core/shared/common.py'
        package = root / 'core/lazy/__init__.py'
        package.write_text(package.read_text().replace('core.shared.helper', 'core.shared.common'))
        module = 'core.lazy.chosen'
    fresh = scope.Dependencies(root)
    assert path in fresh.resolve(module)


@pytest.mark.parametrize('expression', ['alias.wrapper.dispatch', 'alias.factory().dispatch',
                                       'alias.wrapper[0].dispatch', 'alias.factory("a.b").dispatch'],
                         ids=['dotted-name', 'call-base', 'subscript-base', 'dotted-call-argument'])
def test_attribute_resolution_retains_non_name_expression_prefixes(tree, expression):
    root, _ = tree
    (root / 'core/one/__init__.py').write_text('VALUE = 1\n')
    path = root / 'core/shared/attributes.py'
    path.write_text('import core.one as alias\n' + expression + '\n')
    deps, opaque = scope.Dependencies(root).direct('core/shared/attributes.py')
    assert 'core/one/__init__.py' in deps
    assert opaque is False


@pytest.mark.parametrize('changed', ['core/shared/conftest.py', 'core/unrelated/module.py'])
def test_importing_a_runtime_module_does_not_load_its_conftest(tree, changed):
    root, _ = tree
    (root / 'core/shared/conftest.py').write_text('from core.unrelated import module\n')
    assert selected(tree, [changed]) == (set(), set())


def test_opaque_fixture_broadens_only_its_collected_consumers(tree):
    root, _ = tree
    wrapper = root / 'core/two/wrapper.py'
    wrapper.write_text(wrapper.read_text() + 'from core.one import wrapper\n')
    (root / 'core/one/conftest.py').write_text('import importlib\nimportlib.import_module(unknown)\n')
    assert selected(tree, ['core/unrelated/module.py'])[1] == {'one'}


@pytest.mark.parametrize('explicit', [False, True], ids=['ordinary-helper', 'explicit-conftest-import'])
def test_imported_test_support_keeps_python_dependencies_without_inheriting_fixtures(tree, explicit):
    root, _ = tree
    (root / 'core/one/tests/conftest.py').write_text('TOKEN = 1\n')
    helper = root / 'core/one/tests/support.py'
    helper.write_text('from .conftest import TOKEN\n' if explicit else 'TOKEN = 1\n')
    target = root / 'core/two/tests/test_wrapper.py'
    target.write_text(target.read_text() + 'from core.one.tests import support\n')
    assert selected(tree, ['core/one/tests/conftest.py'])[1] == ({'one', 'two'} if explicit else {'one'})
    (root / 'core/one/conftest.py').write_text('PARENT = 1\n')
    assert selected(tree, ['core/one/conftest.py'])[1] == {'one'}


def _external_cases(tree, *, kind):
    root, registry = tree
    directory = root / '.github/acceptance'
    directory.mkdir()
    target = directory / 'cases.py'
    target.write_text('def test_contract():\n    pass\ndef test_native():\n    pass\n')
    if kind == 'default-contract':
        registry['wrappers'][0]['contracts'] = ['.github/acceptance/cases.py::test_contract']
    elif kind == 'platform-contract':
        registry['wrappers'][0]['contract_platforms'] = {'darwin': ['.github/acceptance/cases.py::test_contract']}
    else:
        registry['native'][0]['platforms']['darwin']['tests'] = ['.github/acceptance/cases.py::test_native']
    assert registry_errors(root, registry) == []
    return root, registry


@pytest.mark.parametrize('kind', ['default-contract', 'platform-contract', 'native-only'])
@pytest.mark.parametrize('changed', ['.github/acceptance/cases.py', '.github/acceptance/conftest.py', '.github/conftest.py'])
def test_registered_collection_inputs_outside_source_roots_are_not_skipped(tree, kind, changed):
    root, registry = _external_cases(tree, kind=kind)
    (root / '.github/acceptance/conftest.py').write_text('TOKEN = 1\n')
    (root / '.github/conftest.py').write_text('TOKEN = 1\n')
    matrix = scope.select(root, registry, [changed])['include']
    assert {cell['platform'] for cell in matrix} == ({'linux', 'darwin'} if kind == 'default-contract' else {'darwin'})
    for cell in matrix:
        if kind == 'native-only':
            assert cell['families'] == ['one'] and cell['contracts'] == []
        else:
            assert cell['contracts'] == ['.github/acceptance/cases.py::test_contract'] and cell['families'] == []


@pytest.mark.parametrize('changed', ['.github/acceptance/cases.py', '.github/acceptance/conftest.py', '.github/conftest.py'])
def test_deleted_registered_collection_inputs_keep_full_coverage(tree, changed):
    root, registry = _external_cases(tree, kind='native-only')
    (root / '.github/acceptance/conftest.py').write_text('TOKEN = 1\n')
    (root / '.github/conftest.py').write_text('TOKEN = 1\n')
    (root / changed).unlink()
    matrix = scope.select(root, registry, [changed])['include']
    assert len(matrix) == 2 and all(cell['full'] for cell in matrix)


@pytest.mark.parametrize('changed', ['entrypoint.py', '.github/scripts/indirect.py'])
def test_deleted_relevant_python_inputs_keep_full_coverage(tree, changed):
    root, registry = tree
    matrix = scope.select(root, registry, [changed])['include']
    assert len(matrix) == 2 and all(cell['full'] for cell in matrix)


@pytest.mark.parametrize('kind', ['unused-default', 'manual-native'])
@pytest.mark.parametrize('changed', ['.github/acceptance/cases.py', '.github/acceptance/conftest.py'])
def test_non_automated_bindings_do_not_become_trigger_inputs(tree, kind, changed):
    root, registry = _external_cases(tree, kind='default-contract' if kind == 'unused-default' else 'native-only')
    (root / '.github/acceptance/conftest.py').write_text('TOKEN = 1\n')
    if kind == 'unused-default':
        registry['wrappers'][0]['contract_platforms'] = {
            platform: ['core/one/tests/test_wrapper.py::test_contract'] for platform in scope.PLATFORMS
        }
    else:
        registry['native'][0]['platforms']['darwin'].update(manual=True, reason='owned manual acceptance')
    assert registry_errors(root, registry) == []
    assert scope.select(root, registry, [changed]) == {'include': []}


@pytest.mark.parametrize('case, expected, full', [
    ('docs-only', set(), False),
    ('one-wrapper', {'one'}, False),
    ('two-wrappers', {'one', 'two'}, False),
    ('missing-base', {'one', 'two'}, True),
    ('deleted-module', {'one', 'two'}, True),
    ('shared-harness', {'one', 'two'}, True),
], ids=['docs-only', 'one-wrapper', 'two-wrappers', 'missing-base', 'deleted-module', 'shared-harness'])
def test_merge_queue_scopes_complete_git_group(tree, monkeypatch, case, expected, full):
    from core.testing.gitrepo import git_run

    root, _ = tree
    git_run(root, 'init', '-b', 'main')
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'group base')
    base = git_run(root, 'rev-parse', 'HEAD')
    docs = root / 'docs/guide.md'
    docs.parent.mkdir()
    docs.write_text('queued documentation change\n')
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'first queued change')
    paths = []
    if case in {'one-wrapper', 'two-wrappers'}:
        paths.append('core/one/wrapper.py')
    if case == 'two-wrappers':
        paths.append('core/two/wrapper.py')
    if case == 'shared-harness':
        paths.append('pytest.ini')
    for rel in paths:
        path = root / rel
        path.write_text((path.read_text() if path.exists() else '') + '# queued change\n')
        git_run(root, 'add', '-A')
        git_run(root, 'commit', '-qm', 'additional queued change')
    if case == 'deleted-module':
        (root / 'core/shared/helper.py').unlink()
        git_run(root, 'add', '-A')
        git_run(root, 'commit', '-qm', 'queued removal')
    monkeypatch.chdir(root)
    monkeypatch.setenv('EVENT', 'merge_group')
    monkeypatch.setenv('BASE_SHA', '' if case == 'missing-base' else base)
    output = root / 'scope-output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    scope.main()
    rows = dict(line.split('=', 1) for line in output.read_text().splitlines())
    matrix = json.loads(rows['matrix'])['include']
    assert rows['run'] == str(bool(expected)).lower()
    assert {cell['platform'] for cell in matrix} == ({'linux', 'darwin'} if expected else set())
    for cell in matrix:
        assert set(cell['families']) == expected
        assert len(cell['contracts']) == len(expected)
        assert cell['full'] is full


@pytest.mark.parametrize('event', ['schedule', 'workflow_dispatch'])
def test_scheduled_and_manual_runs_ignore_diff_base(tree, monkeypatch, event):
    root, _ = tree
    monkeypatch.chdir(root)
    monkeypatch.setenv('EVENT', event)
    monkeypatch.setenv('BASE_SHA', 'a' * 40)
    monkeypatch.setattr(scope, 'changed_paths', lambda *args: pytest.fail('full run requested Git scoping'))
    output = root / 'scope-output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    scope.main()
    rows = dict(line.split('=', 1) for line in output.read_text().splitlines())
    matrix = json.loads(rows['matrix'])['include']
    assert len(matrix) == 2
    assert all(cell['full'] and set(cell['families']) == {'one', 'two'} for cell in matrix)


def test_wrapper_workflow_passes_merge_group_base_to_scope():
    root = Path(__file__).resolve().parents[3]
    workflow = (root / '.github/workflows/sandbox-wrappers.yml').read_text()
    jobs = workflow.split('\njobs:\n', 1)[1]
    job = re.search(r'^  scope:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)', jobs, re.M | re.S)
    assert job is not None, 'wrapper scope job missing'
    steps = re.split(r'^      - ', job[1], flags=re.M)[1:]
    matches = [step for step in steps if re.search(r'^        id: scope$', step, re.M)]
    assert len(matches) == 1, 'wrapper scope step must be unique'
    environment = re.search(r'^        env:\n((?:          .*\n)+)', matches[0], re.M)
    assert environment is not None, 'scope inputs must remain explicit'
    fields = dict(re.findall(r'^          ([A-Z_]+): (.+)$', environment[1], re.M))
    assert fields['BASE_SHA'] == (
        "${{ github.event_name != 'push' && (github.event.pull_request.base.sha || github.event.merge_group.base_sha) || steps.push_base.outputs.base }}")
    assert fields['EVENT'] == '${{ github.event_name }}'


@pytest.fixture
def registry_git(tree):
    from core.testing.gitrepo import git_run

    root, registry = tree
    path = root / 'core/one/tests/test_wrapper.py'
    path.write_text(path.read_text() + '\ndef test_extra():\n    pass\n')
    git_run(root, 'init', '-b', 'main')
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'registry comparison base')
    return root, registry, git_run(root, 'rev-parse', 'HEAD')


def _registry_step(root, registry, base, monkeypatch, *, payload=None):
    from core.testing.gitrepo import git_run

    (root / '.github/sandbox-wrapper-tests.json').write_text(
        json.dumps(registry, indent=2) if payload is None else payload)
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'current registry selection')
    monkeypatch.chdir(root)
    monkeypatch.setenv('EVENT', 'merge_group')
    monkeypatch.setenv('BASE_SHA', base)
    output = root / 'scope-output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    scope.main()
    fields = dict(line.split('=', 1) for line in output.read_text().splitlines())
    matrix = json.loads(fields['matrix'])['include']
    assert fields['run'] == str(bool(matrix)).lower()
    return {cell['platform']: cell for cell in matrix}


@pytest.mark.parametrize('kind', ['count', 'selector'])
@pytest.mark.parametrize('platform', ['linux', 'darwin'])
def test_registry_cell_only_git_diff_keeps_other_platform_idle(registry_git, monkeypatch, kind, platform):
    root, registry, base = registry_git
    cell = registry['native'][0]['platforms'][platform]
    cell['expected'] = 2
    if kind == 'selector':
        cell['tests'].append('core/one/tests/test_wrapper.py::test_extra')
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert set(matrix) == {platform}
    assert matrix[platform]['families'] == ['one']
    assert matrix[platform]['contracts'] == []
    assert matrix[platform]['full'] is False


def test_registry_formatting_only_needs_no_platform_runner(registry_git, monkeypatch):
    root, registry, base = registry_git
    assert _registry_step(root, registry, base, monkeypatch) == {}


def test_registry_delta_unions_normal_source_selection(registry_git, monkeypatch):
    root, registry, base = registry_git
    registry['native'][0]['platforms']['linux']['expected'] = 2
    path = root / 'core/two/wrapper.py'
    path.write_text(path.read_text() + '# source changed\n')
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert matrix['linux']['families'] == ['one', 'two']
    assert matrix['darwin']['families'] == ['two']
    for cell in matrix.values():
        assert cell['contracts'] == ['core/two/tests/test_wrapper.py::test_contract']
        assert cell['full'] is False


@pytest.mark.parametrize('other', ['global', 'deleted', 'unparseable', 'shared-opaque'])
def test_registry_narrowing_cannot_override_full_fallbacks(registry_git, monkeypatch, other):
    from core.testing.gitrepo import git_run

    root, registry, base = registry_git
    registry['native'][0]['platforms']['linux']['expected'] = 2
    if other == 'global':
        (root / 'uv.lock').write_text('owned change\n')
    elif other == 'deleted':
        (root / 'core/shared/helper.py').unlink()
    elif other == 'unparseable':
        (root / 'core/shared/helper.py').write_text('def broken(')
    else:
        (root / 'conftest.py').write_text('import importlib\nimportlib.import_module(unknown)\n')
        git_run(root, 'add', 'conftest.py')
        git_run(root, 'commit', '-qm', 'shared opaque fixture base')
        base = git_run(root, 'rev-parse', 'HEAD')
        path = root / 'core/two/wrapper.py'
        path.write_text(path.read_text() + '# runtime input changed\n')
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert set(matrix) == {'linux', 'darwin'}
    assert all(cell['full'] and cell['families'] == ['one', 'two']
               and len(cell['contracts']) == 2 for cell in matrix.values())


def test_registry_delta_uses_comparison_base_not_previous_commit(registry_git, monkeypatch):
    from core.testing.gitrepo import git_run

    root, registry, base = registry_git
    registry['native'][0]['platforms']['linux']['expected'] = 2
    (root / '.github/sandbox-wrapper-tests.json').write_text(json.dumps(registry))
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'first queued registry edit')
    # The next commit only changes formatting. HEAD^ already has the new cell.
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert set(matrix) == {'linux'} and matrix['linux']['families'] == ['one']
    assert matrix['linux']['full'] is False


def test_retired_old_selector_need_not_exist_in_current_tree(registry_git, monkeypatch):
    from core.testing.gitrepo import git_run

    root, registry, _ = registry_git
    old_cell = registry['native'][0]['platforms']['linux']
    old_cell['tests'].append('core/one/tests/test_wrapper.py::test_extra')
    old_cell['expected'] = 2
    (root / '.github/sandbox-wrapper-tests.json').write_text(json.dumps(registry))
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'old selector exists at base')
    base = git_run(root, 'rev-parse', 'HEAD')
    old_cell['tests'].pop()
    old_cell['expected'] = 1
    path = root / 'core/one/tests/test_wrapper.py'
    path.write_text(path.read_text().replace('\ndef test_extra():\n    pass\n', ''))
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert set(matrix) == {'linux', 'darwin'}  # Python change affects both.
    assert all(cell['families'] == ['one'] and not cell['full'] for cell in matrix.values())


@pytest.mark.parametrize('old', ['missing', 'json', 'schema', 'duplicate-id', 'unknown-cell',
                                 'zero-count', 'bad-tests', 'manual-type', 'null-native', 'unknown-wrapper'])
def test_unavailable_or_invalid_old_registry_keeps_full_selection(registry_git, monkeypatch, old):
    from core.testing.gitrepo import git_run

    root, registry, _ = registry_git
    path = root / '.github/sandbox-wrapper-tests.json'
    if old == 'missing':
        path.unlink()
    elif old == 'json':
        path.write_text('{')
    else:
        previous = deepcopy(registry)
        if old == 'schema':
            previous['version'] = 999
        elif old == 'duplicate-id':
            previous['native'].append(deepcopy(previous['native'][0]))
        elif old == 'unknown-cell':
            previous['native'][0]['platforms']['linux']['unknown'] = 'future policy'
        elif old == 'zero-count':
            previous['native'][0]['platforms']['linux']['expected'] = 0
        elif old == 'bad-tests':
            previous['native'][0]['platforms']['linux']['tests'] = 'not a selector list'
        elif old == 'manual-type':
            previous['native'][0]['platforms']['linux']['manual'] = 'false'
        elif old == 'null-native':
            previous['native'] = None
        else:
            previous['wrappers'][0]['unknown'] = 'future policy'
        path.write_text(json.dumps(previous))
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'unavailable historical schema')
    base = git_run(root, 'rev-parse', 'HEAD')
    registry['native'][0]['platforms']['linux']['expected'] = 2
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert all(cell['full'] and cell['families'] == ['one', 'two'] for cell in matrix.values())


@pytest.mark.parametrize('policy', ['wrapper', 'env', 'reason', 'manual', 'family-id', 'unknown'])
def test_registry_policy_changes_still_run_full_without_manual_opt_in(registry_git, monkeypatch, policy):
    root, registry, base = registry_git
    if policy == 'wrapper':
        registry['wrappers'][0]['discovery'] = 'owned additional policy review'
    elif policy == 'env':
        registry['native'][0]['env'] = {'OWNED_MODE': 'changed'}
    elif policy == 'reason':
        registry['native'][0]['platforms']['linux']['reason'] = 'new policy rationale'
    elif policy == 'manual':
        registry['native'][0]['platforms']['linux']['manual'] = True
    elif policy == 'family-id':
        registry['native'][0]['id'] = 'renamed'
    else:
        registry['future_policy'] = True
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert set(matrix) == {'linux', 'darwin'} and all(cell['full'] for cell in matrix.values())
    expected_linux = ['two'] if policy == 'manual' else ['renamed', 'two'] if policy == 'family-id' else ['one', 'two']
    assert matrix['linux']['families'] == expected_linux
    assert len(matrix['linux']['contracts']) == 2


@pytest.mark.parametrize('base', ['', '0' * 40, 'HEAD', 'a' * 39, 'a' * 41, 'a' * 40 + ':other'])
def test_unverified_registry_base_never_runs_git(tmp_path, monkeypatch, base):
    from types import SimpleNamespace

    monkeypatch.setattr(scope, 'subprocess', SimpleNamespace(
        run=lambda *a, **k: pytest.fail('unverified revision reached Git')))
    assert scope.base_registry(tmp_path, base) is None


@pytest.mark.parametrize('failure', ['spawn', 'timeout', 'status'])
def test_registry_history_read_failures_are_unavailable(tmp_path, monkeypatch, failure):
    import subprocess
    from types import SimpleNamespace

    error = {'spawn': OSError('owned spawn failure'),
             'timeout': subprocess.TimeoutExpired(['git'], 10),
             'status': subprocess.CalledProcessError(128, ['git'])}[failure]
    def fail(*args, **kwargs):
        raise error
    private = SimpleNamespace(**vars(subprocess))
    private.run = fail
    monkeypatch.setattr(scope, 'subprocess', private)
    assert scope.base_registry(tmp_path, 'a' * 40) is None


@pytest.mark.parametrize('payload', [b'[]', b'null', b'{', b'\xff', b' ' * (2 * 1024 * 1024 + 1)],
                         ids=['list', 'null', 'json', 'encoding', 'oversized'])
def test_unreadable_registry_payload_is_unavailable(tmp_path, monkeypatch, payload):
    import subprocess
    from types import SimpleNamespace

    def read(command, **options):
        assert options['cwd'] == tmp_path and options['check'] is True
        assert options['stdout'] is subprocess.PIPE and options['stderr'] is subprocess.DEVNULL
        assert 0 < options['timeout'] <= 10
        if len(command) == 3:
            assert command == ['git', 'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)']
            assert options['input'] == b'a' * 40 + b':.github/sandbox-wrapper-tests.json\n'
            return SimpleNamespace(stdout=b'b' * 40 + b' blob ' + str(len(payload)).encode('ascii') + b'\n')
        assert command == ['git', 'cat-file', 'blob', 'b' * 40]
        assert len(payload) <= 2 * 1024 * 1024, 'oversized blob reached content read'
        assert 'input' not in options
        return SimpleNamespace(stdout=payload)
    private = SimpleNamespace(**vars(subprocess))
    private.run = read
    monkeypatch.setattr(scope, 'subprocess', private)
    assert scope.base_registry(tmp_path, 'a' * 40) is None


def test_registry_retirement_with_deleted_external_test_keeps_full(registry_git, monkeypatch):
    from core.testing.gitrepo import git_run

    root, registry, _ = registry_git
    retired = root / '.github/acceptance/old.py'
    retired.parent.mkdir(parents=True)
    retired.write_text('def test_old():\n    pass\n')
    cell = registry['native'][0]['platforms']['linux']
    cell['tests'] = ['.github/acceptance/old.py::test_old']
    (root / '.github/sandbox-wrapper-tests.json').write_text(json.dumps(registry))
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'old external native selector')
    base = git_run(root, 'rev-parse', 'HEAD')
    retired.unlink()
    cell['tests'] = ['core/one/tests/test_wrapper.py::test_native']
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert set(matrix) == {'linux', 'darwin'}
    assert all(cell['full'] and cell['families'] == ['one', 'two'] for cell in matrix.values())


@pytest.mark.parametrize('selector', [
    'not-a-selector', 'core/one/tests/test_wrapper.py',
    '/absolute.py::test_native', '../outside.py::test_native',
    'core/../outside.py::test_native', 'core//test.py::test_native',
    r'C:\outside.py::test_native', 'core/file.txt::test_native',
    'core/file.py::', 'core/file.py::not-a-name', 'core/file.py::class',
    'core/file.py::test_native[unfinished', 'core/file.py::test_native\n',
    'core/file.py::helper', 'core/file.py::TestContainer', 'core/file.py::testnative',
], ids=['no-file', 'no-node', 'absolute', 'parent', 'nested-parent', 'empty-part',
        'windows', 'not-python', 'empty-node', 'bad-name', 'keyword', 'parameter', 'newline',
        'helper', 'class-only', 'missing-test-prefix'])
def test_malformed_historical_selector_requires_full(registry_git, monkeypatch, selector):
    from core.testing.gitrepo import git_run

    root, registry, _ = registry_git
    previous = deepcopy(registry)
    previous['native'][0]['platforms']['linux']['tests'] = [selector]
    (root / '.github/sandbox-wrapper-tests.json').write_text(json.dumps(previous))
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'historical selector shape')
    base = git_run(root, 'rev-parse', 'HEAD')
    registry['native'][0]['platforms']['linux']['expected'] = 2
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert set(matrix) == {'linux', 'darwin'}
    assert all(cell['full'] and cell['families'] == ['one', 'two'] for cell in matrix.values())


@pytest.mark.parametrize('key', ['expected', 'tests', 'platforms', 'native'])
@pytest.mark.parametrize('where', ['old', 'current'])
def test_duplicate_registry_keys_require_full(registry_git, monkeypatch, where, key):
    from core.testing.gitrepo import git_run

    root, registry, base = registry_git
    current = deepcopy(registry)
    current['native'][0]['platforms']['linux']['expected'] = 2
    value = registry if where == 'old' else current
    raw = json.dumps(value)
    duplicate = {'expected': '999', 'tests': '[]', 'platforms': '{}', 'native': '[]'}[key]
    raw = raw.replace('"' + key + '":', '"' + key + '": ' + duplicate + ', "' + key + '":', 1)
    if where == 'old':
        (root / '.github/sandbox-wrapper-tests.json').write_text(raw)
        git_run(root, 'add', '-A')
        git_run(root, 'commit', '-qm', 'ambiguous historical registry')
        base = git_run(root, 'rev-parse', 'HEAD')
    matrix = _registry_step(root, current, base, monkeypatch, payload=raw if where == 'current' else None)
    assert set(matrix) == {'linux', 'darwin'}
    assert all(cell['full'] and cell['families'] == ['one', 'two'] for cell in matrix.values())


@pytest.mark.parametrize('encoding', ['utf-16', 'utf-8-sig'])
def test_historical_registry_uses_current_utf8_text_contract(registry_git, monkeypatch, encoding):
    from core.testing.gitrepo import git_run

    root, registry, _ = registry_git
    (root / '.github/sandbox-wrapper-tests.json').write_bytes(json.dumps(registry).encode(encoding))
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'historical encoding differs from census')
    base = git_run(root, 'rev-parse', 'HEAD')
    registry['native'][0]['platforms']['linux']['expected'] = 2
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert set(matrix) == {'linux', 'darwin'}
    assert all(cell['full'] for cell in matrix.values())


def test_oversized_registry_blob_is_rejected_before_content_capture(tmp_path, monkeypatch):
    import subprocess
    from types import SimpleNamespace

    metadata = ['git', 'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)']
    calls = []
    def read(command, **options):
        calls.append(command)
        if command[1] == 'show':  # Original reader captures the blob first.
            return SimpleNamespace(stdout=b' ' * (2 * 1024 * 1024 + 1))
        assert command == metadata
        return SimpleNamespace(stdout=b'b' * 40 + b' blob 2097153\n')
    private = SimpleNamespace(**vars(subprocess))
    private.run = read
    monkeypatch.setattr(scope, 'subprocess', private)
    assert scope.base_registry(tmp_path, 'a' * 40) is None
    assert calls == [metadata], 'oversized blob contents were requested before size admission'


@pytest.mark.parametrize('selector', [
    '.github/retired.py::TestOld::test_native[one]',
    'core/old_name.py::test_λ[one::two]',
    'tests with spaces/old.py::test_native[a b]',
])
def test_historical_selector_syntax_does_not_require_current_files(tree, selector):
    _, registry = tree
    previous = deepcopy(registry)
    previous['native'][0]['platforms']['linux']['tests'] = [selector]
    assert scope.native_cell_changes(previous, registry) == {('linux', 'one')}


@pytest.mark.parametrize('payload', [
    b'{"native": [], "native": []}',
    b'{"na\\u0074ive": [], "native": []}',
    b'{"platforms": {"linux": {}, "linux": {}}}',
    b'{"tests": [], "tests": []}',
    b'{"expected": 1, "expected": 2}',
])
def test_current_raw_duplicate_keys_are_not_admitted(tmp_path, payload):
    path = tmp_path / '.github/sandbox-wrapper-tests.json'
    path.parent.mkdir()
    path.write_bytes(payload)
    assert scope.current_registry(tmp_path) is None


@pytest.mark.parametrize('header', [
    b'not metadata\n', b'b' * 40 + b' tree 2\n', b'b' * 40 + b' blob -1\n',
    b'b' * 39 + b' blob 2\n', b'b' * 40 + b' blob 2\nextra\n',
])
def test_unverified_blob_metadata_never_reads_contents(tmp_path, monkeypatch, header):
    import subprocess
    from types import SimpleNamespace

    calls = []
    def read(command, **options):
        calls.append(command)
        assert len(command) == 3, 'unverified blob reached content capture'
        assert options['stderr'] is subprocess.DEVNULL
        return SimpleNamespace(stdout=header)
    private = SimpleNamespace(**vars(subprocess))
    private.run = read
    monkeypatch.setattr(scope, 'subprocess', private)
    assert scope.base_registry(tmp_path, 'a' * 40) is None
    assert len(calls) == 1


def test_metadata_and_blob_reads_share_one_deadline(tmp_path, monkeypatch):
    import subprocess
    from types import SimpleNamespace

    clock = iter([100.0, 111.0])
    monkeypatch.setattr(scope, 'time', SimpleNamespace(monotonic=lambda: next(clock)))
    calls = []
    def read(command, **options):
        calls.append(command)
        assert len(command) == 3, 'blob read began after the shared deadline'
        return SimpleNamespace(stdout=b'b' * 40 + b' blob 2\n')
    private = SimpleNamespace(**vars(subprocess))
    private.run = read
    monkeypatch.setattr(scope, 'subprocess', private)
    assert scope.base_registry(tmp_path, 'a' * 40) is None
    assert len(calls) == 1


@pytest.mark.parametrize('declared,body,expected', [
    (2, b'{}', {}), (1, b'{}', None),
    (2 * 1024 * 1024, b'{}' + b' ' * (2 * 1024 * 1024 - 2), {}),
], ids=['owned-blob', 'size-mismatch', 'at-size-cap'])
def test_registry_blob_read_uses_admitted_object_id(tmp_path, monkeypatch, declared, body, expected):
    import subprocess
    from types import SimpleNamespace

    calls = []
    def read(command, **options):
        calls.append(command)
        assert options['stdout'] is subprocess.PIPE and options['stderr'] is subprocess.DEVNULL
        assert 0 < options['timeout'] <= 10
        if len(command) == 3:
            return SimpleNamespace(stdout=b'b' * 40 + b' blob ' + str(declared).encode('ascii') + b'\n')
        assert command == ['git', 'cat-file', 'blob', 'b' * 40]
        return SimpleNamespace(stdout=body)
    private = SimpleNamespace(**vars(subprocess))
    private.run = read
    monkeypatch.setattr(scope, 'subprocess', private)
    assert scope.base_registry(tmp_path, 'a' * 40) == expected
    assert len(calls) == 2


@pytest.mark.parametrize('field,value', [
    ('expected', True), ('expected', 1.0), ('version', True), ('version', 1.0), ('manual', 0),
    ('key-order', None),
], ids=['expected-boolean', 'expected-float', 'version-boolean', 'version-float', 'manual-integer', 'key-order'])
def test_current_snapshot_types_must_match_census(registry_git, monkeypatch, field, value):
    from core.testing.gitrepo import git_run

    root, registry, _ = registry_git
    registry['version'] = 1
    registry['native'][0]['platforms']['linux']['manual'] = False
    previous = deepcopy(registry)
    previous['native'][0]['platforms']['linux']['tests'].append('core/one/tests/test_wrapper.py::test_extra')
    previous['native'][0]['platforms']['linux']['expected'] = 2
    (root / '.github/sandbox-wrapper-tests.json').write_text(json.dumps(previous))
    git_run(root, 'add', '-A')
    git_run(root, 'commit', '-qm', 'prior native cell with two selectors')
    base = git_run(root, 'rev-parse', 'HEAD')
    real_read = scope.current_registry
    reads = []
    def changed_snapshot(repo):
        # Deterministically change the owned file after the census read, not
        # the parsed census dictionary or a shared JSON/OS module binding.
        raw = deepcopy(registry)
        if field == 'key-order':
            raw = json.loads(json.dumps(raw, sort_keys=True))
        elif field == 'version':
            raw[field] = value
        else:
            raw['native'][0]['platforms']['linux'][field] = value
        (repo / '.github/sandbox-wrapper-tests.json').write_text(json.dumps(raw))
        reads.append(True)
        return real_read(repo)
    monkeypatch.setattr(scope, 'current_registry', changed_snapshot)
    matrix = _registry_step(root, registry, base, monkeypatch)
    assert reads == [True]
    if field == 'key-order':
        assert set(matrix) == {'linux'}
        assert matrix['linux']['families'] == ['one'] and not matrix['linux']['full']
    else:
        assert set(matrix) == {'linux', 'darwin'}
        assert all(cell['full'] and cell['families'] == ['one', 'two'] for cell in matrix.values())

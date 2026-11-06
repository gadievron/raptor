"""Every discovered policy owner needs a reviewed executable test binding."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / '.github/scripts'
with patch.object(sys, 'path', [str(SCRIPTS), *sys.path]):
    import sandbox_wrapper_tests as inventory
    spec = importlib.util.spec_from_file_location('wrapper_test_runner', SCRIPTS / 'run_sandbox_wrapper_tests.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)


# The wrapper workflow's scope job runs this full registration census before
# every selection, including selections that skip platform runners. Repeating
# it in shuffled-fast adds a loaded-runner 20-30s scan without new PR coverage.
# Keep the independent shipped-tree assertion in nightly's slow lane; the
# hermetic fail-direction and registration-mechanics tests below stay fast.
@pytest.mark.slow
def test_all_policy_owners_have_reviewed_test_cases():
    assert inventory.registry_errors(ROOT, inventory.load_registry()) == []


def _fixture(root):
    source = root / 'packages/owned.py'
    source.parent.mkdir()
    source.write_text('from core.sandbox import run as confined\ndef dispatch():\n    return confined(["true"])\n')
    test = root / 'tests/test_owned.py'
    test.parent.mkdir()
    test.write_text('def test_dispatch():\n    pass\n')
    return {'wrappers': [{'source': 'packages/owned.py', 'entrypoints': ['dispatch'],
                          'contracts': ['tests/test_owned.py::test_dispatch']}], 'native': []}


def test_new_wrapper_and_new_entrypoint_need_review(tmp_path):
    registry = _fixture(tmp_path)
    assert not inventory.registry_errors(tmp_path, registry)
    source = tmp_path / 'packages/new.py'
    source.write_text('import core.sandbox as jail\ndef spawn():\n    jail.run(["true"])\n')
    assert any('unregistered' in e for e in inventory.registry_errors(tmp_path, registry))
    source.unlink()
    source = tmp_path / 'packages/owned.py'
    source.write_text(source.read_text() + '\ndef another():\n    confined(["true"])\n')
    assert any('entrypoints changed' in e for e in inventory.registry_errors(tmp_path, registry))


def test_missing_case_and_platform_binding_fail(tmp_path):
    registry = _fixture(tmp_path)
    row = registry['wrappers'][0]
    row['contract_platforms'] = {'darwin': ['tests/test_owned.py::test_missing']}
    assert any('missing platform test' in e for e in inventory.registry_errors(tmp_path, registry))
    row.pop('contract_platforms')
    row['contracts'] = []
    assert any('no contract' in e for e in inventory.registry_errors(tmp_path, registry))


@pytest.mark.parametrize('body', ['', '<testcase><skipped/></testcase>',
                                 '<testcase><failure/></testcase>', '<testcase><error/></testcase>'])
def test_native_report_cannot_pass_without_execution(tmp_path, body):
    xml = tmp_path / 'report.xml'
    xml.write_text('<testsuite>' + body + '</testsuite>')
    assert runner.check_report(xml, expected=1)


def test_native_report_rejects_count_drift_and_missing_file(tmp_path):
    xml = tmp_path / 'report.xml'
    assert runner.check_report(xml, expected=1)
    xml.write_text('<testsuite><testcase/></testsuite>')
    assert not runner.check_report(xml, expected=1)
    assert runner.check_report(xml, expected=2)


def test_runner_exposes_selected_venv_console_scripts(tmp_path):
    import os
    binary = tmp_path / 'venv/bin/python'
    binary.parent.mkdir(parents=True)
    binary.symlink_to(sys.executable)
    inherited = '/usr/bin:/bin'
    path = runner.interpreter_tool_path(str(binary), inherited)
    assert path.split(os.pathsep)[0] == str(binary.parent)
    assert path.endswith(os.pathsep + inherited)


@pytest.mark.parametrize("list_only", [False, True], ids=["run", "list"])
def test_registry_refusal_preserves_evidence_without_running_pytest(tmp_path, monkeypatch, list_only):
    import json
    errors = ["owned.py: sandbox entrypoints changed; review test bindings"]
    report = tmp_path / "reports"
    monkeypatch.setattr(runner, "load_registry", lambda: {})
    monkeypatch.setattr(runner, "registry_errors", lambda *args: errors)
    monkeypatch.setattr(runner, "subprocess", SimpleNamespace(
        run=lambda *a, **kw: pytest.fail("pytest started after refusal")))
    monkeypatch.setattr(sys, "argv", ["runner", "--lane", "contracts", "--report-dir", str(report)]
                        + (["--list"] if list_only else []))
    assert runner.main() == 1
    if list_only:
        assert not report.exists()
    else:
        summary = json.loads((report / "summary.json").read_text())
        assert summary["preflight_errors"] == errors
        assert summary["results"] == []
        assert summary["lane"] == "contracts"


def test_injected_sandbox_runner_needs_reviewed_binding(tmp_path):
    registry = _fixture(tmp_path)
    source = tmp_path / "packages/stages.py"
    source.write_text('def invoke(state):\n    return state.sandbox_run(["true"], block_network=True)\n')
    assert inventory.policy_entrypoints(source) == ["invoke"]
    assert any("unregistered" in error for error in inventory.registry_errors(tmp_path, registry))
    registry["wrappers"].append({
        "source": "packages/stages.py", "entrypoints": ["invoke"],
        "contracts": ["tests/test_owned.py::test_dispatch"],
    })
    assert inventory.registry_errors(tmp_path, registry) == []
    source.write_text(source.read_text() + '\ndef another(state):\n    state.sandbox_run(["false"])\n')
    assert any("entrypoints changed" in error for error in inventory.registry_errors(tmp_path, registry))


def test_scoped_runner_keeps_only_registered_platform_targets(tmp_path):
    registry = _fixture(tmp_path)
    target = registry['wrappers'][0]['contracts'][0]
    selection = {'platform': 'linux', 'contracts': [target], 'families': [], 'full': False}
    assert runner.selected_targets(registry, selection, 'linux') == ([target], [])
    with pytest.raises(ValueError, match='platform'):
        runner.selected_targets(registry, selection, 'darwin')
    with pytest.raises(ValueError, match='unregistered'):
        runner.selected_targets(registry, dict(selection, contracts=['tests/test_unknown.py::test_unknown']), 'linux')
    with pytest.raises(ValueError, match='unique'):
        runner.selected_targets(registry, dict(selection, contracts=[target, target]), 'linux')
    with pytest.raises(ValueError, match='omits'):
        runner.selected_targets(registry, dict(selection, full=True, contracts=[]), 'linux')
    assert runner.selected_targets(registry, dict(selection, full=True), 'linux') == ([target], None)


def test_empty_scoped_native_selection_cannot_fall_back_to_all(tmp_path, monkeypatch):
    import json
    registry = _fixture(tmp_path)
    monkeypatch.setattr(runner, 'load_registry', lambda: registry)
    monkeypatch.setattr(runner, 'registry_errors', lambda *args: [])
    monkeypatch.setattr(runner, 'sys', SimpleNamespace(**(vars(sys) | {'platform': 'linux'})))
    selection = {'platform': 'linux', 'contracts': registry['wrappers'][0]['contracts'], 'families': [], 'full': False}
    monkeypatch.setattr(sys, 'argv', ['runner', '--lane', 'native', '--report-dir', str(tmp_path / 'out'),
                                    '--selection-json', json.dumps(selection), '--list'])
    with pytest.raises(SystemExit) as error:
        runner.main()
    assert error.value.code == 2


def test_registry_cache_is_local_and_sees_changed_test_bodies(tmp_path):
    registry = _fixture(tmp_path)
    selector = registry['wrappers'][0]['contracts'][0]
    registry['wrappers'][0]['contract_platforms'] = {'linux': [selector], 'darwin': [selector]}
    assert inventory.registry_errors(tmp_path, registry) == []
    (tmp_path / 'tests/test_owned.py').write_text('def test_replaced():\n    pass\n')
    assert any('missing' in error for error in inventory.registry_errors(tmp_path, registry))


@pytest.mark.parametrize(('imports', 'call'), [
    ('from core.sandbox import run as confined', 'confined(["true"])'),
    ('from core.sandbox.context import sandbox as context', 'context()'),
    ('import core.sandbox', 'core.sandbox.run(["true"])'),
    ('import core.sandbox.context', 'core.sandbox.context.run(["true"])'),
    ('import core.sandbox as sbx', 'sbx.run_untrusted(["true"])'),
    ('import core.sandbox.context as sbx', 'sbx.run_untrusted_networked(["true"])'),
    ('from core import sandbox as sbx', '(sbx).sandbox()'),
    ('', 'state.sandbox_run(["true"])'),
])
def test_policy_census_preserves_aliases_and_nested_async_scopes(tmp_path, imports, call):
    source = tmp_path / 'owned.py'
    source.write_text(imports + '\nclass Owner:\n    async def invoke(self):\n        ' + call + '\n')
    assert inventory.policy_entrypoints(source) == ['Owner.invoke']


@pytest.mark.parametrize('receiver', ['other', 'factory()', 'receivers[0]', '(left or right)'])
def test_incidental_executor_names_are_not_wrapper_calls(tmp_path, receiver):
    source = tmp_path / 'owned.py'
    source.write_text('import core.sandbox as sbx\ndef invoke():\n    ' + receiver + '.run(["true"])\n')
    assert inventory.policy_entrypoints(source) == []


def test_policy_census_still_finds_nested_calls_and_module_dispatch(tmp_path):
    source = tmp_path / 'owned.py'
    source.write_text('''import core.sandbox as sbx
sbx.run(["true"])
class Owner:
    def invoke(self):
        return factory(sbx.run(["true"])).run(state.sandbox_run(["true"]))
''')
    assert inventory.policy_entrypoints(source) == ['<module>', 'Owner.invoke']


def test_policy_census_keeps_file_wide_import_resolution(tmp_path):
    source = tmp_path / 'owned.py'
    source.write_text('def invoke():\n    sbx.run(["true"])\nimport core.sandbox as sbx\n')
    assert inventory.policy_entrypoints(source) == ['invoke']


@pytest.mark.parametrize('source', [
    'from core.ｓａｎｄｂｏｘ import run\ndef invoke():\n    run(["true"])\n',
    'import core.ｓａｎｄｂｏｘ as jail\ndef invoke():\n    jail.run(["true"])\n',
    'def invoke():\n    state.ｓａｎｄｂｏｘ_ｒｕｎ(["true"])\n',
], ids=['normalized-import', 'normalized-module', 'normalized-injected-runner'])
def test_policy_census_accepts_normalized_python_identifiers(tmp_path, source):
    assert 'sandbox' not in source
    path = tmp_path / 'owned.py'
    path.write_text(source)
    assert inventory.policy_entrypoints(path) == ['invoke']


def test_normalized_unregistered_wrapper_fails_census(tmp_path):
    registry = _fixture(tmp_path)
    source = tmp_path / 'packages/new.py'
    source.write_text('from core.ｓａｎｄｂｏｘ import run\ndef invoke():\n    run(["true"])\n')
    assert 'packages/new.py: unregistered sandbox wrapper; add an owned test case' in (
        inventory.registry_errors(tmp_path, registry))

"""Every discovered policy owner needs a reviewed executable test binding."""
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / '.github/scripts'
sys.path.insert(0, str(SCRIPTS))
try:
    import sandbox_wrapper_tests as inventory
    spec = importlib.util.spec_from_file_location('wrapper_test_runner', SCRIPTS / 'run_sandbox_wrapper_tests.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
finally:
    sys.path.remove(str(SCRIPTS))


@pytest.mark.wall_budget(30)
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
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: pytest.fail("pytest started after refusal"))
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

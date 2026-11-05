"""Execute both reusable tier commands to pin selection and failure semantics."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _native_tier_settings(tier):
    text = (ROOT / ".github/workflows/tests.yml").read_text()
    job = "source-intel" if tier == "source_intel" else tier
    block = text.split(f"  python-unit-tests-{job}:\n", 1)[1]
    block = re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]
    markers = re.search(r'^      native_pytest_markers: "([^"]+)"$', block, re.M)
    assert markers is not None, f"{tier} must include its native coverage"
    return block, markers.group(1)


def _source_intel_settings():
    return _native_tier_settings("source_intel")


def _run_tier(tmp_path, branch, native_markers, *, selection="", fail_phase=""):
    workflow = (ROOT / ".github/workflows/_tier.yml").read_text()
    blocks = re.findall(
        r"(?ms)^      - name: Run tests\n(.*?)(?=^      - name:|\Z)", workflow,
    )
    assert len(blocks) == 2
    block = blocks[branch]
    assert "NATIVE_PYTEST_MARKERS: ${{ inputs.native_pytest_markers }}" in block
    assert 'RAPTOR_MAX_TEST_SECONDS: "10"' in block
    command = re.search(r"        run: \|\n((?:          [^\n]*\n|[ \t]*\n)+)", block)
    assert command is not None
    script = textwrap.dedent(command.group(1))

    (tmp_path / "pytest.ini").write_text((ROOT / "pytest.ini").read_text())
    tests = tmp_path / "test_markers.py"
    tests.write_text(
        "import os, pytest\n"
        "def test_default():\n"
        "    assert os.environ['RAPTOR_MAX_TEST_SECONDS'] == '10'\n"
        "    assert os.environ.get('FAIL_PHASE') != 'fast'\n"
        "@pytest.mark.integration\ndef test_integration():\n"
        "    assert os.environ['RAPTOR_MAX_TEST_SECONDS'] == ''\n"
        "    assert os.environ.get('FAIL_PHASE') != 'native'\n"
        "@pytest.mark.slow\ndef test_slow():\n"
        "    assert os.environ['RAPTOR_MAX_TEST_SECONDS'] == ''\n"
        "@pytest.mark.corpus\ndef test_corpus(): assert False\n"
    )
    toolbin = tmp_path / "bin"
    toolbin.mkdir()
    python = toolbin / "python"
    python.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} \"$@\"\n")
    python.chmod(0o755)
    env = dict(
        os.environ, PATH=str(toolbin) + os.pathsep + os.environ.get("PATH", ""),
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTEST_ADDOPTS="",
        PYTEST_EXTRA="--noconftest -q" + (f" -k {selection}" if selection else ""),
        NATIVE_PYTEST_MARKERS=native_markers, RAPTOR_MAX_TEST_SECONDS="10",
        TEST_PATH=str(tests), RUNNER_TEMP=str(tmp_path), FAIL_PHASE=fail_phase,
    )
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        ["/bin/sh", "-eu", "-c", script], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=20,
    )
    reports = {}
    for name in ("pytest-junit.xml", "pytest-native-junit.xml"):
        path = tmp_path / name
        if path.exists():
            reports[name] = {case.get("name") for case in ET.parse(path).iter("testcase")}
    return result, reports


@pytest.mark.parametrize("branch", [0, 1], ids=["image", "runner"])
@pytest.mark.parametrize("marker_mode", ["default", "source-intel", "engine", "slow-only"])
def test_tier_shell_preserves_disjoint_marker_selection(tmp_path, branch, marker_mode):
    markers, expected = {
        "default": ("", None),
        "source-intel": (_source_intel_settings()[1], {"test_integration", "test_slow"}),
        "engine": (_native_tier_settings("engine")[1], {"test_integration"}),
        "slow-only": ("slow", {"test_slow"}),
    }[marker_mode]
    result, reports = _run_tier(tmp_path, branch, markers)
    assert result.returncode == 0, result.stdout + result.stderr
    assert reports["pytest-junit.xml"] == {"test_default"}
    if expected is None:
        assert "pytest-native-junit.xml" not in reports
    else:
        assert reports["pytest-native-junit.xml"] == expected
        assert reports["pytest-junit.xml"].isdisjoint(reports["pytest-native-junit.xml"])


@pytest.mark.parametrize("branch", [0, 1], ids=["image", "runner"])
@pytest.mark.parametrize("selection,fail_phase,expected_status", [
    ("test_default", "", 0),  # no native cases in this scoped selection
    ("test_integration", "", 0),  # no default cases in this scoped selection
    ("test_corpus", "", 5),  # both empty must never greenwash zero coverage
    ("", "fast", 1),
    ("", "native", 1),
])
def test_tier_runs_both_phases_and_preserves_failures(
    tmp_path, branch, selection, fail_phase, expected_status,
):
    result, reports = _run_tier(
        tmp_path, branch, _source_intel_settings()[1],
        selection=selection, fail_phase=fail_phase,
    )
    assert result.returncode == expected_status, result.stdout + result.stderr
    assert set(reports) == {"pytest-junit.xml", "pytest-native-junit.xml"}
    if not selection:
        assert reports["pytest-junit.xml"] == {"test_default"}
        assert reports["pytest-native-junit.xml"] == {"test_integration", "test_slow"}


def test_source_intel_job_keeps_scoped_paths_and_bounded_workers():
    block, markers = _source_intel_settings()
    assert markers == "(slow or integration) and not corpus"
    assert "test_path: ${{ needs.changes.outputs.source_intel_files }}" in block
    assert "contains(needs.changes.outputs.source_intel_files, ' ')" in block
    assert "&& '-n 2 --dist loadfile' || ''" in block


@pytest.mark.parametrize("tier", ["engine", "source_intel"])
@pytest.mark.parametrize("file_count", [1, 2, 5])
def test_native_worker_selection_matches_scope_output_contract(
    tmp_path, monkeypatch, tier, file_count,
):
    monkeypatch.syspath_prepend(str(ROOT / ".github/scripts"))
    from pytest_workers import worker_count
    from test_scope import _emit_outputs

    paths = [Path(f"test_{index}.py") for index in range(file_count)]
    for path in paths:
        (tmp_path / path).touch()
    outputs = {}
    _emit_outputs({tier: {"run": True, "files": paths}}, outputs.__setitem__)
    selected = outputs[f"{tier}_files"]
    monkeypatch.chdir(tmp_path)
    # This is the GHA contains(..., ' ') predicate on the actual emitter's
    # file-list format, cross-checked against the bounded-worker helper.
    assert (2 if " " in selected else 0) == worker_count(selected.split())

    workflow = (ROOT / ".github/workflows/tests.yml").read_text()
    job = "source-intel" if tier == "source_intel" else tier
    block = workflow.split(f"  python-unit-tests-{job}:\n", 1)[1]
    block = re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]
    assert f"test_path: ${{{{ needs.changes.outputs.{tier}_files }}}}" in block
    distribution = "worksteal" if tier == "engine" else "loadfile"
    assert (f"pytest_args: ${{{{ contains(needs.changes.outputs.{tier}_files, ' ') "
            f"&& '-n 2 --dist {distribution}' || '' }}}}") in block


def test_combined_native_rule_controls_have_ci_and_nightly_owners():
    _, markers = _native_tier_settings("engine")
    assert markers == "integration and not corpus"
    path = ROOT / "engine/coccinelle/tests/test_resource_leak_err_rule.py"
    tree = ast.parse(path.read_text())
    case = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                and n.name == "test_error_path_controls")
    assert "pytest.mark.integration" in {ast.unparse(n) for n in case.decorator_list}
    nightly = (ROOT / ".github/workflows/nightly.yml").read_text()
    step = nightly.split("      - name: Run integration tests (retry once on external outage)\n", 1)[1]
    step = step.split("      - name:", 1)[0]
    assert "python -m pytest -m integration core packages engine" in step
    tokens = shlex.split(step)
    assert not any(token == "--ignore=engine" or token.startswith("--ignore=engine/coccinelle")
                   for token in tokens)


def test_semgrep_native_fixture_checks_keep_their_nightly_owner():
    path = ROOT / "engine/semgrep/tests/test_rule_fixtures.py"
    tree = ast.parse(path.read_text())
    native = []
    for case in tree.body:
        if not isinstance(case, ast.FunctionDef) or not case.name.startswith("test_"):
            continue
        calls = {ast.unparse(n.func) for n in ast.walk(case) if isinstance(n, ast.Call)}
        markers = {ast.unparse(n) for n in case.decorator_list}
        if "_run_semgrep" in calls or "subprocess.run" in calls:
            native.append(case.name)
            assert "pytest.mark.integration" in markers, case.name
        else:
            assert "pytest.mark.integration" not in markers, case.name
    assert native
    nightly = (ROOT / ".github/workflows/nightly.yml").read_text()
    step = nightly.split("      - name: Run Semgrep engine regressions\n", 1)[1]
    step = step.split("      - name:", 1)[0]
    assert "python -m pytest engine/semgrep/tests" in step
    assert "-m 'slow or integration'" in step

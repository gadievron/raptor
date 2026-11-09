"""Only Python sources admitted by the CodeQL config should wake extraction."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


def _load_filters():
    path = Path(__file__).resolve().parents[1] / "scripts/compute_filters.py"
    spec = importlib.util.spec_from_file_location("owned_codeql_source_filters", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


filters = _load_filters()


def test_test_only_python_diff_skips_extraction():
    result = filters.evaluate(["core/audit/tests/test_scorecard_events.py"])
    assert result == dict.fromkeys(filters.FILTERS, False)


def test_production_python_neighbor_still_scans():
    assert filters.evaluate(["core/audit/scorecard_events.py"])["codeql_python"]


@pytest.mark.parametrize("path", [
    "tests/root_case.py", "test/fixtures/sample.py",
    ".github/tests/test_filters.py", "packages/demo/test_fixtures/input.py",
    ".claude/worktrees/demo/core/code.py", "packages/web/_probe_tls.py",
])
def test_config_excluded_python_sources_skip_extraction(path):
    assert not filters.evaluate([path])["codeql_python"]


@pytest.mark.parametrize("path", [
    "test_source.py", "core/testing/helpers.py", "core/tests_support/input.py",
    "packages/web/_probe_tls_helpers.py",
])
def test_nearby_scanned_sources_keep_extraction(path):
    assert filters.evaluate([path])["codeql_python"]


def test_actual_config_is_recognised():
    expected = [json.loads(line[4:]) for line in filters.CONFIG.read_text().splitlines()
                if line.startswith("  - ")]
    assert expected
    assert filters._ignored_source_patterns() == tuple(expected)


def test_workflow_uses_the_selectors_config_without_overrides():
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github/workflows/codeql.yml").read_text()
    block = re.search(r"^      - name: Initialize CodeQL\n(?:(?!      - ).*\n)+",
                      workflow, re.M)
    assert block is not None
    config = re.search(r"^          config-file: (.+)$", block[0], re.M)
    assert config is not None
    assert config[1] == "./" + filters.CONFIG.relative_to(root).as_posix()
    assert not re.search(r"^          config:", block[0], re.M)


def test_mixed_diff_keeps_production_scan():
    assert filters.evaluate(["core/tests/input.py", "core/runtime.py"])["codeql_python"]


@pytest.mark.parametrize("path", [
    ".github/codeql/codeql-config.yml", ".github/codeql/tests/control.py",
    ".github/workflows/codeql.yml", ".github/scripts/ci_push_base.py",
])
def test_metadata_triggers_override_source_exclusions(path):
    assert filters.evaluate([path]) == dict.fromkeys(filters.FILTERS, True)


def test_source_exclusion_keeps_other_language_and_dependency_triggers():
    result = filters.evaluate(["core/tests/fixture.py", "uv.lock", "core/native.c"])
    assert result["codeql_python"] and result["codeql_cpp"]
    assert not result["codeql_actions"]
    # The C/C++ filter remains broad; only Python source admission changes.
    assert filters.evaluate(["core/tests/fixture.c"])["codeql_cpp"]


@pytest.mark.parametrize("text", [
    "name: '\npaths-ignore:\n  - \"**/tests/**\"\n#'\n",
    'paths-ignore: ["**/tests/**"]\n',
    'paths-ignore:\n  - **/tests/**\n',
    'paths-ignore:\n  - null\n',
    'paths-ignore:\n  - "**/tests/**"\nqueries: []\n',
    'paths-ignore:\n  - "**/tests/**"\npaths-ignore:\n  - "other"\n',
    'paths-ignore:\n - "**/tests/**"\n',
    'paths-ignore:\n  - "**broken/**"\n',
    'paths-ignore:\n  - "**/tests/**"\nname: |\n  - "**/core/**"\n',
    'paths-ignore:\n  - "**/tests/**"\n  - "core/[ab]/**"\n',
])
def test_unfamiliar_config_keeps_broad_matching(tmp_path, monkeypatch, text):
    config = tmp_path / "config.yml"
    config.write_text(text)
    monkeypatch.setattr(filters, "CONFIG", config)
    assert filters.evaluate(["core/tests/input.py"])["codeql_python"]


def test_missing_config_keeps_broad_matching(tmp_path, monkeypatch):
    monkeypatch.setattr(filters, "CONFIG", tmp_path / "missing")
    assert filters.evaluate(["core/tests/input.py"])["codeql_python"]


@pytest.mark.parametrize("path,pattern,expected", [
    ("tests/a.py", "**/tests/**", True),
    ("core/sub/tests/deeper/a.py", "**/tests/**", True),
    ("core/tests_support/a.py", "**/tests/**", False),
    ("core/tests/a.py", "core/**/tests/*.py", True),
    ("core/sub/tests/a.py", "core/**/tests/*.py", True),
    ("other/core/tests/a.py", "core/**/tests/*.py", False),
    ("core/sub/tests/a.py", "core/*/tests/*.py", True),
    ("core/sub/deep/tests/a.py", "core/*/tests/*.py", False),
    ("packages/web/_probe_tls.py", "packages/web/_probe_tls.py", True),
    ("packages/web/_probe_tls_helpers.py", "packages/web/_probe_tls.py", False),
])
def test_codeql_glob_segments(path, pattern, expected):
    assert filters._ignored_source(path, pattern) is expected


@pytest.mark.skipif(not shutil.which("bash") or not shutil.which("jq"),
                    reason="native shell and jq")
@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_rename_into_ignored_tree_keeps_source_scan(tmp_path, event):
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "owned_codeql_changed_step", root / ".github/tests/test_changed_files_step.py")
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    workflow = root / ".github/workflows/codeql.yml"
    row = {"filename": "core/tests/fixture.py", "previous_filename": "core/runtime.py"}
    if event == "push":
        listed, output = harness._run_step(tmp_path, workflow, {"files": [row]})
        assert "list=" in output
    else:
        script = harness._extract_changed_files_run(workflow)
        listed = tmp_path / "changed.txt"
        script = script.replace("/tmp/changed_files.txt", str(listed))
        bindir = tmp_path / "bin"
        bindir.mkdir()
        stub = bindir / "gh"
        stub.write_text('#!/bin/bash\nset -euo pipefail\n'
                        '[[ "$1" == api && "$2" == --paginate && "$4" == --jq ]]\n'
                        'jq -r "$5" "$GH_STUB_RESPONSE"\n')
        stub.chmod(0o700)
        response = tmp_path / "pr.json"
        response.write_text(json.dumps([row]))
        result = subprocess.run(
            [shutil.which("bash"), "-c", script], capture_output=True, text=True, timeout=10,
            env={"PATH": str(bindir) + os.pathsep + os.defpath, "HOME": str(tmp_path),
                 "EVENT": event, "REPO": "owner/repo", "PR_NUMBER": "4",
                 "GH_STUB_RESPONSE": str(response), "GITHUB_OUTPUT": str(tmp_path / "output")},
        )
        assert result.returncode == 0, result.stdout + result.stderr
    paths = listed.read_text().splitlines()
    assert paths == [row["filename"], row["previous_filename"]]
    assert filters.evaluate(paths)["codeql_python"]

"""Execute both reusable tier commands to pin selection and failure semantics."""

from __future__ import annotations

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


def _source_intel_settings():
    text = (ROOT / ".github/workflows/tests.yml").read_text()
    block = text.split("  python-unit-tests-source-intel:\n", 1)[1]
    block = re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]
    markers = re.search(r'^      native_pytest_markers: "([^"]+)"$', block, re.M)
    assert markers is not None, "source-intel must include its native coverage"
    return block, markers.group(1)


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
@pytest.mark.parametrize("marker_mode", ["default", "source-intel", "slow-only"])
def test_tier_shell_preserves_disjoint_marker_selection(tmp_path, branch, marker_mode):
    markers, expected = {
        "default": ("", None),
        "source-intel": (_source_intel_settings()[1], {"test_integration", "test_slow"}),
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
    assert 'pytest_args: "-n 2 --dist loadfile"' in block

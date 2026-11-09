"""Nightly slow and integration phases partition their shared test universe."""

import os
from pathlib import Path
import re
import shlex
import sys
import textwrap
import xml.etree.ElementTree as ET

from core.testing.standalone_cli import run_standalone_cli


ROOT = Path(__file__).resolve().parents[2]
TEST_ROOTS = ["core", "packages", "engine", ".github/tests", ".github/scripts/tests"]


def _commands(step_id):
    text = (ROOT / ".github/workflows/nightly.yml").read_text()
    job = text.split("  slow-integration:\n", 1)[1]
    job = re.split(r"\n  [a-z][a-z0-9-]*:\n", job, maxsplit=1)[0]
    steps = re.split(r"^      - ", job, flags=re.M)[1:]
    step = next(part for part in steps
                if re.search(rf"^        id: {step_id}$", part, re.M))
    body = re.search(r"^        run: \|\n((?:          .*\n|\n)+)", step, re.M)
    assert body is not None
    script = textwrap.dedent(body[1]).replace("\\\n", " ")
    commands = []
    for line in script.splitlines():
        if not line.startswith("python -m pytest "):
            continue
        tokens = shlex.split(line, comments=True)[3:]
        index = tokens.index("-m")
        marker = tokens[index + 1]
        roots = []
        for token in tokens[index + 2:]:
            if token.startswith("-"):
                break
            roots.append(token)
        exclusions = {token for token in tokens
                      if token.startswith(("--ignore=", "--deselect="))}
        commands.append((marker, roots, exclusions))
    return commands


def test_nightly_marker_phases_are_disjoint_and_complete(tmp_path):
    slow, = _commands("slow_tests")
    first, retry = _commands("integration_tests")
    assert first == retry, "retry must keep the original collection boundary"
    assert slow[1] == first[1] == TEST_ROOTS
    assert slow[2] == first[2], "exclusions must agree across phases"
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\nmarkers =\n    slow: slow case\n    integration: native case\n"
    )
    for index, directory in enumerate(TEST_ROOTS):
        path = tmp_path / directory / f"test_markers_{index}.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "import pytest\n"
            "def test_default(): pass\n"
            "@pytest.mark.slow\ndef test_slow_only(): pass\n"
            "@pytest.mark.integration\ndef test_integration_only(): pass\n"
            "@pytest.mark.slow\n@pytest.mark.integration\ndef test_both(): pass\n"
            "@pytest.mark.slow\nclass TestSlowClass:\n"
            "    @pytest.mark.integration\n    def test_both_class(self): pass\n"
        )
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTEST_ADDOPTS="")
    env.pop("PYTHONPATH", None)
    reports = []
    for index, (marker, roots, _) in enumerate((slow, first)):
        report = tmp_path / f"phase-{index}.xml"
        result = run_standalone_cli(
            [sys.executable, "-m", "pytest", "-q", "-m", marker, *roots,
             f"--junitxml={report}"],
            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        cases = list(ET.parse(report).iter("testcase"))
        assert not any(case.find("skipped") is not None for case in cases)
        reports.append({(case.get("classname"), case.get("name")) for case in cases})
    assert reports[0].isdisjoint(reports[1]), "mixed-marker cases ran twice"
    assert len(reports[0]) == len(TEST_ROOTS)
    assert len(reports[1]) == 3 * len(TEST_ROOTS)
    assert {name for _, name in reports[0]} == {"test_slow_only"}
    assert {name for _, name in reports[1]} == {
        "test_integration_only", "test_both", "test_both_class",
    }

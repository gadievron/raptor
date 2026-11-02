"""Semgrep nightly cases have one visible owner in scheduled and full runs."""

import ast
import importlib.util
from pathlib import Path
import re
import shlex
import subprocess
import sys
import textwrap

import pytest

_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/nightly.yml"


def _jobs():
    """Read the repo's block-style workflow using its stdlib step parser."""
    text = _WORKFLOW.read_text()
    script = _WORKFLOW.parents[1] / "scripts/check_workflow_pipefail.py"
    spec = importlib.util.spec_from_file_location("nightly_workflow_steps", script)
    assert spec is not None and spec.loader is not None
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    jobs = {}
    current = None
    for line in text.split("\njobs:\n", 1)[1].splitlines():
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if match:
            current = match.group(1)
            jobs[current] = {"steps": []}
        elif current is not None and line.startswith("    if: "):
            jobs[current]["if"] = line.removeprefix("    if: ")
    for step in parser.parse_steps(str(_WORKFLOW), text):
        jobs[step.job]["steps"].append({
            "run": textwrap.dedent("\n".join(step.run_body)),
        })
    assert jobs and all("if" in job for job in jobs.values())
    return jobs


def _condition(expression, event, suite):
    """Evaluate the workflow's small boolean predicate without eval/exec."""
    text = expression.replace("github.event_name", "event").replace("inputs.suite", "suite")
    tree = ast.parse(text.replace("||", "or").replace("&&", "and"), mode="eval")

    def value(node):
        if isinstance(node, ast.Expression):
            return value(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return {"event": event, "suite": suite}[node.id]
        if isinstance(node, ast.BoolOp):
            values = [value(v) for v in node.values]
            if isinstance(node.op, ast.Or):
                return any(values)
            assert isinstance(node.op, ast.And)
            return all(values)
        assert isinstance(node, ast.Compare) and len(node.ops) == 1
        left, right = value(node.left), value(node.comparators[0])
        if isinstance(node.ops[0], ast.Eq):
            return left == right
        assert isinstance(node.ops[0], ast.NotEq)
        return left != right

    return value(tree)


def _commands(job):
    for step in job["steps"]:
        for line in step.get("run", "").replace("\\\n", " ").splitlines():
            if line.strip().startswith("python -m pytest "):
                yield shlex.split(line)[3:]  # Arguments after python -m pytest.


@pytest.mark.parametrize("event,suite,expected", [
    ("schedule", "", {"slow-integration", "java-query-regressions", "cpp-query-regressions", "semgrep-regressions"}),
    ("workflow_dispatch", "full", {"slow-integration", "java-query-regressions", "cpp-query-regressions", "semgrep-regressions"}),
    ("workflow_dispatch", "semgrep", {"semgrep-regressions"}),
    ("workflow_dispatch", "java", {"java-query-regressions"}),
    ("workflow_dispatch", "cpp", {"cpp-query-regressions"}),
])
def test_job_routing(event, suite, expected):
    jobs = _jobs()
    assert {name for name, job in jobs.items() if _condition(job["if"], event, suite)} == expected


def test_engine_cases_are_excluded_from_both_broad_lanes_and_retry():
    jobs = _jobs()
    dedicated = list(_commands(jobs["semgrep-regressions"]))
    assert len(dedicated) == 1
    assert "engine/semgrep/tests" in dedicated[0]
    metadata_case = "packages/semgrep/tests/test_runner.py::TestSandboxMetadataIntegration"
    assert metadata_case in dedicated[0]
    assert dedicated[0][dedicated[0].index("-m") + 1] == "slow or integration"
    broad = list(_commands(jobs["slow-integration"]))
    assert len(broad) == 3  # Slow, integration, integration retry.
    for command in broad:
        assert "--ignore=engine/semgrep/tests" in command
        assert "--deselect=" + metadata_case in command
    assert {command[command.index("-m") + 1] for command in broad} == {"slow", "integration"}


@pytest.mark.parametrize("body,success", [
    ('<testsuite><testcase name="executed"/></testsuite>', True),
    ('<testsuite/>', False),
    ('<testsuite><testcase name="missing-tool"><skipped/></testcase></testsuite>', False),
])
def test_dedicated_job_rejects_empty_or_skipped_results(tmp_path, body, success):
    job = _jobs()["semgrep-regressions"]
    script = next(s["run"] for s in job["steps"] if "scan-regressions.xml\" <<'PY'" in s.get("run", ""))
    guard = script.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    report = tmp_path / "results.xml"
    report.write_text(body)
    process = subprocess.run([sys.executable, "-c", guard, str(report)],
                             capture_output=True, text=True, timeout=5)
    assert (process.returncode == 0) is success, process.stderr

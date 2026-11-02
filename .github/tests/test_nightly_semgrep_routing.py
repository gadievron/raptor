"""Semgrep nightly cases have one visible owner in scheduled and full runs."""

import ast
from pathlib import Path
import shlex
import subprocess
import sys

import pytest
import yaml

_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/nightly.yml"


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
    jobs = yaml.safe_load(_WORKFLOW.read_text())["jobs"]
    assert {name for name, job in jobs.items() if _condition(job["if"], event, suite)} == expected


def test_engine_cases_are_excluded_from_both_broad_lanes_and_retry():
    jobs = yaml.safe_load(_WORKFLOW.read_text())["jobs"]
    dedicated = list(_commands(jobs["semgrep-regressions"]))
    assert len(dedicated) == 1
    assert "engine/semgrep/tests" in dedicated[0]
    assert dedicated[0][dedicated[0].index("-m") + 1] == "slow or integration"
    broad = list(_commands(jobs["slow-integration"]))
    assert len(broad) == 3  # Slow, integration, integration retry.
    for command in broad:
        assert "--ignore=engine/semgrep/tests" in command
    assert {command[command.index("-m") + 1] for command in broad} == {"slow", "integration"}


@pytest.mark.parametrize("body,success", [
    ('<testsuite><testcase name="executed"/></testsuite>', True),
    ('<testsuite/>', False),
    ('<testsuite><testcase name="missing-tool"><skipped/></testcase></testsuite>', False),
])
def test_dedicated_job_rejects_empty_or_skipped_results(tmp_path, body, success):
    job = yaml.safe_load(_WORKFLOW.read_text())["jobs"]["semgrep-regressions"]
    script = next(s["run"] for s in job["steps"] if "scan-regressions.xml\" <<'PY'" in s.get("run", ""))
    guard = script.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    report = tmp_path / "results.xml"
    report.write_text(body)
    process = subprocess.run([sys.executable, "-c", guard, str(report)],
                             capture_output=True, text=True, timeout=5)
    assert (process.returncode == 0) is success, process.stderr

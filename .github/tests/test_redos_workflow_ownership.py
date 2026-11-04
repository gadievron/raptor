"""A deduplicated census must still execute on every supported event."""

import ast
import json
from pathlib import Path
import re
import shlex
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]
CENSUS = ".github/tests/test_redos_idiom_census.py"
AUTOMATIC = {"pull_request", "push", "merge_group"}
FULL = {"schedule", "workflow_dispatch"}


def _workflow(name):
    return (ROOT / ".github/workflows" / name).read_text()


def _triggers(workflow):
    return workflow.split("\non:\n", 1)[1].split("\nconcurrency:", 1)[0]


def _job(workflow, name):
    body = workflow.split(f"\n  {name}:\n", 1)[1]
    return re.split(r"^  [\w-]+:\s*$", body, maxsplit=1, flags=re.MULTILINE)[0]


def _step(job, name):
    body = job.split(f"      - name: {name}\n", 1)[1]
    return re.split(r"^      - ", body, maxsplit=1, flags=re.MULTILINE)[0]


def _command(step):
    body = step.split("        run: |\n", 1)[1]
    return shlex.split(textwrap.dedent(body), comments=True)


def _condition_allows(expression, *, event, outcome, cancelled):
    """Evaluate the small Boolean subset used by the fallback gate."""
    expression = expression.removeprefix("${{").removesuffix("}}").strip()
    expression = expression.replace("!cancelled()", "active")
    expression = expression.replace("github.event_name", "event")
    expression = expression.replace("steps.ci_tests.outcome", "outcome")
    expression = expression.replace("&&", " and ").replace("||", " or ")
    values = {"event": event, "outcome": outcome, "active": not cancelled}

    def value(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return values[node.id]
        if isinstance(node, ast.BoolOp):
            items = [value(item) for item in node.values]
            return all(items) if isinstance(node.op, ast.And) else any(items)
        if isinstance(node, ast.Compare):
            assert len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq)
            return value(node.left) == value(node.comparators[0])
        raise AssertionError(f"unhandled workflow gate: {ast.dump(node)}")

    return value(ast.parse(expression, mode="eval").body)


@pytest.mark.parametrize("event", sorted(AUTOMATIC | FULL))
def test_census_has_exactly_one_owner_for_each_event(event):
    lint = _workflow("lint.yml")
    suite = _workflow("tests.yml")
    assert set(re.findall(r"^  (\w+):", _triggers(suite), re.MULTILINE)) == AUTOMATIC | FULL
    trigger_block = _triggers(lint)
    assert AUTOMATIC <= set(re.findall(r"^  (\w+):", trigger_block, re.MULTILINE))
    assert not re.search(r"^\s+paths(?:-ignore)?:", trigger_block, re.MULTILINE)
    for shared in ("pull_request", "push"):
        block = trigger_block.split(f"  {shared}:\n", 1)[1].split("\n  ", 1)[0]
        assert re.search(r"branches:\s*\[\s*main\s*\]", block)

    lint_owner = _step(_job(lint, "repo-invariants"), "Run ReDoS idiom census")
    assert CENSUS in _command(lint_owner)
    ci = _job(suite, "ci-lint-tests")
    main = _command(_step(ci, "Run CI filter-coverage tests"))
    assert [arg for arg in main if arg.startswith("--ignore=")] == [f"--ignore={CENSUS}"]
    fallback = _step(ci, "Run ReDoS census for full-suite events")
    assert CENSUS in _command(fallback)
    condition = re.search(r"^        if: (.+)$", fallback, re.MULTILINE).group(1)
    for outcome in ("success", "failure", "skipped"):
        for cancelled in (False, True):
            runs = _condition_allows(condition, event=event, outcome=outcome, cancelled=cancelled)
            assert runs == (event in FULL and outcome != "skipped" and not cancelled)
    assert int(event in AUTOMATIC) + int(_condition_allows(
        condition, event=event, outcome="success", cancelled=False,
    )) == 1


def test_both_census_owners_reject_skipped_checks():
    baseline = json.loads((ROOT / ".github/scripts/skip_budget_baseline.json").read_text())
    assert baseline["redos-census"]["skips"] == 0
    for workflow, job, owner in (
        ("lint.yml", "repo-invariants", "Run ReDoS idiom census"),
        ("tests.yml", "ci-lint-tests", "Run ReDoS census for full-suite events"),
    ):
        body = _job(_workflow(workflow), job)
        check = _step(body, "Require complete ReDoS census execution")
        assert "--lane redos-census --full" in check
        emitted = next(arg.split("=", 1)[1] for arg in _command(_step(body, owner))
                       if arg.startswith("--junitxml="))
        command = _command(check)
        assert command[command.index("--junit-xml") + 1] == emitted

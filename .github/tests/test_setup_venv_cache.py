"""Exercise the composite action's real cache-selection expressions without I/O."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_ACTION = Path(__file__).resolve().parents[1] / "actions/setup-venv/action.yml"


def _steps():
    # This action has flat, block-style steps. Keep CI's stdlib+pytest-only
    # contract: extract scalar fields, including folded expressions, by indent.
    return [part.splitlines() for part in re.split(r"(?m)^    - name: ", _ACTION.read_text())[1:]]


def _field(lines, key, indent=6):
    prefix = " " * indent + key + ":"
    for index, line in enumerate(lines):
        if not line.startswith(prefix):
            continue
        value = line[len(prefix):].strip()
        if value != ">-":
            return value
        folded = []
        for continuation in lines[index + 1:]:
            if not continuation.strip() or continuation.lstrip().startswith("#"):
                continue
            if len(continuation) - len(continuation.lstrip()) <= indent:
                break
            folded.append(continuation.strip())
        return " ".join(folded)
    return ""


def _expression(text, context):
    text = text.strip().removeprefix("${{").removesuffix("}}").strip()
    text = re.sub(r"\b(?:steps|inputs|runner|env)\.[A-Za-z0-9_.-]+",
                  lambda match: repr(context.get(match[0], "")), text)
    text = text.replace("&&", " and ").replace("||", " or ")
    text = re.sub(r"!(?!=)", " not ", text).strip()

    def visit(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.BoolOp):
            for child in node.values:
                value = visit(child)
                if isinstance(node.op, ast.And) and not value:
                    return value
                if isinstance(node.op, ast.Or) and value:
                    return value
            return value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not visit(node.operand)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = visit(node.left), visit(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "format":
            assert not node.keywords
            template, *values = [visit(arg) for arg in node.args]
            return template.format(*values)
        raise AssertionError(f"Unsupported Actions expression node: {ast.dump(node)}")

    return visit(ast.parse(text, mode="eval").body)


def _simulate(save, first, second=None, rebuild="success"):
    context = {"inputs.save-on-rebuild": str(save).lower()}
    selected = []
    failed = False
    for step in _steps():
        # All conditions in this action use the default success() guard;
        # continue-on-error lets a restore failure reach its fallback.
        condition = _field(step, "if")
        if failed or condition and not _expression(condition, context):
            continue
        name, step_id = step[0].strip(), _field(step, "id")
        selected.append(name)
        if step_id in {"cache-1", "cache-2"}:
            result = first if step_id == "cache-1" else second
            assert result is not None, f"Unexpected restore attempt: {step_id}"
            outcome, matched = result
            context[f"steps.{step_id}.outputs.cache-matched-key"] = matched
            context[f"steps.{step_id}.outputs.cache-hit"] = str(matched == "exact").lower()
        else:
            outcome = rebuild if step_id == "rebuild" else "success"
        if step_id:
            context[f"steps.{step_id}.outcome"] = outcome
        if outcome == "failure" and _field(step, "continue-on-error") != "true":
            failed = True
    return selected, failed


@pytest.mark.parametrize("save,first,second,backoff,rebuild,saved", [
    (True, ("success", "exact"), None, False, False, False),
    (False, ("success", "exact"), None, False, False, False),
    (True, ("success", ""), None, False, True, True),
    (False, ("success", ""), None, False, True, False),

    (True, ("failure", ""), ("success", "exact"), True, False, False),
    (True, ("failure", ""), ("success", ""), True, True, True),
    (True, ("failure", ""), ("failure", ""), True, True, True),
    (False, ("failure", ""), ("success", "prefix"), True, True, False),
    (False, ("failure", ""), ("failure", ""), True, True, False),
    # Even a partially populated output is not evidence of a usable restore.
    (True, ("failure", "partial"), ("failure", "partial"), True, True, True),
])
def test_restore_and_rebuild_paths(save, first, second, backoff, rebuild, saved):
    selected, failed = _simulate(save, first, second)
    assert not failed
    assert ("Backoff before retry" in selected) == backoff
    assert any(name.startswith("Restore venv from cache (attempt 2") for name in selected) == (second is not None)
    assert any(name.startswith("Install uv (rebuild") for name in selected) == rebuild
    assert any(name.startswith("Rebuild venv (") for name in selected) == rebuild
    assert ("Save rebuilt venv to cache" in selected) == saved
    assert selected[-1] == "Restore venv permissions and fix symlinks"


@pytest.mark.parametrize("step_id", ["cache-1", "cache-2"])
def test_normal_miss_is_not_an_action_error(step_id):
    step = next(step for step in _steps() if _field(step, "id") == step_id)
    assert _field(step, "fail-on-cache-miss", indent=8) in {"", "false"}


def test_failed_rebuild_is_not_saved_or_used():
    selected, failed = _simulate(True, ("success", ""), rebuild="failure")
    assert failed
    assert "Save rebuilt venv to cache" not in selected
    assert "Restore venv permissions and fix symlinks" not in selected


def test_no_executable_environment_can_restore_an_old_lock_prefix():
    for step in _steps():
        assert _field(step, "restore-keys", indent=8) == ""
    keys = [_field(step, "key", indent=8) for step in _steps() if _field(step, "key", indent=8)]
    assert len(keys) == 3
    assert set(keys) == {"${{ steps.venv-key.outputs.key }}"}


@pytest.mark.parametrize('existing,expected', [('', True), ('/owned/uv-cache', False)])
def test_rebuild_does_not_add_a_second_owner_for_an_existing_uv_cache(existing, expected):
    step = next(step for step in _steps() if step[0].startswith('Install uv (rebuild'))
    assert _expression(_field(step, 'enable-cache', indent=8), {'env.UV_CACHE_DIR': existing}) is expected

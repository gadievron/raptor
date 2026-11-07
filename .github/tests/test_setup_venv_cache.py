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


@pytest.mark.parametrize('extras,expected_extras', [('--extra grammars', ['--extra', 'grammars']), ('--no-dev', ['--no-dev']),
                                                   ('--no-dev --extra cvss', ['--no-dev', '--extra', 'cvss']),
                                                   ('--extra cvss', ['--extra', 'cvss'])])
@pytest.mark.parametrize('method', ['export', 'sync'])
@pytest.mark.parametrize('status', [0, 23])
def test_native_rebuild_keeps_method_extras_active_env_and_failure_status(tmp_path, method, status, extras, expected_extras):
    import json
    import os
    import subprocess
    import sys
    import textwrap

    rebuild = next(lines for lines in _steps() if lines[0].startswith('Rebuild venv ('))
    start = rebuild.index('      run: |')
    script = textwrap.dedent('\n'.join(rebuild[start + 1:]))
    tools = tmp_path / 'tools with spaces'
    tools.mkdir()
    (tools / 'python3').symlink_to(sys.executable)
    uv = tools / 'uv'
    uv.write_text(f'''#!{sys.executable}
import json, os, pathlib, shlex, sys
args = sys.argv[1:]
with pathlib.Path(os.environ['UV_RECORD']).open('a') as record:
    record.write(json.dumps({{'args': args, 'active': os.environ.get('VIRTUAL_ENV')}}) + '\\n')
if args[0] == 'venv':
    target = pathlib.Path(args[-1])
    (target / 'bin').mkdir(parents=True)
    (target / 'bin/activate').write_text('export VIRTUAL_ENV=' + shlex.quote(str(target)) + '\\n')
elif args[0] == 'export':
    print('pytest==9.1.1')
    raise SystemExit(int(os.environ['INSTALL_EXIT']))
elif args[0] == 'sync':
    raise SystemExit(int(os.environ['INSTALL_EXIT']))
else:
    assert args == ['pip', 'install', '-r', '-']
    assert sys.stdin.read().strip() == 'pytest==9.1.1'
''')
    uv.chmod(0o755)
    venv = tmp_path / 'project environment'
    record = tmp_path / 'uv-record.jsonl'
    env = dict(os.environ, PATH=str(tools) + ':/usr/bin:/bin', VENV_PATH=str(venv),
               VENV_CACHE_INSTALL_METHOD=method, UV_EXPORT_EXTRA_ARGS=extras,
               UV_RECORD=str(record), INSTALL_EXIT=str(status))
    env.pop('VIRTUAL_ENV', None)
    result = subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == status, result.stdout + result.stderr
    calls = [json.loads(line) for line in record.read_text().splitlines()]
    assert calls[0] == {'args': ['venv', '--clear', '--python', str(tools / 'python3'), str(venv)],
                        'active': None}
    assert all(call['active'] == str(venv) for call in calls[1:])
    if method == 'sync':
        assert [call['args'] for call in calls[1:]] == [
            ['sync', '--locked', '--active', *expected_extras],
        ]
    else:
        assert sorted(call['args'] for call in calls[1:]) == sorted([
            ['export', '--locked', '--no-hashes', *expected_extras],
            ['pip', 'install', '-r', '-'],
        ])


def test_native_permission_repair_handles_a_venv_path_with_spaces(tmp_path):
    import os
    import subprocess
    import sys
    import textwrap

    repair = next(lines for lines in _steps() if lines[0] == 'Restore venv permissions and fix symlinks')
    start = repair.index('      run: |')
    script = textwrap.dedent('\n'.join(repair[start + 1:]))
    venv = tmp_path / 'project environment'
    binary = venv / 'bin'
    binary.mkdir(parents=True)
    tool = binary / 'owned-console'
    tool.write_text('#!/bin/sh\nexit 0\n')
    tool.chmod(0o600)
    (binary / 'python').symlink_to('/owned/missing-interpreter')
    tools = tmp_path / 'tools with spaces'
    tools.mkdir()
    (tools / 'python3').symlink_to(sys.executable)
    result = subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', script],
        cwd=tmp_path, env=dict(os.environ, PATH=str(tools) + ':/usr/bin:/bin', VENV_PATH=str(venv)),
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    for name in ['python', 'python3', f'python{sys.version_info.major}.{sys.version_info.minor}']:
        assert (binary / name).resolve() == Path(sys.executable).resolve()
    assert tool.stat().st_mode & 0o111 == 0o111

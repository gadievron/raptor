"""Relative source operands keep their meaning after child cwd selection."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from packages.coccinelle import runner


@pytest.mark.parametrize("spelling", ["relative", "absolute"])
@pytest.mark.parametrize("mode", ["file", "directory", "batch", "file_set"])
def test_relative_target_operand_reaches_owned_input(tmp_path, monkeypatch, mode, spelling):
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "nested" / "source"
    root.mkdir(parents=True)
    source = root / "owned.c"
    source.write_text("void owned(void) {}\n")
    rules = []
    for name in ("first", "second"):
        rule = tmp_path / f"{name}.cocci"
        rule.write_text(f"@{name}@\nposition p;\n@@\nowned@p(...)\n")
        rules.append(rule)
    target = source if mode == "file" else root
    relative = Path(os.path.relpath(target, Path.cwd()))
    argument = relative if spelling == "relative" else target
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "_spatch_path", lambda: "/unused/spatch")
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        operand = command[command.index("--dir") + 1] if "--dir" in command else command[3]
        effective = (Path(kwargs["cwd"]) / operand).resolve()
        assert effective == (source if mode == "file_set" else target).resolve()
        assert effective.exists()
        output = ""
        if mode != "batch":
            rule_text = Path(command[command.index("--sp-file") + 1]).read_text()
            prefix = re.search(r"COCCIRESULT-[0-9a-f]+:", rule_text).group()
            output = prefix + json.dumps({
                "rule": "first", "file": str(source), "line": 1, "message": "owned",
            }) + "\n"
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    options = {"subprocess_runner": execute, "_installed_version": lambda: "1.3.0"}
    if mode == "file_set":
        options["file_set"] = [source]
    if mode == "batch":
        results = runner.run_rules_batched(argument, rules, **options)
        assert list(results) == ["first", "second"]
        assert all(result.ok for result in results.values())
        assert all(result.files_examined == [str(source)]
                   for result in results.values())
    else:
        result = runner.run_rule(argument, rules[0], **options)
        assert result.ok
        assert result.files_examined == [str(source)]
        assert len(result.matches) == 1
        assert result.matches[0].file == str(source)
    assert len(calls) == 1

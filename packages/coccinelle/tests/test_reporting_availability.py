"""Unavailable reporting cannot become quiet-match evidence."""

import json
import re
import subprocess
from pathlib import Path

import pytest

from packages.coccinelle import runner


@pytest.fixture
def owned(tmp_path, monkeypatch):
    root = tmp_path / "input"
    root.mkdir()
    source = root / "owned.c"
    source.write_text("void owned(void) {}\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "_spatch_path", lambda: "/unused/spatch")
    return tmp_path, root, source


def rule_file(owned, name, shape):
    directory, _, _ = owned
    text = f"@{name}@\nposition p;\n@@\nowned@p(...)\n"
    if shape == "no_position":
        text = f"@{name}@\nidentifier f;\n@@\nf(...)\n"
    elif shape == "multiple":
        text += "\n@other@\nposition q;\n@@\nowned@q(...)\n"
    elif shape == "scripted":
        text += f'\n@script:python@\np << {name}.p;\n@@\nprint("COCCIRESULT:" + "{{}}")\n'
    path = directory / f"{name}.cocci"
    path.write_text(text)
    return path


def execution(owned, names=(), *, emit=True, returncode=0):
    calls = []

    def execute(command, **kwargs):
        text = Path(command[command.index("--sp-file") + 1]).read_text()
        prefix = re.search(r"COCCIRESULT-[0-9a-f]+:", text)
        calls.append((text, prefix.group() if prefix else None))
        output = "--- owned.c\n+++ owned.c\n"
        if prefix:
            output = ""
            if emit:
                for name in names:
                    if f"@{name}@" in text:
                        output += prefix.group() + json.dumps({
                            "rule": name, "file": str(owned[2]), "line": 1,
                        }) + "\n"
        return subprocess.CompletedProcess(command, returncode, stdout=output,
                                           stderr="engine stopped" if returncode else "")

    return execute, calls


@pytest.mark.parametrize("shape", ["no_position", "multiple"])
def test_unsupported_reporting_executes_without_quiet_credit(owned, shape):
    rule = rule_file(owned, "unsupported", shape)
    execute, calls = execution(owned)
    result = runner.run_rule(owned[1], rule, subprocess_runner=execute,
                             _installed_version=lambda: "1.3.0")
    assert len(calls) == 1 and calls[0][1] is None
    assert result.returncode == 0
    assert not result.ok
    assert result.matches == [] and result.files_examined == []
    assert any("reporting unavailable" in error for error in result.errors)


@pytest.mark.parametrize("emit", [False, True], ids=["quiet", "hit"])
def test_report_capable_position_rule_keeps_valid_output(owned, emit):
    rule = rule_file(owned, "plain", "position")
    execute, calls = execution(owned, ("plain",), emit=emit)
    result = runner.run_rule(owned[1], rule, subprocess_runner=execute,
                             _installed_version=lambda: "1.3.0")
    assert len(calls) == 1 and calls[0][1]
    assert result.ok and not result.errors
    assert len(result.matches) == int(emit)
    assert result.files_examined == [str(owned[2])]


def test_engine_error_remains_visible_without_reporter(owned):
    rule = rule_file(owned, "unsupported", "no_position")
    execute, calls = execution(owned, returncode=2)
    result = runner.run_rule(owned[1], rule, subprocess_runner=execute,
                             _installed_version=lambda: "1.3.0")
    assert len(calls) == 1 and not result.ok
    assert result.returncode == 2 and result.files_examined == []
    assert any("code 2" in error for error in result.errors)


def test_mixed_batch_keeps_supported_siblings(owned):
    rules = [rule_file(owned, name, shape) for name, shape in
             [("unsupported", "no_position"), ("good", "scripted"),
              ("good2", "scripted"), ("plain", "position")]]
    execute, calls = execution(owned, ("good", "good2", "plain"))
    results = runner.run_rules_batched(owned[1], rules, allow_scripting=True,
                                       subprocess_runner=execute, _installed_version=lambda: "1.3.0")
    assert list(results) == ["unsupported", "good", "good2", "plain"]
    assert len(calls) == 3
    assert sum("@good@" in text and "@good2@" in text for text, _ in calls) == 1
    assert not results["unsupported"].ok
    assert results["unsupported"].files_examined == []
    for name in ("good", "good2", "plain"):
        assert results[name].ok
        assert len(results[name].matches) == 1
        assert results[name].matches[0].rule == name
        assert results[name].files_examined == [str(owned[2])]


def test_plain_batch_rules_get_individual_reporters(owned):
    rules = [rule_file(owned, name, "position") for name in ("alpha", "beta")]
    execute, calls = execution(owned, ("alpha", "beta"))
    results = runner.run_rules_batched(owned[1], rules, subprocess_runner=execute,
                                       _installed_version=lambda: "1.3.0")
    assert len(calls) == 2
    assert len({prefix for _, prefix in calls if prefix}) == 2
    for name in ("alpha", "beta"):
        assert results[name].ok and len(results[name].matches) == 1
        assert results[name].matches[0].rule == name


def test_untrusted_script_refusal_stays_before_execution(owned):
    rule = rule_file(owned, "scripted", "scripted")
    execute, calls = execution(owned)
    result = runner.run_rule(owned[1], rule, subprocess_runner=execute,
                             _installed_version=lambda: "1.3.0")
    assert calls == [] and not result.ok
    assert result.returncode == -1 and result.files_examined == []

"""Batch splitting and recovery share only the current sweep's inventory."""

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from packages.coccinelle import runner
from packages.coccinelle.tests.test_batch_id_collisions import rule_file


@pytest.fixture
def sweep(tmp_path, monkeypatch):
    target = tmp_path / "src"
    target.mkdir()
    (target / "first.c").write_text("void f(void *p) { free(p); }\n")
    (target / "second.c").write_text("void g(void) {}\n")
    (target / "shared.h").write_text("void g(void);\n")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rules = [rule_file(rules_dir, name, name) for name in ("first", "second", "third", "fourth", "fifth")]
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "_spatch_path", lambda: "/unused/spatch")
    walk = Mock(wraps=runner._walk_c_h)
    monkeypatch.setattr(runner, "_walk_c_h", walk)
    return target, rules, walk


@pytest.mark.parametrize("mode", ["batch", "collision", "timeout", "failure", "isolation"])
@pytest.mark.parametrize("no_includes", [False, True])
def test_recovery_and_split_groups_walk_directory_once(sweep, mode, no_includes):
    target, rules, walk = sweep
    if mode == "collision":
        rules[1].write_text(rules[1].read_text().replace('"rule":"second"', '"rule":"first"'))
    if mode == "isolation":
        rules[2].write_text("@initialize:python@\n@@\nSTATE = 1\n" + rules[2].read_text())
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        if len(calls) == 1 and mode == "timeout":
            raise subprocess.TimeoutExpired(command, 17)
        status = 2 if len(calls) == 1 and mode == "failure" else 0
        return subprocess.CompletedProcess(command, status, stdout="", stderr="")

    results = runner.run_rules_batched(target, rules, allow_scripting=True,
                                       no_includes=no_includes, timeout=17,
                                       subprocess_runner=execute)
    expected = sorted(str(path) for path in target.iterdir()
                      if not no_includes or path.suffix != ".h")
    assert list(results) == [rule.stem for rule in rules]
    assert all(result.ok and result.files_examined == expected for result in results.values())
    walk.assert_called_once_with(target)
    assert len(calls) == {"batch": 1, "collision": 5, "timeout": 6,
                          "failure": 6, "isolation": 3}[mode]
    results["first"].files_examined.append("consumer-local")
    assert all("consumer-local" not in result.files_examined
               for name, result in results.items() if name != "first")


@pytest.mark.parametrize("empty", [False, True])
def test_supplied_inventory_is_reused_without_mutation(sweep, empty):
    target, rules, walk = sweep
    inventory = set() if empty else {str(path) for path in target.iterdir()}
    original = inventory.copy()
    expected = sorted(path for path in inventory if not path.endswith(".h"))
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 2 if len(calls) == 1 else 0, stdout="", stderr="")

    results = runner.run_rules_batched(target, rules, tree_files=inventory, no_includes=True,
                                       allow_scripting=True, subprocess_runner=execute)
    assert all(result.ok and result.files_examined == expected for result in results.values())
    assert inventory == original
    walk.assert_not_called()


def test_next_sweep_rereads_tree_and_failed_rules_claim_no_coverage(sweep):
    target, rules, walk = sweep
    calls = []

    def execute(command, **kwargs):
        text = Path(command[command.index("--sp-file") + 1]).read_text()
        calls.append(text)
        # Both combined batches fail; the first rule also fails individually.
        status = 2 if "begin " in text or "@first@" in text else 0
        return subprocess.CompletedProcess(command, status, stdout="", stderr="")

    first = runner.run_rules_batched(target, rules, allow_scripting=True, subprocess_runner=execute)
    added = target / "added.c"
    added.write_text("void added(void) {}\n")
    second = runner.run_rules_batched(target, rules, allow_scripting=True, subprocess_runner=execute)
    assert walk.call_count == 2
    assert first["first"].errors and not first["first"].files_examined
    assert second["first"].errors and not second["first"].files_examined
    assert str(added) not in first["second"].files_examined
    assert str(added) in second["second"].files_examined


def test_refused_rules_do_not_trigger_a_directory_walk(sweep):
    target, rules, walk = sweep
    execute = Mock(side_effect=AssertionError("refused rule reached spatch"))
    results = runner.run_rules_batched(target, rules, subprocess_runner=execute)
    assert all(result.errors and not result.files_examined for result in results.values())
    execute.assert_not_called()
    walk.assert_not_called()

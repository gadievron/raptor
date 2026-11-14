"""Inventory errors with all engine, rule-grammar and output-parser seams owned."""
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from packages.coccinelle import runner
from packages.coccinelle.coverage import to_coverage_record
from packages.coccinelle.models import SpatchMatch


@pytest.fixture
def sweep(tmp_path, monkeypatch):
    target = tmp_path / "src"
    target.mkdir()
    hit, quiet = target / "hit.c", target / "quiet.h"
    hit.write_text("owned, never parsed")
    quiet.write_text("owned, never parsed")
    directory = tmp_path / "rules"
    directory.mkdir()
    rules = [directory / (name + ".cocci")
             for name in ("first", "second", "third", "fourth", "fifth")]
    for rule in rules:
        rule.write_text("owned, never parsed")
    state = SimpleNamespace(mode="batch", active=[], calls=[],
                            paths={rule.stem: str(hit) for rule in rules})

    def forbidden(*args, **kwargs):
        pytest.fail("native engine, version or unowned parser reached")

    monkeypatch.setattr(runner, "subprocess", SimpleNamespace(
        run=forbidden, TimeoutExpired=subprocess.TimeoutExpired))
    monkeypatch.setattr(runner, "version", forbidden)
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "_spatch_path", lambda: "/unused/spatch")
    monkeypatch.setattr(runner, "_rule_version_probe", lambda: lambda: None)
    monkeypatch.setattr(runner, "rule_version_refusal", lambda *_: None)
    monkeypatch.setattr(runner, "read_text_gated", lambda path, *a, **kw: Path(path).stem)
    monkeypatch.setattr(runner, "contains_script_block", lambda _: False)
    monkeypatch.setattr(runner, "_lexical_scan", lambda text: (text, False))
    monkeypatch.setattr(runner, "_LIFECYCLE_BLOCK_RE", SimpleNamespace(
        search=lambda text: state.mode == "isolation" and text == "third"))
    monkeypatch.setattr(runner, "_emitted_rule_ids", lambda text:
                        {"shared"} if state.mode == "collision" else {text})
    monkeypatch.setattr(runner, "_inject_harness", lambda text, _: text)
    monkeypatch.setattr(runner, "_make_nonce", lambda: "owned-nonce")
    monkeypatch.setattr(runner, "_parse_errors", lambda _: [])
    monkeypatch.setattr(runner, "_warn_forged_markers", lambda *a, **kw: 0)
    monkeypatch.setattr(runner, "_confined_default_runner", lambda supplied, *a: supplied)
    monkeypatch.setattr(runner, "_parse_results", lambda text, *a, **kw:
                        [SpatchMatch(file=state.paths[name], line=1, rule=name, message="owned")
                         for name in state.active] if text else [])
    walk = Mock(side_effect=PermissionError("owned inventory refusal"))
    monkeypatch.setattr(runner, "_walk_c_h", walk)

    def execute(command, **kwargs):
        text = Path(command[command.index("--sp-file") + 1]).read_text()
        state.active = [rule.stem for rule in rules if rule.stem in text]
        state.calls.append(command)
        if len(state.calls) == 1 and state.mode == "timeout":
            raise subprocess.TimeoutExpired(command, 17)
        status = 2 if len(state.calls) == 1 and state.mode == "failure" else 0
        return subprocess.CompletedProcess(command, status, "owned", "")

    return SimpleNamespace(target=target, hit=hit, quiet=quiet, directory=directory,
                           rules=rules, state=state, walk=walk, execute=execute,
                           env={"TMPDIR": str(tmp_path)})


def assert_incomplete(result, sweep):
    assert not result.ok
    assert result.matches
    assert result.files_examined == [str(sweep.hit)]
    assert any("source inventory unavailable: PermissionError" in error for error in result.errors)
    record = to_coverage_record([result])
    assert record["files_examined"] == [str(sweep.hit)]
    assert record["files_failed"]
    assert str(sweep.quiet) not in record["files_examined"]


def test_single_rule_preserves_matches_and_reports_inventory_refusal(sweep):
    result = runner.run_rule(sweep.target, sweep.rules[0], env=sweep.env,
                             allow_scripting=True, subprocess_runner=sweep.execute)
    assert_incomplete(result, sweep)
    sweep.walk.assert_called_once_with(sweep.target)
    assert len(sweep.state.calls) == 1


def test_sequential_preflight_refusal_does_not_execute_engines(sweep):
    results = runner.run_rules(sweep.target, sweep.directory, exclude_rules={"third"},
                               env=sweep.env, allow_scripting=True,
                               subprocess_runner=sweep.execute)
    assert [result.rule for result in results] == sorted(
        rule.stem for rule in sweep.rules if rule.stem != "third")
    assert all(not result.ok and result.errors and not result.matches
               and not result.files_examined for result in results)
    assert sweep.state.calls == []
    sweep.walk.assert_called_once_with(sweep.target)
    assert to_coverage_record(results)["files_failed"]


@pytest.mark.parametrize("mode", ["batch", "failure", "timeout", "collision", "isolation"])
def test_batch_recovery_discloses_one_failed_inventory(sweep, mode):
    sweep.state.mode = mode
    results = runner.run_rules_batched(sweep.target, sweep.rules, env=sweep.env,
                                       timeout=17, allow_scripting=True,
                                       subprocess_runner=sweep.execute)
    assert set(results) == {rule.stem for rule in sweep.rules}
    for result in results.values():
        assert_incomplete(result, sweep)
    sweep.walk.assert_called_once_with(sweep.target)
    first = results["first"]
    first.errors.append("consumer-local")
    first.files_examined.append("consumer-local")
    assert all("consumer-local" not in result.errors
               and "consumer-local" not in result.files_examined
               for name, result in results.items() if name != "first")


@pytest.mark.parametrize("empty", [False, True])
def test_supplied_inventory_survives_recovery_without_rewalk(sweep, empty):
    sweep.state.mode = "failure"
    inventory = set() if empty else {str(sweep.hit), str(sweep.quiet)}
    original = inventory.copy()
    results = runner.run_rules_batched(sweep.target, sweep.rules, env=sweep.env,
                                       tree_files=inventory, allow_scripting=True,
                                       subprocess_runner=sweep.execute)
    assert all(result.ok and result.files_examined == sorted(inventory | {str(sweep.hit)})
               for result in results.values())
    assert inventory == original
    sweep.walk.assert_not_called()


@pytest.mark.parametrize("no_includes", [False, True])
def test_successful_inventory_preserves_existing_header_filter(sweep, no_includes):
    sweep.walk.side_effect = None
    sweep.walk.return_value = {str(sweep.hit), str(sweep.quiet)}
    results = runner.run_rules_batched(sweep.target, sweep.rules, env=sweep.env,
                                       no_includes=no_includes, allow_scripting=True,
                                       subprocess_runner=sweep.execute)
    expected = [str(sweep.hit)] if no_includes else sorted([str(sweep.hit), str(sweep.quiet)])
    assert all(result.ok and result.files_examined == expected for result in results.values())
    sweep.walk.assert_called_once_with(sweep.target)


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_unexpected_inventory_errors_propagate(sweep, error):
    sweep.walk.side_effect = error("owned unexpected inventory failure")
    with pytest.raises(error, match="owned unexpected inventory failure"):
        runner.run_rule(sweep.target, sweep.rules[0], env=sweep.env,
                        allow_scripting=True, subprocess_runner=sweep.execute)


def test_inventory_refusal_keeps_each_rules_own_match_files(sweep):
    other = sweep.target / "other.c"
    other.write_text("owned, never parsed")
    sweep.state.paths["second"] = str(other)
    results = runner.run_rules_batched(sweep.target, sweep.rules[:2], env=sweep.env,
                                       allow_scripting=True, subprocess_runner=sweep.execute)
    assert results["first"].files_examined == [str(sweep.hit)]
    assert results["second"].files_examined == [str(other)]
    assert all(not result.ok and result.errors for result in results.values())
    record = to_coverage_record(list(results.values()))
    assert record["files_examined"] == sorted([str(sweep.hit), str(other)])
    assert record["files_failed"]
    sweep.walk.assert_called_once_with(sweep.target)

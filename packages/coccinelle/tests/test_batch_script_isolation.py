"""Lifecycle scripts from independent rules need independent interpreters."""

from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.coccinelle import runner
from packages.coccinelle.models import SpatchResult
from packages.coccinelle.tests.test_batch_id_collisions import rule_file


@pytest.mark.parametrize("header", ["@initialize:python@", "@finalize:python@",
                                   "@/*comment*/initialize : python@", "@\nfinalize:python@"])
def test_lifecycle_rules_do_not_enter_combined_process(tmp_path, monkeypatch, header):
    before = rule_file(tmp_path, "before", "before")
    left = rule_file(tmp_path, "left", "left")
    right = rule_file(tmp_path, "right", "right")
    after = rule_file(tmp_path, "after", "after")
    before.write_text(header + "\n@@\nSTATE = 1\n" + before.read_text())
    after.write_text(header + "\n@@\nSTATE = 2\n" + after.read_text())
    monkeypatch.setattr(runner, "is_available", lambda: True)
    events = []

    def individual(target, rule, **kw):
        events.append(rule.stem)
        assert kw["timeout"] == 17 and kw["no_includes"] and kw["allow_scripting"]
        return SpatchResult(rule.stem)

    def batch(cmd, **kw):
        text = Path(cmd[cmd.index("--sp-file") + 1]).read_text()
        assert "STATE =" not in text
        assert "begin left" in text and "begin right" in text
        assert kw["timeout"] == 17
        events.append("left+right")
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(runner, "run_rule", individual)
    result = runner.run_rules_batched(tmp_path / "target.c", [before, left, right, after],
                                      timeout=17, no_includes=True, allow_scripting=True,
                                      subprocess_runner=batch)
    assert events == ["before", "left+right", "after"]
    assert list(result) == ["before", "left", "right", "after"]


def test_lifecycle_mentions_in_comments_remain_batched(tmp_path, monkeypatch):
    rules = [rule_file(tmp_path, name, name) for name in ("left", "right")]
    rules[0].write_text("// @initialize:python@ is only documentation\n" + rules[0].read_text())
    monkeypatch.setattr(runner, "is_available", lambda: True)
    calls = []
    def batch(*args, **kw):
        calls.append(1)
        return SimpleNamespace(stdout="", stderr="", returncode=0)
    def individual(*args, **kw):
        raise AssertionError("comment must not force individual execution")
    monkeypatch.setattr(runner, "run_rule", individual)
    assert len(runner.run_rules_batched(tmp_path / "target.c", rules,
                                       allow_scripting=True, subprocess_runner=batch)) == 2
    assert calls == [1]


@pytest.mark.skipif(not runner.is_available(), reason="spatch not installed")
def test_native_initializers_keep_each_rules_own_state(tmp_path):
    rules = []
    for name, value in (("first", 1), ("second", 2)):
        path = rule_file(tmp_path, name, name)
        text = path.read_text().replace(f'"message":"{name}"', '"message":str(CROSS_RULE_STATE)')
        path.write_text(f"@initialize:python@\n@@\nCROSS_RULE_STATE = {value}\n" + text)
        rules.append(path)
    target = tmp_path / "target.c"
    target.write_text("void f(void *p) {\n    free(p);\n}\n")
    expected = {p.stem: runner.run_rule(target, p, no_includes=True, allow_scripting=True)
                for p in rules}
    actual = runner.run_rules_batched(target, rules, no_includes=True, allow_scripting=True)
    for name, message in (("first", "1"), ("second", "2")):
        assert actual[name].ok
        assert [match.message for match in actual[name].matches] == [message]
        before, after = asdict(expected[name]), asdict(actual[name])
        before.pop("elapsed_ms")
        after.pop("elapsed_ms")
        assert before == after

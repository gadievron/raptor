"""Timed-out batches retry individual rules rather than exporting partial coverage."""

from dataclasses import asdict
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest

from packages.coccinelle import runner
from packages.coccinelle.tests.test_batch_id_collisions import rule_file


def prefix_and_text(cmd):
    text = Path(cmd[cmd.index("--sp-file") + 1]).read_text()
    return re.search(r"COCCIRESULT-[0-9a-f]{32}:", text).group(0), text


def test_timeout_retries_keep_options_results_and_clean_scratch(tmp_path, monkeypatch):
    rules = [rule_file(tmp_path, name, name) for name in ("first", "second")]
    bad = tmp_path / "bad.cocci"
    bad.write_bytes(b"\xff")
    target = tmp_path / "target.c"
    target.write_text("void f(void *p) { free(p); }\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    calls = []
    scratches = []
    env = {"KEEP_ME": "value"}

    def execute(cmd, **kw):
        prefix, text = prefix_and_text(cmd)
        calls.append(text)
        assert kw["timeout"] == 17
        assert "--no-includes" in cmd and ["-D", "func=free"] == cmd[-2:]
        assert kw["env"]["KEEP_ME"] == "value"
        scratches.append(Path(kw["env"]["TMPDIR"]))
        if len(calls) == 1:
            (scratches[-1] / "stranded-working-copy").write_text("partial")
            partial = prefix + json.dumps({"file": str(target), "line": 9999, "rule": "first"})
            raise subprocess.TimeoutExpired(cmd, 17, output=partial)
        if "@first@" in text:
            return SimpleNamespace(returncode=0, stdout="", stderr=prefix + json.dumps(
                {"file": str(target), "line": 5, "rule": "first", "message": "complete"}))
        return SimpleNamespace(returncode=2, stdout="", stderr="individual rule failure")

    out = runner.run_rules_batched(target, rules + [bad], no_includes=True, timeout=17,
                                   env=env, defines={"func": "free"}, allow_scripting=True,
                                   subprocess_runner=execute)
    assert len(calls) == 3  # One batch, then exactly one attempt per accepted rule.
    assert out["first"].ok
    assert [m.line for m in out["first"].matches] == [5]
    assert out["second"].returncode == 2 and out["second"].errors
    assert out["second"].files_examined == []
    assert out["bad"].returncode == -1 and "unreadable" in out["bad"].errors[0]
    assert len(set(scratches)) == 3
    assert all(not path.exists() for path in scratches)
    assert env == {"KEEP_ME": "value"}


def test_individual_timeouts_do_not_trigger_more_batch_retries(tmp_path, monkeypatch):
    rules = [rule_file(tmp_path, name, name) for name in ("first", "second")]
    target = tmp_path / "target.c"
    target.write_text("void f(void) {}\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    calls = []
    def timeout(cmd, **kw):
        calls.append(cmd)
        raise subprocess.TimeoutExpired(cmd, 1)
    out = runner.run_rules_batched(target, rules, timeout=1, allow_scripting=True,
                                   subprocess_runner=timeout)
    assert len(calls) == 3
    assert all(result.returncode == -1 and result.errors for result in out.values())
    assert all(not result.files_examined for result in out.values())


@pytest.mark.skipif(not runner.is_available(), reason="spatch not installed")
def test_native_results_after_batch_timeout_match_individual_runs(tmp_path, monkeypatch):
    rules = [rule_file(tmp_path, name, name) for name in ("first", "second")]
    target = tmp_path / "target.c"
    target.write_text("void f(void *p) {\n    free(p);\n}\n")
    expected = {p.stem: runner.run_rule(target, p, no_includes=True, allow_scripting=True)
                for p in rules}
    real = runner._sandboxed_run
    calls = []
    def one_timeout(cmd, **kw):
        calls.append(cmd)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd, 30)
        return real(cmd, **kw)
    monkeypatch.setattr(runner, "_sandboxed_run", one_timeout)
    out = runner.run_rules_batched(target, rules, no_includes=True, timeout=30,
                                   allow_scripting=True)
    assert len(calls) == 3
    for stem in ("first", "second"):
        before, after = asdict(expected[stem]), asdict(out[stem])
        before.pop("elapsed_ms")
        after.pop("elapsed_ms")
        assert after == before
        assert out[stem].ok and len(out[stem].matches) == 1


@pytest.mark.skipif(not runner.is_available(), reason="spatch not installed")
def test_native_parse_failure_does_not_hide_valid_rules_matches(tmp_path):
    good = rule_file(tmp_path, "good", "good")
    bad = tmp_path / "broken.cocci"
    bad.write_text("@broken@\nthis is deliberately invalid SmPL syntax\n@@\n")
    target = tmp_path / "target.c"
    target.write_text("void f(void *p) {\n    free(p);\n}\n")
    expected = runner.run_rule(target, good, no_includes=True, allow_scripting=True)
    actual = runner.run_rules_batched(target, [good, bad], no_includes=True, allow_scripting=True)
    before, after = asdict(expected), asdict(actual["good"])
    before.pop("elapsed_ms")
    after.pop("elapsed_ms")
    assert after == before
    assert actual["good"].ok and len(actual["good"].matches) == 1
    assert actual["broken"].returncode != 0 and actual["broken"].errors

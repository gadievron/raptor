"""Ambiguous batch result IDs must never merge different rules' evidence."""

from dataclasses import asdict
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from packages.coccinelle import runner
from packages.coccinelle.models import SpatchMatch, SpatchResult


def rule_file(root, name, emitted):
    path = root / f"{name}.cocci"
    path.write_text(
        f"@{name}@\nexpression E;\nposition p;\n@@\nfree(E@p);\n"
        f"@script:python@\np << {name}.p;\n@@\nimport json,sys\n"
        "for x in p:\n"
        '    sys.stderr.write("COCCIRESULT:" + json.dumps({'
        f'"file":x.file,"line":int(x.line),"rule":"{emitted}","message":"{name}"'
        '}) + "\\n")\n'
    )
    return path


@pytest.fixture(autouse=True)
def fresh_resolution(monkeypatch):
    monkeypatch.setattr(runner, "_spatch_resolved", False)
    monkeypatch.setattr(runner, "_resolved_spatch", None)


def test_duplicate_ids_preserve_results_options_and_refusals(tmp_path, monkeypatch, caplog):
    first = rule_file(tmp_path, "first", "shared_id")
    second = rule_file(tmp_path, "second", "shared_id")
    refused = tmp_path / "oversize.cocci"
    refused.write_text("x" * 4096)
    monkeypatch.setattr(runner, "_RULE_MAX_BYTES", 1024)
    monkeypatch.setattr(runner, "is_available", lambda: True)
    expected = {
        "first": SpatchResult("first", matches=[SpatchMatch("target.c", 1, rule="shared_id")]),
        "second": SpatchResult("second", errors=["individual rule failure"], returncode=2),
    }
    calls = []
    version_callbacks = []
    target = tmp_path / "target.c"
    include = [tmp_path / "include"]
    env = {"KEEP": "value"}
    defines = {"func": "free"}

    def no_batch(*args, **kwargs):
        raise AssertionError("ambiguous batch must never execute")

    def individual(actual_target, path, **kwargs):
        calls.append(path)
        assert actual_target == target
        version_callbacks.append(kwargs.pop("_installed_version"))
        assert callable(version_callbacks[-1])
        assert kwargs == dict(include_dirs=include, no_includes=True, timeout=17,
                              env=env, defines=defines, subprocess_runner=no_batch,
                              allow_scripting=True)
        return expected[path.stem]

    monkeypatch.setattr(runner, "run_rule", individual)
    results = runner.run_rules_batched(
        target, [first, second, refused], include_dirs=include, no_includes=True,
        timeout=17, env=env, defines=defines, subprocess_runner=no_batch,
        allow_scripting=True,
    )
    assert calls == [first, second]
    assert version_callbacks[0] is version_callbacks[1]
    assert results["first"] is expected["first"]
    assert results["second"] is expected["second"]
    assert results["oversize"].returncode == -1
    assert "cap" in results["oversize"].errors[0]
    assert sum("colliding result IDs" in r.message for r in caplog.records) == 1


@pytest.mark.parametrize("reverse", [False, True])
def test_emitted_id_cannot_take_another_file_stem(tmp_path, monkeypatch, reverse):
    first = rule_file(tmp_path, "first", "second")
    second = rule_file(tmp_path, "second", "other_alias")
    rules = [second, first] if reverse else [first, second]
    calls = []
    monkeypatch.setattr(runner, "is_available", lambda: True)

    def individual(target, rule, **kwargs):
        calls.append(rule)
        return SpatchResult(rule.stem)

    monkeypatch.setattr(runner, "run_rule", individual)
    results = runner.run_rules_batched(tmp_path / "target.c", rules, allow_scripting=True)
    assert calls == rules
    assert list(results) == [p.stem for p in rules]


def test_disjoint_ids_keep_one_batch(tmp_path, monkeypatch):
    first = rule_file(tmp_path, "first", "first_alias")
    second = rule_file(tmp_path, "second", "second_alias")
    target = tmp_path / "target.c"
    target.write_text("void f(void *p) { free(p); }\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    calls = []

    def individual(*args, **kwargs):
        raise AssertionError("disjoint IDs should remain batched")

    def batch(cmd, **kwargs):
        calls.append(cmd)
        text = Path(cmd[cmd.index("--sp-file") + 1]).read_text()
        prefix = re.search(r"COCCIRESULT-[0-9a-f]{32}:", text).group(0)
        stderr = "".join(prefix + json.dumps({"file": str(target), "line": index,
                                             "rule": alias}) + "\n"
                         for index, alias in enumerate(("first_alias", "second_alias"), 1))
        return SimpleNamespace(returncode=0, stdout="", stderr=stderr)

    monkeypatch.setattr(runner, "run_rule", individual)
    results = runner.run_rules_batched(target, [first, second],
                                       subprocess_runner=batch, allow_scripting=True)
    assert len(calls) == 1
    assert [m.rule for m in results["first"].matches] == ["first_alias"]
    assert [m.rule for m in results["second"].matches] == ["second_alias"]


@pytest.mark.skipif(not runner.is_available(), reason="spatch not installed")
def test_native_duplicate_ids_match_individual_execution(tmp_path):
    first = rule_file(tmp_path, "first", "shared_id")
    second = rule_file(tmp_path, "second", "shared_id")
    target = tmp_path / "target.c"
    target.write_text("void f(void *p) {\n    free(p);\n}\n")
    expected = {p.stem: runner.run_rule(target, p, no_includes=True, allow_scripting=True)
                for p in (first, second)}
    actual = runner.run_rules_batched(target, [first, second], no_includes=True, allow_scripting=True)
    for stem in ("first", "second"):
        assert expected[stem].ok and actual[stem].ok
        assert [m.message for m in actual[stem].matches] == [stem]
        before, after = asdict(expected[stem]), asdict(actual[stem])
        before.pop("elapsed_ms")
        after.pop("elapsed_ms")
        assert after == before

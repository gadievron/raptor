"""Rule reads stay bounded on the opened file in every execution lane."""

import os
import subprocess
from pathlib import Path

import pytest

from core.source import gated
from packages.coccinelle import runner


@pytest.fixture(params=["single", "sequential", "batch"])
def execution(request, tmp_path, monkeypatch):
    source = tmp_path / "input.c"
    source.write_text("void f(void) { foo(); }\n")
    rules = tmp_path / "rules"
    rules.mkdir()
    good = rules / "good.cocci"
    good.write_text("@good@\n@@\nfoo()\n")
    bad = rules / "bad.cocci"
    bad.write_text("@bad@\n@@\nfoo()\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "_spatch_path", lambda: "/unused/spatch")
    executed = []

    def execute(command, **kwargs):
        rule_path = Path(command[command.index("--sp-file") + 1])
        executed.append(rule_path.read_text(encoding="utf-8"))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def run():
        if request.param == "single":
            result = runner.run_rule(source, bad, subprocess_runner=execute)
            return {"bad": result}
        if request.param == "sequential":
            return {r.rule: r for r in runner.run_rules(source, rules, subprocess_runner=execute)}
        return runner.run_rules_batched(source, [bad, good], subprocess_runner=execute)

    return bad, executed, run


def _assert_refused(results, executed, reason):
    assert results["bad"].returncode == -1
    assert any(reason in error for error in results["bad"].errors)
    if "good" in results:
        assert results["good"].ok
        assert len(executed) == 1
    else:
        assert not executed


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires filesystem FIFOs")
def test_fifo_rule_is_refused_without_blocking_and_siblings_survive(execution, monkeypatch):
    bad, executed, run = execution
    bad.unlink()
    os.mkfifo(bad)
    original_read = Path.read_text

    def forbid_raw_fifo_read(path, *args, **kwargs):
        # A regression must fail immediately instead of hanging the test
        # process in the old blocking Path.read_text() call.
        if path == bad:
            pytest.fail("rule reader attempted a blocking raw FIFO read")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", forbid_raw_fifo_read)
    _assert_refused(run(), executed, "not a regular file")


@pytest.mark.parametrize("within_budget", [False, True])
def test_growth_after_open_is_bounded_and_complete(execution, monkeypatch, within_budget):
    bad, executed, run = execution
    cap = 128
    monkeypatch.setattr(runner, "_RULE_MAX_BYTES", cap)
    initial = bad.read_text()
    grown = initial + "\n// " + ("appended" if within_budget else "x" * cap) + "\n"
    original_open = gated._open_gated
    grew = False

    def grow_after_fstat(path, **kwargs):
        nonlocal grew
        handle, stat = original_open(path, **kwargs)
        if Path(path) == bad and not grew:
            try:
                bad.write_text(grown)
                grew = True
            except BaseException:
                handle.close()
                raise
        return handle, stat

    monkeypatch.setattr(gated, "_open_gated", grow_after_fstat)
    results = run()
    assert grew
    if within_budget:
        assert all(result.ok for result in results.values())
        assert any("// appended" in text for text in executed)
    else:
        _assert_refused(results, executed, "byte cap")


def test_byte_limit_applies_before_utf8_decoding(execution, monkeypatch):
    bad, executed, run = execution
    monkeypatch.setattr(runner, "_RULE_MAX_BYTES", 128)
    text = "// " + "é" * 80 + "\n"
    assert len(text) < 128 < len(text.encode("utf-8"))
    bad.write_text(text, encoding="utf-8")
    _assert_refused(run(), executed, "byte cap")


def test_rule_symlink_to_regular_file_remains_supported(execution):
    bad, executed, run = execution
    target = bad.with_suffix(".txt")
    bad.rename(target)
    bad.symlink_to(target)
    results = run()
    assert all(result.ok for result in results.values())
    assert executed

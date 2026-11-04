"""A failed rule process cannot count as a successful no-match fixture."""

import json
import subprocess

import pytest

from engine.coccinelle.tests import _rule_runner


def _result(monkeypatch, returncode, stdout="", stderr=""):
    monkeypatch.setattr(
        _rule_runner.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], returncode, stdout=stdout, stderr=stderr,
        ),
    )


@pytest.mark.parametrize("returncode", [1, 2, -9])
@pytest.mark.parametrize("stdout", ["", 'COCCIRESULT:{"rule":"partial"}\n'])
def test_failed_process_rejects_empty_and_partial_results(
    tmp_path, monkeypatch, returncode, stdout,
):
    _result(monkeypatch, returncode, stdout, "injected tool failure")
    with pytest.raises(AssertionError, match="injected tool failure") as raised:
        _rule_runner.run_rule(tmp_path, "int f(void) { return 0; }", tmp_path / "rule.cocci")
    assert f"spatch exited {returncode}" in str(raised.value)
    assert stdout in str(raised.value)


@pytest.mark.parametrize("include_stderr", [True, False])
def test_success_parses_selected_streams(tmp_path, monkeypatch, include_stderr):
    _result(
        monkeypatch, 0,
        'ordinary diagnostic\nCOCCIRESULT:{"rule":"stdout"}\n',
        'COCCIRESULT:{"rule":"stderr"}\n',
    )
    results = _rule_runner.run_rule(
        tmp_path, "int f(void) { return 0; }", tmp_path / "rule.cocci",
        include_stderr=include_stderr,
    )
    assert results == ([{"rule": "stdout"}, {"rule": "stderr"}]
                       if include_stderr else [{"rule": "stdout"}])


def test_successful_no_match_stays_empty(tmp_path, monkeypatch):
    _result(monkeypatch, 0, "ordinary diagnostic", "ordinary warning")
    assert _rule_runner.run_rule(tmp_path, "int f(void);", tmp_path / "rule.cocci") == []


def test_malformed_result_is_not_silently_discarded(tmp_path, monkeypatch):
    _result(monkeypatch, 0, "COCCIRESULT:not json")
    with pytest.raises(json.JSONDecodeError):
        _rule_runner.run_rule(tmp_path, "int f(void);", tmp_path / "rule.cocci")

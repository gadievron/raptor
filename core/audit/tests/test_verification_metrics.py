"""Observe existing memo behavior without changing verdicts, retries or budgets."""

import json
from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch, verification_metrics as metrics
from core.audit.sweep import SweepResult
from core.audit.sweep_memo import SweepMemo
from core.json.jsonl import load_jsonl


def _config(tmp_path):
    return SimpleNamespace(out_dir=tmp_path, sweep_memo=SweepMemo())


def _result(outcome="inconclusive"):
    return SweepResult(tool="semgrep", file_path="a.c", function_name="f",
                       outcome=outcome, details={"reason": "unsupported context"})


def test_identical_inconclusive_check_is_reused_and_changed_inputs_retry(tmp_path):
    config = _config(tmp_path)
    calls = []
    def runner():
        calls.append(1)
        return _result()
    parts = {"file": "hash-a", "function": "f"}
    for source_hash in ("hash-a", "hash-a", "hash-b"):
        result = orch._memoized_sweep_step(config, "semgrep", {**parts, "file": source_hash}, runner)
        assert result.outcome == "inconclusive"
    rows = load_jsonl(tmp_path / metrics.ATTEMPTS_FILENAME)
    assert len(calls) == 2
    assert [r["origin"] for r in rows] == ["fresh", "memo", "fresh"]
    assert rows[0]["input_id"] == rows[1]["input_id"] != rows[2]["input_id"]
    assert rows[0]["reason"] == "unsupported context"
    assert all(r["cost_usd"] is None for r in rows)
    assert all(isinstance(r["ts"], (int, float)) and r["ts"] > 0 for r in rows)
    report = metrics.summarize_attempts(rows)
    assert report["repeated_fresh_inputs"] == 0
    assert report["tools"]["semgrep"]["outcomes"] == {"inconclusive": 3}


def test_transient_error_remains_retryable_and_visible(tmp_path):
    config = _config(tmp_path)
    for _ in range(2):
        orch._memoized_sweep_step(config, "semgrep", {"file": "hash"}, lambda: _result("error"))
    report = metrics.summarize_attempts(load_jsonl(tmp_path / metrics.ATTEMPTS_FILENAME))
    assert report["repeated_fresh_inputs"] == 1
    assert report["tools"]["semgrep"]["origins"] == {"fresh": 2}


def test_raised_error_is_observed_and_original_exception_propagates(tmp_path):
    def runner():
        raise RuntimeError("original error")
    with pytest.raises(RuntimeError, match="original error"):
        orch._memoized_sweep_step(_config(tmp_path), "semgrep", {"file": "hash"}, runner)
    row = load_jsonl(tmp_path / metrics.ATTEMPTS_FILENAME)[0]
    assert row["outcome"] == "error" and row["reason"] == "RuntimeError"


def test_recording_failure_cannot_change_checker_result(tmp_path, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("full disk")
    monkeypatch.setattr(metrics, "append_jsonl", broken)
    result = _result()
    assert orch._memoized_sweep_step(_config(tmp_path), "semgrep", {"file": "hash"}, lambda: result) is result


def test_checkpoint_reuse_is_distinct_from_fresh_work(tmp_path, monkeypatch):
    from core.audit import sweep_checkpoint
    result = _result()
    checkpoint = SimpleNamespace(lookup=lambda key: result)
    monkeypatch.setattr(sweep_checkpoint, "checkpoint_for_run", lambda path: checkpoint)
    orch._memoized_sweep_step(_config(tmp_path), "coccinelle", {"file": "hash"},
                             lambda: pytest.fail("checkpoint must prevent execution"))
    assert load_jsonl(tmp_path / metrics.ATTEMPTS_FILENAME)[0]["origin"] == "checkpoint"


def test_unhashable_inputs_cannot_be_reported_as_equivalent_work(tmp_path):
    config = _config(tmp_path)
    for _ in range(2):
        orch._memoized_sweep_step(config, "semgrep", {"file": None}, _result)
    rows = load_jsonl(tmp_path / metrics.ATTEMPTS_FILENAME)
    assert all(r["input_id"] is None for r in rows)
    assert metrics.summarize_attempts(rows)["repeated_fresh_inputs"] == 0


def test_cli_reads_trail_once_and_reports_missing_coverage(tmp_path, capsys):
    metrics.record_attempt(tmp_path, "semgrep", {"file": "hash"}, _result(), origin="fresh", elapsed_s=0.1)
    assert metrics.main([str(tmp_path), str(tmp_path / "alias" / "..")]) == 0
    assert json.loads(capsys.readouterr().out)["attempts"] == 1
    assert metrics.main([str(tmp_path / "missing")]) == 1
    assert json.loads(capsys.readouterr().out)["missing_trails"]


def test_trail_symlink_cannot_redirect_observation(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("owned")
    (tmp_path / metrics.ATTEMPTS_FILENAME).symlink_to(outside)
    metrics.record_attempt(tmp_path, "semgrep", {}, _result(), origin="fresh", elapsed_s=0)
    assert outside.read_text() == "owned"


def test_oversized_trail_is_not_reported_as_zero_attempts(tmp_path):
    with (tmp_path / metrics.ATTEMPTS_FILENAME).open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    with pytest.raises(SystemExit) as error:
        metrics.main([str(tmp_path)])
    assert error.value.code == 2

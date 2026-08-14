"""Tests for decision logging."""

from __future__ import annotations

import json
import threading

import pytest

from core.dispatch.broker.decision_log import DecisionLog, DecisionRecord


@pytest.fixture()
def log_path(tmp_path):
    return tmp_path / "decisions.jsonl"


class TestDecisionRecord:
    def test_defaults(self):
        rec = DecisionRecord(
            selected_model="claude-haiku-4-5",
            reason="cheapest",
        )
        assert rec.hint_tier == "defer"
        assert rec.success is True
        assert rec.was_retry is False
        assert rec.timestamp > 0

    def test_full_record(self):
        rec = DecisionRecord(
            selected_model="claude-opus-4-6",
            reason="scorecard top pick",
            hint_tier="prefer",
            hint_model="claude-opus-4-6",
            decision_class="agentic:use-after-free",
            prompt_tokens=4200,
            alternatives=[
                {"model": "claude-haiku-4-5", "reason_rejected": "lower score"},
            ],
            latency_ms=1234.5,
            cost_usd=0.0042,
            input_tokens=4200,
            output_tokens=150,
        )
        assert rec.selected_model == "claude-opus-4-6"
        assert len(rec.alternatives) == 1


class TestDecisionLog:
    def test_write_and_read(self, log_path):
        log = DecisionLog(log_path)
        rec = DecisionRecord(
            selected_model="claude-haiku-4-5",
            reason="test",
        )
        log.record(rec)
        assert log.count == 1
        assert log_path.exists()

        records = log.read_all()
        assert len(records) == 1
        assert records[0].selected_model == "claude-haiku-4-5"

    def test_stats(self, log_path):
        log = DecisionLog(log_path)
        log.record(DecisionRecord(
            selected_model="haiku", reason="cheap", cost_usd=0.001,
        ))
        log.record(DecisionRecord(
            selected_model="haiku", reason="cheap", cost_usd=0.002,
        ))
        log.record(DecisionRecord(
            selected_model="opus", reason="deep", cost_usd=0.05,
            success=False, error="timeout",
        ))

        s = log.stats()
        assert s["total_decisions"] == 3
        assert s["models_used"]["haiku"] == 2
        assert s["models_used"]["opus"] == 1
        assert s["failures"] == 1
        assert abs(s["total_cost_usd"] - 0.053) < 1e-6

    def test_jsonl_format(self, log_path):
        log = DecisionLog(log_path)
        log.record(DecisionRecord(
            selected_model="haiku", reason="test",
        ))
        log.record(DecisionRecord(
            selected_model="opus", reason="test2",
        ))

        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "selected_model" in parsed

    def test_concurrent_writes(self, log_path):
        log = DecisionLog(log_path)
        errors = []

        def writer(model_name, n):
            try:
                for _ in range(n):
                    log.record(DecisionRecord(
                        selected_model=model_name, reason="concurrent",
                    ))
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=writer, args=(f"model-{i}", 50))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert log.count == 200
        records = log.read_all()
        assert len(records) == 200

    def test_read_empty(self, log_path):
        log = DecisionLog(log_path)
        assert log.read_all() == []

    def test_read_nonexistent(self, tmp_path):
        log = DecisionLog(tmp_path / "nope.jsonl")
        assert log.read_all() == []

    def test_zero_cost_counted(self, log_path):
        log = DecisionLog(log_path)
        log.record(DecisionRecord(
            selected_model="haiku", reason="cached", cost_usd=0.0,
        ))
        log.record(DecisionRecord(
            selected_model="haiku", reason="real", cost_usd=0.01,
        ))
        s = log.stats()
        assert s["total_cost_usd"] == 0.01

    def test_none_cost_not_counted(self, log_path):
        log = DecisionLog(log_path)
        log.record(DecisionRecord(
            selected_model="haiku", reason="no cost data",
        ))
        s = log.stats()
        assert s["total_cost_usd"] == 0.0

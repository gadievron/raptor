"""Numeric artefact failures do not hide independent run-status evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.json import jsonl
from core.run import metadata, resume
from core.run.digest import read_run_digest, render_run_digest, render_run_status


@pytest.fixture
def exact_json_numbers(monkeypatch):
    # Bind the actual readers, including namespaces retained across imports.
    for loader in (metadata.load_json, resume.load_json, jsonl._loads):
        monkeypatch.setitem(loader.__globals__, "_orjson", None)


def _write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, allow_nan=False), encoding="utf-8")


def test_oversized_duration_keeps_other_lifecycle_fields(tmp_path, exact_json_numbers):
    _write_json(tmp_path / ".raptor-run.json", {
        "command": "agentic", "status": "failed", "duration_seconds": 10**400,
        "target_path": "/saved/target", "extra": {"error": "saved failure", "findings_count": 7},
    })
    assert metadata.load_run_metadata(tmp_path)["duration_seconds"] == 10**400

    digest = read_run_digest(tmp_path)

    assert digest.duration_seconds is None
    assert digest.target_path == "/saved/target"
    assert digest.error == "saved failure"
    assert digest.findings_total == 7
    assert "saved failure" in render_run_status(digest)
    assert "Failed" in render_run_digest(digest)
    assert "Failed" in render_run_status(digest)


def test_oversized_cap_keeps_booked_spend(tmp_path, exact_json_numbers):
    _write_json(tmp_path / "audit-run-config.json", {"max_cost_usd": 10**400})
    _write_json(tmp_path / "spend-floor.json", {"spend_usd": 3.5})
    assert resume.load_run_config(tmp_path, filename="audit-run-config.json")["max_cost_usd"] == 10**400

    digest = read_run_digest(tmp_path)

    assert digest.max_cost_usd is None
    assert digest.spend_usd == 3.5
    assert "$3.50" in render_run_status(digest)


@pytest.mark.parametrize("cost", [10**400, -(10**400)], ids=["positive", "negative"])
def test_oversized_telemetry_cost_keeps_later_events(tmp_path, exact_json_numbers, cost):
    rows = [
        {"event": "call", "call_class": "first", "cost_usd": cost},
        {"event": "attempt_failed", "disposition": "timeout", "call_class": "last",
         "cost_usd": 0.25, "ts": "2026-01-02T03:04:05+00:00"},
        {"event": "breaker_tripped"},
    ]
    path = tmp_path / "llm-telemetry.jsonl"
    path.write_text("".join(json.dumps(row, allow_nan=False) + "\n" for row in rows))
    assert jsonl.load_jsonl(path)[0]["cost_usd"] == cost

    digest = read_run_digest(tmp_path)

    assert digest.llm_calls == 1
    assert digest.llm_failed_attempts == digest.llm_timeouts == digest.breaker_trips == 1
    assert digest.last_call_class == "last"
    assert digest.last_call_ts == "2026-01-02T03:04:05+00:00"
    expected = (resume._MAX_SPEND_EVIDENCE_USD if cost > 0 else 0.0) + 0.25
    assert digest.spend_usd == expected
    json.dumps({"spend_usd": digest.spend_usd}, allow_nan=False)


def test_large_finite_telemetry_total_stays_serializable(tmp_path, exact_json_numbers):
    path = tmp_path / "llm-telemetry.jsonl"
    path.write_text('{"event":"call","cost_usd":1e308}\n' * 2)

    digest = read_run_digest(tmp_path)

    assert digest.llm_calls == 2
    assert digest.spend_usd == 2 * resume._MAX_SPEND_EVIDENCE_USD
    json.dumps({"spend_usd": digest.spend_usd}, allow_nan=False)


@pytest.mark.parametrize(("duration", "expected"), [
    (0, 0.0), (1, 1.0), (1.5, 1.5), (1e100, 1e100),
    (True, None), ("2.0", None), (None, None),
])
def test_duration_admission(tmp_path, exact_json_numbers, duration, expected):
    _write_json(tmp_path / ".raptor-run.json", {"duration_seconds": duration})
    digest = read_run_digest(tmp_path)
    assert digest.duration_seconds == expected
    render_run_status(digest)

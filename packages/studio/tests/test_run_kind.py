"""Tests for run_kind classification + lane/stage mapping."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from packages.studio.services.run_kind import (
    BINARY_STAGES,
    FORENSICS_STAGES,
    SOURCE_STAGES,
    classify,
    lane_for,
    lane_status,
    next_action,
    stages_for,
)


@pytest.mark.parametrize("command,expected", [
    ("raptor agentic /path",                       "agentic"),
    ("raptor scan --repo .",                       "scan"),
    ("python raptor_codeql.py --repo x",           "codeql"),
    ("/validate",                                   "validate"),
    ("python raptor_fuzzing.py --binary x",         "fuzz"),
    ("/crash-analysis url",                         "crash-analysis"),
    ("/oss-forensics https://...",                  "oss-forensics"),
    ("/understand --map",                           "understand"),
    ("/exploit",                                    "exploit"),
    ("/patch",                                      "patch"),
    ("/analyze --sarif x.sarif",                    "analyze"),
    ("/web --url x",                                "web"),
    ("something random",                            "other"),
    ("",                                            "other"),
])
def test_classify(command: str, expected: str):
    assert classify(command) == expected


def test_classify_crash_analysis_before_analysis():
    # 'crash-analysis' must win over 'analyze'/'analysis' substring.
    assert classify("raptor crash-analysis url") == "crash-analysis"


def test_classify_falls_back_to_dirname():
    assert classify("", "fuzz_mybinary_20260423_120000") == "fuzz"


def test_lane_for():
    assert lane_for("scan") == "source"
    assert lane_for("codeql") == "source"
    assert lane_for("fuzz") == "binary"
    assert lane_for("crash-analysis") == "binary"
    assert lane_for("oss-forensics") == "forensics"
    assert lane_for("exploit") == "artifacts"
    assert lane_for("nonsense") == "other"


def test_stages_for_agentic_is_multi_stage():
    # /agentic is the all-in-one; it satisfies both scan and validate.
    assert stages_for("agentic") == ("scan", "validate")


def test_stages_for_codeql_counts_as_scan():
    assert stages_for("codeql") == ("scan",)


@dataclass
class _FakeRun:
    kind: str
    status: str = "completed"


def test_lane_status_empty():
    status = lane_status([])
    for stage in SOURCE_STAGES:
        assert status["source"][stage]["status"] == "pending"
    for stage in BINARY_STAGES:
        assert status["binary"][stage]["status"] == "pending"
    for stage in FORENSICS_STAGES:
        assert status["forensics"][stage]["status"] == "pending"


def test_lane_status_agentic_marks_both_scan_and_validate():
    status = lane_status([_FakeRun("agentic")])
    assert status["source"]["scan"]["status"] == "complete"
    assert status["source"]["validate"]["status"] == "complete"
    assert status["source"]["understand"]["status"] == "pending"


def test_lane_status_running_is_partial():
    status = lane_status([_FakeRun("scan", status="running")])
    assert status["source"]["scan"]["status"] == "partial"


def test_lane_status_failed_with_no_completed_marks_failed():
    status = lane_status([_FakeRun("fuzz", status="failed")])
    assert status["binary"]["fuzz"]["status"] == "failed"


def test_lane_status_completed_trumps_failed():
    status = lane_status([
        _FakeRun("scan", status="failed"),
        _FakeRun("scan", status="completed"),
    ])
    assert status["source"]["scan"]["status"] == "complete"


def test_next_action_suggests_first_pending():
    na = next_action([])
    assert na is not None
    assert na["stage"] == "understand"


def test_next_action_after_understand():
    na = next_action([_FakeRun("understand")])
    assert na is not None
    assert na["stage"] == "scan"


def test_next_action_returns_none_when_full_source_pipeline_done():
    na = next_action([
        _FakeRun("understand"),
        _FakeRun("agentic"),  # covers scan + validate
    ])
    assert na is None

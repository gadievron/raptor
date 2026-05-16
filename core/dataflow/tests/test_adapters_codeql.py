"""Tests for ``core.dataflow.adapters.codeql``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import pytest

from core.dataflow import Finding, Step
from core.dataflow.adapters.codeql import (
    PRODUCER,
    from_dataflow_path,
    from_sarif_result,
    make_finding_id,
)


# ---------------------------------------------------------------------
# SARIF fixtures
# ---------------------------------------------------------------------


def _sarif_step(uri: str, line: int, column: int, snippet: str, message: str) -> dict:
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {
                    "startLine": line,
                    "startColumn": column,
                    "snippet": {"text": snippet},
                },
            },
            "message": {"text": message},
        }
    }


def _sarif_result(*locations) -> dict:
    return {
        "ruleId": "py/sql-injection",
        "message": {"text": "user-controlled value reaches SQL"},
        "codeFlows": [{"threadFlows": [{"locations": list(locations)}]}],
    }


def _minimal_sarif() -> dict:
    return _sarif_result(
        _sarif_step("app/handler.py", 12, 4, "q = request.GET['q']", "source"),
        _sarif_step("app/db.py", 27, 8, "cursor.execute(sql)", "sink"),
    )


# ---------------------------------------------------------------------
# Duck-typed DataflowPath
# ---------------------------------------------------------------------


@dataclass
class _FakeDpStep:
    file_path: str
    line: int
    column: int
    snippet: str
    label: str


@dataclass
class _FakeDp:
    source: _FakeDpStep
    sink: _FakeDpStep
    intermediate_steps: List[_FakeDpStep]
    sanitizers: List[str]
    rule_id: str
    message: str


def _fake_dp() -> _FakeDp:
    return _FakeDp(
        source=_FakeDpStep("a/h.py", 12, 4, "q = req['q']", "source"),
        sink=_FakeDpStep("a/db.py", 27, 8, "cursor.execute(sql)", "sink"),
        intermediate_steps=[
            _FakeDpStep("a/h.py", 14, 4, "sql = f'SELECT ... {q}'", "step"),
        ],
        sanitizers=["validate_query"],
        rule_id="py/sql-injection",
        message="user input reaches SQL",
    )


# ---------------------------------------------------------------------
# make_finding_id
# ---------------------------------------------------------------------


def test_make_finding_id_is_deterministic():
    a = Step(file_path="x.py", line=1, column=0, snippet="s")
    b = Step(file_path="y.py", line=2, column=0, snippet="t")
    assert make_finding_id("py/inj", a, b) == make_finding_id("py/inj", a, b)


def test_make_finding_id_distinguishes_rule():
    a = Step(file_path="x.py", line=1, column=0, snippet="s")
    b = Step(file_path="y.py", line=2, column=0, snippet="t")
    assert make_finding_id("py/inj", a, b) != make_finding_id("py/xss", a, b)


def test_make_finding_id_distinguishes_producer():
    a = Step(file_path="x.py", line=1, column=0, snippet="s")
    b = Step(file_path="y.py", line=2, column=0, snippet="t")
    cq = make_finding_id("rule", a, b, producer="codeql")
    sg = make_finding_id("rule", a, b, producer="semgrep")
    assert cq.startswith("codeql_")
    assert sg.startswith("semgrep_")
    assert cq != sg


def test_make_finding_id_distinguishes_locations():
    a = Step(file_path="x.py", line=1, column=0, snippet="s")
    b = Step(file_path="y.py", line=2, column=0, snippet="t")
    c = Step(file_path="y.py", line=99, column=0, snippet="t")
    assert make_finding_id("rule", a, b) != make_finding_id("rule", a, c)


def test_make_finding_id_handles_empty_rule_id():
    a = Step(file_path="x.py", line=1, column=0, snippet="s")
    b = Step(file_path="y.py", line=2, column=0, snippet="t")
    fid = make_finding_id("", a, b)
    assert "unknown" in fid


# ---------------------------------------------------------------------
# from_sarif_result
# ---------------------------------------------------------------------


def test_from_sarif_extracts_minimal_dataflow():
    finding = from_sarif_result(_minimal_sarif())
    assert finding is not None
    assert finding.producer == PRODUCER
    assert finding.rule_id == "py/sql-injection"
    assert finding.source.file_path == "app/handler.py"
    assert finding.source.line == 12
    assert finding.source.label == "source"
    assert finding.sink.file_path == "app/db.py"
    assert finding.sink.line == 27
    assert finding.sink.label == "sink"
    assert finding.intermediate_steps == ()


def test_from_sarif_extracts_intermediate_steps():
    sarif = _sarif_result(
        _sarif_step("a.py", 1, 0, "src", "source"),
        _sarif_step("a.py", 5, 0, "mid1", "step1"),
        _sarif_step("a.py", 7, 0, "mid2", "step2"),
        _sarif_step("b.py", 10, 0, "snk", "sink"),
    )
    finding = from_sarif_result(sarif)
    assert finding is not None
    assert len(finding.intermediate_steps) == 2
    assert finding.intermediate_steps[0].snippet == "mid1"
    assert finding.intermediate_steps[1].snippet == "mid2"


def test_from_sarif_returns_none_when_not_a_dataflow():
    assert from_sarif_result({"ruleId": "x", "message": {"text": "y"}}) is None


def test_from_sarif_returns_none_when_codeflows_empty():
    assert from_sarif_result({"ruleId": "x", "codeFlows": []}) is None


def test_from_sarif_returns_none_when_threadflows_empty():
    result = {"ruleId": "x", "codeFlows": [{"threadFlows": []}]}
    assert from_sarif_result(result) is None


def test_from_sarif_returns_none_when_fewer_than_two_locations():
    result = _sarif_result(_sarif_step("a.py", 1, 0, "src", "source"))
    assert from_sarif_result(result) is None


def test_from_sarif_preserves_full_result_in_raw():
    sarif = _minimal_sarif()
    sarif["extra_codeql_field"] = {"key": "value"}
    finding = from_sarif_result(sarif)
    assert finding is not None
    assert finding.raw["extra_codeql_field"] == {"key": "value"}
    assert finding.raw["ruleId"] == "py/sql-injection"


def test_from_sarif_generates_stable_id_when_not_supplied():
    finding_a = from_sarif_result(_minimal_sarif())
    finding_b = from_sarif_result(_minimal_sarif())
    assert finding_a is not None and finding_b is not None
    assert finding_a.finding_id == finding_b.finding_id
    assert finding_a.finding_id.startswith("codeql_py-sql-injection_")


def test_from_sarif_explicit_finding_id_overrides_generated():
    finding = from_sarif_result(_minimal_sarif(), finding_id="my_custom_id")
    assert finding is not None
    assert finding.finding_id == "my_custom_id"


def test_make_finding_id_collides_on_same_endpoints_with_different_intermediate():
    """Documented limitation: ``make_finding_id`` hashes
    ``(producer, rule_id, source loc, sink loc)`` only. Two findings
    that share endpoints but follow different intermediate paths
    collapse to the same id. CodeQL can surface multiple such flows
    for the same source/sink — when that matters, callers must pass
    an explicit ``finding_id`` (e.g. derived from SARIF's
    ``partialFingerprints``)."""
    sarif_path_a = _sarif_result(
        _sarif_step("a.py", 1, 0, "src", "source"),
        _sarif_step("a.py", 5, 0, "via_X", "step"),
        _sarif_step("b.py", 9, 0, "snk", "sink"),
    )
    sarif_path_b = _sarif_result(
        _sarif_step("a.py", 1, 0, "src", "source"),
        _sarif_step("a.py", 7, 0, "via_Y", "step"),
        _sarif_step("b.py", 9, 0, "snk", "sink"),
    )
    a = from_sarif_result(sarif_path_a)
    b = from_sarif_result(sarif_path_b)
    assert a is not None and b is not None
    assert a.finding_id == b.finding_id, (
        "endpoints identical → id identical; intermediate steps don't "
        "participate in the hash. See docstring."
    )


def test_from_sarif_propagates_step_validation_error_on_empty_uri():
    sarif = _sarif_result(
        _sarif_step("", 1, 0, "src", "source"),
        _sarif_step("b.py", 2, 0, "snk", "sink"),
    )
    with pytest.raises(ValueError, match="file_path"):
        from_sarif_result(sarif)


def test_from_sarif_propagates_step_validation_error_on_zero_line():
    sarif = _sarif_result(
        _sarif_step("a.py", 0, 0, "src", "source"),
        _sarif_step("b.py", 2, 0, "snk", "sink"),
    )
    with pytest.raises(ValueError, match="line"):
        from_sarif_result(sarif)


def test_from_sarif_handles_missing_message_text():
    sarif = _minimal_sarif()
    del sarif["message"]
    finding = from_sarif_result(sarif)
    assert finding is not None
    assert finding.message == "(no message)"


def test_from_sarif_handles_missing_rule_id():
    sarif = _minimal_sarif()
    del sarif["ruleId"]
    finding = from_sarif_result(sarif)
    assert finding is not None
    assert finding.rule_id == "unknown"


def test_from_sarif_handles_empty_step_message_label():
    sarif = _sarif_result(
        _sarif_step("a.py", 1, 0, "src", ""),
        _sarif_step("b.py", 2, 0, "snk", ""),
    )
    finding = from_sarif_result(sarif)
    assert finding is not None
    assert finding.source.label is None
    assert finding.sink.label is None


# ---------------------------------------------------------------------
# from_dataflow_path
# ---------------------------------------------------------------------


def test_from_dataflow_path_basic():
    finding = from_dataflow_path(_fake_dp())
    assert finding.producer == PRODUCER
    assert finding.rule_id == "py/sql-injection"
    assert finding.source.file_path == "a/h.py"
    assert finding.sink.file_path == "a/db.py"
    assert len(finding.intermediate_steps) == 1


def test_from_dataflow_path_preserves_sanitizers_in_raw():
    finding = from_dataflow_path(_fake_dp())
    assert finding.raw["dataflow_path_sanitizers"] == ["validate_query"]


def test_from_dataflow_path_omits_sanitizers_when_empty():
    dp = _fake_dp()
    dp.sanitizers = []
    finding = from_dataflow_path(dp)
    assert "dataflow_path_sanitizers" not in finding.raw


def test_from_dataflow_path_generates_stable_id():
    a = from_dataflow_path(_fake_dp())
    b = from_dataflow_path(_fake_dp())
    assert a.finding_id == b.finding_id


def test_from_dataflow_path_explicit_id_overrides():
    finding = from_dataflow_path(_fake_dp(), finding_id="custom")
    assert finding.finding_id == "custom"


def test_from_dataflow_path_and_sarif_produce_same_id_for_same_locations():
    """Same source/sink locations + same rule_id → same finding_id
    whether constructed from SARIF or from an in-memory DataflowPath.
    Critical for corpus replay: a label written against one form
    matches the other."""
    sarif = _sarif_result(
        _sarif_step("a/h.py", 12, 4, "q = req['q']", "source"),
        _sarif_step("a/db.py", 27, 8, "cursor.execute(sql)", "sink"),
    )
    sarif_finding = from_sarif_result(sarif)
    dp_finding = from_dataflow_path(_fake_dp())
    assert sarif_finding is not None
    assert sarif_finding.finding_id == dp_finding.finding_id

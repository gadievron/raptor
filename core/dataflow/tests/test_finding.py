"""Round-trip and validation tests for ``core.dataflow.Finding``."""

from __future__ import annotations

import json

import pytest

from core.dataflow import SCHEMA_VERSION, Finding, Step


def _step(label: str = "step", line: int = 10) -> Step:
    return Step(
        file_path="app/handler.py",
        line=line,
        column=4,
        snippet="x = process(req.params['q'])",
        label=label,
    )


def _finding() -> Finding:
    return Finding(
        finding_id="codeql:py/sql-injection:app/handler.py:10:app/db.py:42",
        producer="codeql",
        rule_id="py/sql-injection",
        message="user-controlled value reaches SQL execution",
        source=_step("source", line=8),
        sink=Step(
            file_path="app/db.py",
            line=42,
            column=8,
            snippet="cursor.execute(sql)",
            label="sink",
        ),
        intermediate_steps=[_step("step", line=10), _step("step", line=20)],
        raw={"sarif": {"ruleIndex": 3}, "kind": "result"},
    )


def test_step_roundtrip_preserves_all_fields():
    step = _step("source")
    assert Step.from_dict(step.to_dict()) == step


def test_step_label_is_optional_and_round_trips_none():
    step = Step(file_path="x.py", line=1, column=0, snippet="y = 1", label=None)
    restored = Step.from_dict(step.to_dict())
    assert restored == step
    assert restored.label is None


def test_step_rejects_empty_file_path():
    with pytest.raises(ValueError, match="file_path"):
        Step(file_path="", line=1, column=0, snippet="y = 1")


def test_step_rejects_zero_line():
    with pytest.raises(ValueError, match="line"):
        Step(file_path="x.py", line=0, column=0, snippet="y = 1")


def test_step_rejects_negative_column():
    with pytest.raises(ValueError, match="column"):
        Step(file_path="x.py", line=1, column=-1, snippet="y = 1")


def test_step_from_dict_rejects_unknown_fields():
    blob = _step().to_dict()
    blob["mystery_field"] = "boo"
    with pytest.raises(ValueError, match="unknown fields"):
        Step.from_dict(blob)


def test_finding_roundtrip_preserves_intermediate_steps_and_raw():
    finding = _finding()
    assert Finding.from_dict(finding.to_dict()) == finding


def test_finding_json_roundtrip():
    finding = _finding()
    assert Finding.from_json(finding.to_json()) == finding


def test_finding_to_dict_records_schema_version():
    assert _finding().to_dict()["schema_version"] == SCHEMA_VERSION


def test_finding_from_dict_rejects_mismatched_schema_version():
    blob = _finding().to_dict()
    blob["schema_version"] = SCHEMA_VERSION + 1
    with pytest.raises(ValueError, match="schema_version"):
        Finding.from_dict(blob)


def test_finding_from_dict_rejects_missing_schema_version():
    blob = _finding().to_dict()
    del blob["schema_version"]
    with pytest.raises(KeyError):
        Finding.from_dict(blob)


def test_finding_from_dict_rejects_unknown_fields():
    blob = _finding().to_dict()
    blob["bogus"] = 1
    with pytest.raises(ValueError, match="unknown fields"):
        Finding.from_dict(blob)


def test_finding_defaults_intermediate_steps_to_empty_tuple_and_raw_to_empty_dict():
    finding = Finding(
        finding_id="x",
        producer="semgrep",
        rule_id="rule.id",
        message="msg",
        source=_step("source"),
        sink=_step("sink"),
    )
    assert finding.intermediate_steps == ()
    assert isinstance(finding.intermediate_steps, tuple)
    assert finding.raw == {}


def test_finding_from_dict_handles_missing_intermediate_steps_and_raw():
    blob = {
        "schema_version": SCHEMA_VERSION,
        "finding_id": "x",
        "producer": "semgrep",
        "rule_id": "rule.id",
        "message": "msg",
        "source": _step("source").to_dict(),
        "sink": _step("sink").to_dict(),
    }
    restored = Finding.from_dict(blob)
    assert restored.intermediate_steps == ()
    assert restored.raw == {}


def test_finding_intermediate_steps_coerced_to_tuple_from_list():
    finding = Finding(
        finding_id="x",
        producer="semgrep",
        rule_id="r",
        message="m",
        source=_step("source"),
        sink=_step("sink"),
        intermediate_steps=[_step("step", line=11), _step("step", line=12)],
    )
    assert isinstance(finding.intermediate_steps, tuple)
    assert len(finding.intermediate_steps) == 2


def test_finding_intermediate_steps_must_contain_step_instances():
    with pytest.raises(TypeError, match="Step"):
        Finding(
            finding_id="x",
            producer="semgrep",
            rule_id="r",
            message="m",
            source=_step("source"),
            sink=_step("sink"),
            intermediate_steps=({"file_path": "x"},),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("field_name", ["finding_id", "producer", "rule_id", "message"])
def test_finding_rejects_empty_required_string(field_name: str):
    kwargs = dict(
        finding_id="x",
        producer="semgrep",
        rule_id="r",
        message="m",
        source=_step("source"),
        sink=_step("sink"),
    )
    kwargs[field_name] = ""
    with pytest.raises(ValueError, match=field_name):
        Finding(**kwargs)


def test_finding_to_json_emits_valid_json():
    text = _finding().to_json()
    parsed = json.loads(text)
    assert parsed["producer"] == "codeql"
    assert parsed["intermediate_steps"][0]["label"] == "step"

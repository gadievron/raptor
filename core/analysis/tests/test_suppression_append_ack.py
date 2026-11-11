"""Best-effort suppression writes expose completion without implying durability."""
import json

import pytest

from core.analysis.reach_chokepoint import record_suppression


def test_complete_native_append_acknowledges_without_changing_record_schema(tmp_path):
    trail = tmp_path / "suppressions.jsonl"
    prior = b'{"finding_id":"prior"}\n'
    trail.write_bytes(prior)
    ack = record_suppression(tmp_path, finding={"finding_id": "current", "file": "unit.c"},
                             verdict="record-only", reason="owned fixture", dropped=False)
    assert ack is True
    assert trail.read_bytes().startswith(prior)
    row = json.loads(trail.read_bytes()[len(prior):])
    assert row == {"finding_id": "current", "rule_id": "", "file_path": "unit.c",
                   "line": None, "function": "", "verdict": "record-only",
                   "reason": "owned fixture", "dropped": False}


def test_native_output_directory_failure_is_explicit_false(tmp_path):
    output = tmp_path / "owned-file"
    output.write_bytes(b"preserved")
    assert record_suppression(output, finding={"finding_id": "current"},
                              verdict="record-only", reason="fixture") is False
    assert output.read_bytes() == b"preserved"


@pytest.mark.parametrize("bad", [object(), float("nan")])
def test_serialisation_failure_remains_best_effort_and_never_acknowledges(tmp_path, bad):
    assert record_suppression(tmp_path, finding={"finding_id": "current"},
                              verdict="record-only", reason="fixture", extra={"bad": bad}) is False
    assert not (tmp_path / "suppressions.jsonl").exists()

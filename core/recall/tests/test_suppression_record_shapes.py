"""Non-object JSONL values remain visible to enforcement review."""
import json

import pytest

from core.recall.verify_enforced import verify_enforced_paths
from core.recall.warm import load_suppression_records


@pytest.mark.parametrize("value", [None, [], [1], True, 7, "owned"])
def test_non_object_record_requires_review(tmp_path, value):
    path = tmp_path / "owned.jsonl"
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    before = path.read_bytes()
    result = verify_enforced_paths(path, [])
    assert result["records_malformed"] == 1
    assert not result["clean"]
    assert path.read_bytes() == before


def test_non_object_does_not_discard_healthy_neighbor(tmp_path):
    path = tmp_path / "owned.jsonl"
    row = {"file_path": "owned.c", "line": 10,
           "verdict": "sanitizer_dominated"}
    path.write_text(json.dumps([]) + "\n" + json.dumps(row) + "\n")
    assert load_suppression_records(path) == [{"_malformed": True}, row]


def test_blank_lines_remain_ignored_and_objects_remain_intact(tmp_path):
    path = tmp_path / "owned.jsonl"
    row = {"verdict": "owned-future", "payload": [1, None]}
    path.write_text("\n  \n" + json.dumps(row) + "\n")
    assert load_suppression_records(path) == [row]

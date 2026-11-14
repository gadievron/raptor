"""Inspection tolerates malformed container shapes without rewriting evidence."""
import json

import pytest

from core.analysis.reach_verdict_log import summarize


@pytest.mark.parametrize("languages", [["python"], "python", 1, True])
def test_malformed_language_container_is_unreadable(tmp_path, languages):
    path = tmp_path / "verdicts.json"
    data = json.dumps({"version": 1, "languages": languages})
    path.write_text(data)
    assert summarize(path) == {}
    assert path.read_text() == data


@pytest.mark.parametrize("verdicts", [[1], "reachable", 1, True])
def test_malformed_verdict_container_preserves_healthy_language(tmp_path, verdicts):
    path = tmp_path / "verdicts.json"
    data = json.dumps({"version": 1, "languages": {
        "bad": {"verdicts": verdicts},
        "python": {"verdicts": {"reachable": 3}},
    }})
    path.write_text(data)
    assert summarize(path) == {"python": {"reachable": 3}}
    assert path.read_text() == data


def test_empty_and_nonobject_slots_keep_existing_behavior(tmp_path):
    path = tmp_path / "verdicts.json"
    path.write_text(json.dumps({"version": 1, "languages": {
        "empty": {}, "null": {"verdicts": None}, "nonobject": [],
    }}))
    assert summarize(path) == {"empty": {}, "null": {}}

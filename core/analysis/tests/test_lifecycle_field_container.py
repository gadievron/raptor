"""Malformed state-field collections cannot abort lifecycle loading."""
import json

import pytest

from core.analysis.lifecycle_context_map import load_state_fields


@pytest.mark.parametrize("fields", [None, True, 1, 1.5])
def test_noniterable_field_collection_is_unreadable(tmp_path, fields):
    path = tmp_path / "context-map.json"
    data = json.dumps({"state_fields": fields, "sources": []})
    path.write_text(data)
    assert load_state_fields(tmp_path) == []
    assert path.read_text() == data


def test_valid_field_survives_malformed_neighbors(tmp_path):
    path = tmp_path / "context-map.json"
    path.write_text(json.dumps({"state_fields": [
        None, {"bad": "entry"},
        {"name": "ready", "struct_type": "Owned", "invariant": "required"},
    ]}))
    fields = load_state_fields(tmp_path)
    assert len(fields) == 1
    assert fields[0].name == "ready"

"""Tests for core.analysis.lifecycle_context_map — context-map.json integration."""

from __future__ import annotations

import json

from core.analysis.lifecycle_context_map import (
    load_state_fields,
    merge_state_fields,
    save_state_fields,
)
from core.analysis.lifecycle_model import Guard, ReadSite, StateField, WriteSite


def _field(name: str = "dumpable", struct: str = "task_struct") -> StateField:
    return StateField(
        name=name, struct_type=struct,
        invariant=f"{name} requires guard",
        write_sites=[
            WriteSite(
                file="a.c", line=1, function="f",
                guards=frozenset({Guard(condition="mm", file="a.c", line=1)}),
            ),
        ],
        read_sites=[
            ReadSite(file="b.c", line=2, function="g", guards=frozenset()),
        ],
    )


class TestSaveAndLoad:
    def test_round_trip(self, tmp_path):
        field = _field()
        save_state_fields(tmp_path, [field])

        loaded = load_state_fields(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].name == "dumpable"
        assert loaded[0].struct_type == "task_struct"
        assert len(loaded[0].write_sites) == 1
        assert len(loaded[0].read_sites) == 1

    def test_merges_with_existing_context_map(self, tmp_path):
        cm_path = tmp_path / "context-map.json"
        cm_path.write_text(json.dumps({
            "sources": [{"type": "http_route"}],
            "entry_points": [],
        }))

        save_state_fields(tmp_path, [_field()])

        data = json.loads(cm_path.read_text())
        assert "sources" in data
        assert "state_fields" in data
        assert len(data["state_fields"]) == 1

    def test_no_context_map(self, tmp_path):
        assert load_state_fields(tmp_path) == []

    def test_malformed_field_skipped(self, tmp_path):
        cm_path = tmp_path / "context-map.json"
        cm_path.write_text(json.dumps({
            "state_fields": [
                {"name": "good", "struct_type": "S", "invariant": "ok"},
                {"bad": "entry"},
            ],
        }))
        loaded = load_state_fields(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].name == "good"


class TestMerge:
    def test_dedup_by_name_and_struct(self):
        a = _field("x", "S")
        b = _field("x", "S")
        c = _field("y", "S")
        merged = merge_state_fields([a], [b, c])
        assert len(merged) == 2
        names = {f.name for f in merged}
        assert names == {"x", "y"}

    def test_different_struct_not_deduped(self):
        a = _field("x", "S1")
        b = _field("x", "S2")
        merged = merge_state_fields([a], [b])
        assert len(merged) == 2

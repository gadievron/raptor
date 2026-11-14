"""Malformed record shapes cannot hide later owned JSONL records."""
import json

import pytest

from core.dataflow import sanitizer_cut_parity as parity


@pytest.mark.parametrize("malformed", [None, [], [1], "text", 7, True])
def test_non_object_line_keeps_surrounding_records(tmp_path, monkeypatch, malformed):
    def forbidden(*args, **kwargs):
        raise AssertionError("reader-only qualification")

    for name in ("aggregate_parity", "render_parity_report", "parity_criterion_met"):
        monkeypatch.setattr(parity, name, forbidden)
    source = tmp_path / "owned-shapes.jsonl"
    values = [{"finding_id": "before", "lexical_suppressed": False},
              malformed,
              {"finding_id": "after", "lexical_suppressed": False}]
    payload = "".join(json.dumps(value) + "\n" for value in values)
    source.write_text(payload, encoding="utf-8")
    records = parity.read_parity_records(source)
    assert [record.finding_id for record in records] == ["before", "after"]
    assert source.read_text(encoding="utf-8") == payload

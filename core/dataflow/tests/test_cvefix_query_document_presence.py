"""An absent query-run document cannot establish a zero measurement."""
import json

import pytest

from core.dataflow import cvefix_walk as walk


@pytest.mark.parametrize("document,expected", [
    ({}, None),
    ({"version": "2.1.0"}, None),
    ({"unrelated": []}, None),
    ({"runs": []}, 0),
    ({"runs": [{"results": []}]}, 0),
], ids=["empty-object", "metadata-only", "unrelated-object", "explicit-empty-runs", "completed-empty-run"])
def test_query_count_requires_run_field(tmp_path, monkeypatch, document, expected):
    output = tmp_path / "query.sarif"
    called = []

    def recorded_run(argv, timeout):
        called.append(argv)
        output.write_text(json.dumps(document))
        return True

    monkeypatch.setattr(walk, "_run", recorded_run)
    result = walk._count_query(tmp_path / "db", "owned-query", output, "not-executed", 1)
    assert len(called) == 1
    assert result == expected

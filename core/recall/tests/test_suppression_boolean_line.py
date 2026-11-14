"""JSON booleans cannot place a suppression at a source line."""
import json

import pytest

from core.recall.verify_enforced import verify_enforced
from core.recall.warm import apply_would_suppress, load_suppression_records


def entry(line):
    return {"id": "owned-label", "file": "owned.c", "cwe": "CWE-79",
            "line_start": line, "line_end": line}


def loaded(tmp_path, line):
    path = tmp_path / "owned.jsonl"
    row = {"file_path": "owned.c", "line": line,
           "verdict": "sanitizer_dominated", "cwe": "CWE-79"}
    path.write_text(json.dumps(row) + "\n")
    return load_suppression_records(path)


@pytest.mark.parametrize("line", [True, False])
def test_boolean_line_requires_null_line_review(tmp_path, line):
    records = loaded(tmp_path, line)
    result = verify_enforced(records, [entry(100)], line_drift=0)
    assert not result["clean"]
    assert result["by_proximity"]["null_line"] == 1


@pytest.mark.parametrize("line", [True, False])
def test_boolean_line_keeps_opposite_damage_and_fp_conservatism(tmp_path, line):
    records = loaded(tmp_path, line)
    result = apply_would_suppress({"clean_region_fps": [entry(1)]}, records,
                                  matched_expected=[entry(100)], line_drift=0)
    assert result["would_suppress_fps"] == 0
    assert result["true_finding_damage_count"] == 1
    assert result["true_finding_would_suppress"][0]["null_line"] is True


@pytest.mark.parametrize("line", [1, 100])
def test_integer_lines_remain_placed(tmp_path, line):
    records = loaded(tmp_path, line)
    result = verify_enforced(records, [entry(100)], line_drift=0)
    assert result["clean"] is (line == 1)
    warm = apply_would_suppress({"clean_region_fps": [entry(1)]}, records,
                                matched_expected=[entry(100)], line_drift=0)
    assert warm["would_suppress_fps"] == int(line == 1)
    assert warm["true_finding_damage_count"] == int(line == 100)
    if line == 100:
        assert warm["true_finding_would_suppress"][0]["null_line"] is False

"""Review ordering must retain unplaced records without comparing JSON types."""
import json

import pytest

from core.recall.verify_enforced import verify_enforced_paths


def write_records(tmp_path, lines):
    path = tmp_path / "owned.jsonl"
    records = [{"file_path": "owned.c", "line": line,
                "verdict": "sanitizer_dominated", "reason": str(i)}
               for i, line in enumerate(lines)]
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return path


@pytest.mark.parametrize("line", ["unknown", [1], {"line": 1}, 1.5])
@pytest.mark.parametrize("file_level", [False, True])
def test_unplaced_records_sort_without_losing_raw_values(tmp_path, line, file_level):
    path = write_records(tmp_path, [line, None])
    before = path.read_bytes()
    entry = {"id": "owned", "file": "owned.c", "cwe": "CWE-79",
             "line_start": None if file_level else 100, "line_end": None}
    result = verify_enforced_paths(path, [entry], line_drift=0)
    assert not result["clean"]
    assert result["flagged"] == 2
    assert [r["record_line"] for r in result["reviews"]] == [line, None]
    assert [r["reason"] for r in result["reviews"]] == ["0", "1"]
    assert result["by_proximity"]["on_expected" if file_level else "null_line"] == 2
    assert path.read_bytes() == before


def test_actual_integer_lines_keep_numeric_order(tmp_path):
    path = write_records(tmp_path, [103, 101, 102])
    entry = {"id": "owned", "file": "owned.c", "line_start": 100, "line_end": 110}
    result = verify_enforced_paths(path, [entry], line_drift=0)
    assert [r["record_line"] for r in result["reviews"]] == [101, 102, 103]

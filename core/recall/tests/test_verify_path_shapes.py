"""Non-string suppression locations cannot establish a clean review."""
import json

import pytest

from core.recall.verify_enforced import verify_enforced_paths


def review(tmp_path, path_value, *, verdict="sanitizer_dominated", include=False):
    path = tmp_path / "owned.jsonl"
    row = {"file_path": path_value, "line": 100, "verdict": verdict}
    path.write_text(json.dumps(row) + "\n")
    return verify_enforced_paths(path, [{"id": "owned", "file": "owned.c",
                                        "line_start": 100, "line_end": 100}],
                                 include_candidates=include)


@pytest.mark.parametrize("value", [["owned.c"], {"file": "owned.c"}, True, 7, 1.5])
def test_non_string_location_is_counted_as_unlocatable(tmp_path, value):
    result = review(tmp_path, value)
    assert result["records_reviewed"] == 1
    assert result["records_unlocatable"] == 1
    assert not result["clean"]


def test_valid_other_file_remains_clean(tmp_path):
    result = review(tmp_path, "other.c")
    assert result["clean"]
    assert result["records_unlocatable"] == 0


def test_candidate_scope_is_unchanged(tmp_path):
    result = review(tmp_path, ["owned.c"], verdict="sanitizer_candidate")
    assert result["clean"] and result["records_reviewed"] == 0
    included = review(tmp_path, ["owned.c"], verdict="sanitizer_candidate", include=True)
    assert not included["clean"] and included["records_unlocatable"] == 1

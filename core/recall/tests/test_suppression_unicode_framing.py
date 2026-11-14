"""JSON string content must not become a JSONL record boundary."""
import json

import pytest

from core.recall.warm import load_suppression_records


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"],
                         ids=["next-line", "line-separator", "paragraph-separator"])
def test_raw_unicode_separator_stays_inside_record(tmp_path, separator):
    path = tmp_path / "owned.jsonl"
    rows = [{"file_path": "owned.c", "reason": "before" + separator + "after"},
            {"file_path": "neighbor.c", "reason": "healthy"}]
    payload = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
    path.write_bytes(payload.encode("utf-8"))
    before = path.read_bytes()
    assert load_suppression_records(path) == rows
    assert path.read_bytes() == before


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_physical_record_separators_and_blanks_still_work(tmp_path, newline):
    path = tmp_path / "owned.jsonl"
    row = {"reason": "escaped\nnewline", "file_path": "owned.c"}
    path.write_bytes((newline + json.dumps(row) + newline + " " + newline).encode())
    assert load_suppression_records(path) == [row]

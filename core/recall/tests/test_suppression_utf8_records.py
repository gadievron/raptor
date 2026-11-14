"""UTF-8 damage is a malformed record, not loss of the entire trail."""
import json

import pytest

from core.recall.warm import load_suppression_records
from core.recall.verify_enforced import verify_enforced_paths


@pytest.mark.parametrize("bad", [b'\xff', b'{"reason":"\xff"}', b'{"reason":"\xe2\x82"}'],
                         ids=["invalid-byte", "quoted-invalid-byte", "incomplete-sequence"])
def test_damaged_utf8_record_keeps_healthy_neighbors(tmp_path, bad):
    path = tmp_path / "owned.jsonl"
    good = {"file_path": "other.c", "line": 1, "verdict": "sanitizer_dominated"}
    encoded = json.dumps(good).encode()
    path.write_bytes(encoded + b"\n" + bad + b"\n" + encoded + b"\n")
    before = path.read_bytes()
    assert load_suppression_records(path) == [good, {"_malformed": True}, good]
    result = verify_enforced_paths(path, [])
    assert result["records_reviewed"] == 2
    assert result["records_malformed"] == 1
    assert not result["clean"]
    assert path.read_bytes() == before


def test_valid_escaped_surrogate_keeps_existing_json_behavior(tmp_path):
    path = tmp_path / "owned.jsonl"
    path.write_bytes(b'{"reason":"\\udcff"}\n')
    assert load_suppression_records(path) == [{"reason": "\udcff"}]

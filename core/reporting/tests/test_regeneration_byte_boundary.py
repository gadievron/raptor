"""Offline regeneration distinguishes input and completed export byte limits."""
import hashlib

import pytest

from core.reporting.document import MAX_JSON_BYTES, ReportDocument, encode
from core.reporting.writer import load_document, regenerate


@pytest.mark.parametrize("output_overflows", [False, True])
def test_saved_json_regeneration_at_production_byte_boundary(tmp_path, output_overflows):
    document = ReportDocument("Saved boundary", "fixture", "captured", metadata={"payload": ""})
    input_size = MAX_JSON_BYTES if output_overflows else MAX_JSON_BYTES - 1
    document.metadata["payload"] = "x" * (input_size - len(encode(document.to_dict())))
    raw = encode(document.to_dict())
    assert len(raw) == input_size
    source = tmp_path / "saved.json"
    source.write_bytes(raw)
    before = hashlib.sha256(raw).hexdigest()
    destination = tmp_path / "export.json"
    destination.write_bytes(b"previous export")

    # Both files are valid saved documents at the real input-admission limit.
    restored = load_document(source)
    assert len(restored.metadata["payload"]) == len(document.metadata["payload"])
    if output_overflows:
        with pytest.raises(ValueError, match="Rendered report exceeds"):
            regenerate(source, destination, format="json")
        assert destination.read_bytes() == b"previous export"
    else:
        assert regenerate(source, destination, format="json") == []
        exported = destination.read_bytes()
        assert len(exported) == MAX_JSON_BYTES
        assert hashlib.sha256(exported).hexdigest() == hashlib.sha256(raw + b"\n").hexdigest()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before

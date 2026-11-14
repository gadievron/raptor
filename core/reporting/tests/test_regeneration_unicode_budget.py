"""Canonical expansion can refuse an otherwise readable saved document."""
import hashlib
import json

import pytest

from core.reporting.document import MAX_JSON_BYTES, ReportDocument, encode
from core.reporting.writer import load_document, regenerate


def test_unicode_saved_document_refusal_preserves_prior_export(tmp_path):
    document = ReportDocument("Saved Unicode", "fixture", "captured", metadata={"payload": ""})
    overhead = len(encode(document.to_dict()))
    # Each non-ASCII scalar occupies two UTF-8 bytes but six canonical ASCII bytes.
    count = (MAX_JSON_BYTES - overhead) // 6 + 1
    document.metadata["payload"] = "é" * count
    raw = json.dumps(document.to_dict(), ensure_ascii=False, separators=(",", ":")).encode()
    assert len(raw) < MAX_JSON_BYTES < overhead + 6 * count
    source = tmp_path / "saved.json"
    source.write_bytes(raw)
    original = hashlib.sha256(raw).hexdigest()
    destination = tmp_path / "export.json"
    destination.write_bytes(b"previous export")

    restored = load_document(source)
    assert len(restored.metadata["payload"]) == count
    with pytest.raises(ValueError, match="Reporting JSON exceeds"):
        regenerate(source, destination, format="json")

    assert destination.read_bytes() == b"previous export"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original

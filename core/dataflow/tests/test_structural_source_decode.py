"""Structural absence evidence requires faithful source text."""

import pytest

from core.dataflow import structural_validator as sv


def test_invalid_utf8_is_not_replaced_before_structural_verdict(tmp_path):
    source = b"# exact\ndef first(value):\n    return value\n\ndef second(value):\n    return value\n"
    file = tmp_path / "app.py"
    path = {
        "source": {"file": "app.py", "line": 3},
        "sink": {"file": "app.py", "line": 6},
    }
    # Complete valid source still supports the existing broken-edge result.
    # A deliberately encoded replacement character is valid source too.
    for comment in (b"exact", "\ufffd".encode()):
        file.write_bytes(source.replace(b"exact", comment))
        assert sv.validate_structurally(path, tmp_path, language="python").refuted

    invalid = source.replace(b"exact", b"\xff")
    file.write_bytes(invalid)
    # Some Python versions ignore invalid comment bytes during AST parsing.
    # Strict decoding establishes the malformed-source fixture consistently.
    with pytest.raises(UnicodeDecodeError):
        invalid.decode("utf-8")
    result = sv.validate_structurally(path, tmp_path, language="python")
    assert result.verdict == "inconclusive"
    assert not result.refuted
    assert sv._read_file_content(file) is None

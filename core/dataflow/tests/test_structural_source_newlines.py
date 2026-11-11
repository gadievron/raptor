"""Preserve raw scanner newlines and decline disagreeing Python spans."""

from core.dataflow import structural_validator as sv


def test_source_reader_preserves_scanner_newlines(tmp_path):
    file = tmp_path / "app.py"
    source = "def handle(value):\n    return value  # before\rafter\n"
    file.write_bytes(source.encode())
    assert sv._read_file_content(file) == source
    path = {
        "source": {"file": "app.py", "line": 2},
        "sink": {"file": "app.py", "line": 3},
    }
    result = sv.validate_structurally(path, tmp_path, language="python")
    assert result.evidence[0]["exists"] is True
    assert result.evidence[1]["exists"] is False
    # Python's parser counts bare CR as another line; raw scanners do not.
    assert sv._extract_graph(source, "python") is None
    # LF and CRLF remain supported, with exact source text retained.
    for newline in ("\n", "\r\n"):
        valid = f"def handle(value):{newline}    return value{newline}"
        file.write_bytes(valid.encode())
        assert sv._read_file_content(file) == valid
        path["sink"]["line"] = 2
        result = sv.validate_structurally(path, tmp_path, language="python")
        assert result.verdict == "confirmed"
        assert all(step["exists"] for step in result.evidence)

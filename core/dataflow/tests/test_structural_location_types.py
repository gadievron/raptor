"""Scanner line metadata must not acquire Python numeric coercions."""

from core.dataflow import structural_validator as sv


def test_noninteger_locations_decline_before_source_reads(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("def handle(value):\n    return value\n")
    path = {
        "source": {"file": "app.py", "line": 1},
        "sink": {"file": "app.py", "line": 2},
    }
    assert sv.validate_structurally(path, tmp_path, language="python").verdict == "confirmed"
    reader = sv._read_file_content
    reads = []

    def observe_read(file):
        reads.append(file)
        return reader(file)

    monkeypatch.setattr(sv, "_read_file_content", observe_read)
    for invalid in (True, False, 1.0, "1"):
        path["source"]["line"] = invalid
        reads.clear()
        result = sv.validate_structurally(path, tmp_path, language="python")
        assert result.verdict == "inconclusive", repr(invalid)
        assert not result.refuted
        assert not result.evidence
        assert not reads

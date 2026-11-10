"""Saved report display refuses unreadable text without stale substitution."""
from packages.binary_analysis.cli import main


def test_invalid_preferred_report_returns_failure_without_printing_older_report(tmp_path, capsys):
    preferred = tmp_path / "binary-investigation-report.md"
    preferred.write_bytes(b"invalid UTF-8: \xff")
    older = tmp_path / "binary-analysis-report.md"
    older.write_text("older captured output")
    assert main(["report", str(tmp_path)]) == 1
    output = capsys.readouterr()
    assert output.out == "" and "UnicodeDecodeError" in output.err
    assert "older captured output" not in output.err
    assert preferred.read_bytes() == b"invalid UTF-8: \xff"
    assert older.read_text() == "older captured output"
    assert not (tmp_path / "summary.json").exists()

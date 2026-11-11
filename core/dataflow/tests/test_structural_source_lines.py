"""Scanner line numbers do not count display-only Unicode separators."""

from core.dataflow.structural_validator import validate_structurally


def test_display_separators_do_not_create_source_locations(tmp_path):
    file = tmp_path / "app.py"
    path = {
        "source": {"file": "app.py", "line": 2},
        "sink": {"file": "app.py", "line": 3},
    }
    for separator in ("\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
        # Source is only parsed. The separator stays inside a comment.
        file.write_text(f"def handle(value):\n    return value  # before{separator}after\n")
        result = validate_structurally(path, tmp_path, language="python")
        assert result.evidence[0]["exists"] is True
        assert result.evidence[1]["exists"] is False, repr(separator)
        assert "exceeds file length 2" in result.evidence[1]["detail"]

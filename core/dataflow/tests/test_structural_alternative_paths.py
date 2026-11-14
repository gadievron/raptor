"""A primary-path refutation does not adjudicate sibling SARIF paths."""
from core.dataflow import structural_validator as sv


def test_primary_refutation_cannot_refute_a_viable_sibling(tmp_path):
    (tmp_path / "app.py").write_text(
        "def broken():\n"
        "    return 1\n"
        "def sink(value):\n"
        "    return value\n"
        "def live():\n"
        "    return sink(1)\n"
    )
    sink = {"file": "app.py", "line": 4}
    primary = {"source": {"file": "app.py", "line": 2}, "sink": sink, "steps": []}
    sibling = {"source": {"file": "app.py", "line": 6}, "sink": sink, "steps": []}
    assert sv.validate_structurally(primary, tmp_path, language="python").refuted
    assert sv.validate_structurally(sibling, tmp_path, language="python").verdict == "confirmed"
    assert sv.validate_structurally(
        {**primary, "alternative_paths": []}, tmp_path, language="python",
    ).refuted
    result = sv.validate_structurally(
        {**primary, "alternative_paths": [sibling]}, tmp_path, language="python",
    )
    assert result.verdict == "inconclusive"
    assert not result.refuted


def test_multiple_paths_decline_before_source_reads(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("def handle():\n    return 1\n")

    def unexpected_read(*args, **kwargs):
        raise AssertionError("unadjudicated alternatives must decline before reading source")

    monkeypatch.setattr(sv, "_read_file_content", unexpected_read)
    path = {"source": {"file": "app.py", "line": 1}, "sink": {"file": "app.py", "line": 2}}
    result = sv.validate_structurally({**path, "alternative_paths": [path]}, tmp_path, language="python")
    assert result.verdict == "inconclusive"
    assert not result.evidence

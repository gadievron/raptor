from core.dataflow.structural_validator import validate_structurally


def test_unresolved_cross_file_hop_does_not_report_complete_link_coverage(tmp_path):
    (tmp_path / "a.py").write_text("def start():\n    value = input()\n    sink(value)\n")
    (tmp_path / "b.py").write_text("def finish(value):\n    return value\n")
    result = validate_structurally({
        "source": {"file": "a.py", "line": 2},
        "steps": [{"file": "a.py", "line": 3}],
        "sink": {"file": "b.py", "line": 2},
    }, tmp_path, language="python")
    assert result.verdict == "confirmed"  # Existing advisory classification.
    assert "1/2 call link(s) verified" in result.reasoning
    assert "1 unresolved" in result.reasoning
    assert result.confidence == "medium"


def test_resolved_intra_function_path_retains_complete_coverage(tmp_path):
    (tmp_path / "a.py").write_text("def start():\n    value = input()\n    sink(value)\n")
    result = validate_structurally({
        "source": {"file": "a.py", "line": 2},
        "sink": {"file": "a.py", "line": 3},
    }, tmp_path, language="python")
    assert result.verdict == "confirmed"
    assert "All 1 call link(s) verified" in result.reasoning
    assert result.confidence == "high"

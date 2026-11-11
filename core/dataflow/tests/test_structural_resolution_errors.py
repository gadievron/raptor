"""Unavailable source paths decline structural validation."""

from core.dataflow.structural_validator import validate_structurally


def test_invalid_relative_path_is_inconclusive(tmp_path):
    result = validate_structurally({
        "source": {"file": "invalid\x00.py", "line": 1},
        "sink": {"file": "invalid\x00.py", "line": 2},
    }, tmp_path, language="python")
    assert result.verdict == "inconclusive"
    assert not result.refuted
    assert all(not step["exists"] for step in result.evidence)


def test_relative_symlink_loop_is_inconclusive(tmp_path):
    (tmp_path / "loop.py").symlink_to("loop.py")
    result = validate_structurally({
        "source": {"file": "loop.py", "line": 1},
        "sink": {"file": "loop.py", "line": 2},
    }, tmp_path, language="python")
    assert result.verdict == "inconclusive"
    assert not result.refuted
    assert all(not step["exists"] for step in result.evidence)

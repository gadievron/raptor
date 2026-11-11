"""A bounded prefix cannot establish that a source call edge is absent."""

from core.dataflow import structural_validator as sv


def test_truncated_source_cannot_refute_later_call(tmp_path, monkeypatch):
    prefix = "def second(value):\n    return value\n\ndef first(value):\n    copy = value\n"
    complete = prefix + "    return second(copy)\n"
    (tmp_path / "app.py").write_text(complete)
    path = {
        "source": {"file": "app.py", "line": 5},
        "sink": {"file": "app.py", "line": 2},
    }
    # Parse inert source only; neither fixture function is executed.
    control = sv.validate_structurally(path, tmp_path, language="python")
    assert control.verdict == "confirmed"
    assert control.evidence[0]["call_link_to_next"] is True

    monkeypatch.setattr(sv, "DEFAULT_MAX_SOURCE_CHARS", len(prefix))
    assert sv.read_text_capped(tmp_path / "app.py", max_chars=len(prefix)) == (prefix, True)
    result = sv.validate_structurally(path, tmp_path, language="python")
    assert result.verdict == "inconclusive"
    assert not result.refuted
    assert all("call_link_to_next" not in step for step in result.evidence)

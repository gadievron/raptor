"""Source containment must still hold when structural parsing reads."""

from core.dataflow import structural_validator as sv


def test_directory_change_after_resolution_declines_source(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    inside = repo / "src"
    inside.mkdir(parents=True)
    outside = tmp_path / "outside-fixture"
    outside.mkdir()
    source = "def handle(value):\n    return value\n"
    (inside / "app.py").write_text(source)
    (outside / "app.py").write_text("# outside fixture\n" + source)
    path = {
        "source": {"file": "src/app.py", "line": 1},
        "sink": {"file": "src/app.py", "line": 2},
    }
    assert sv.validate_structurally(path, repo, language="python").verdict == "confirmed"
    resolve = sv._resolve_file
    graph = sv._extract_graph
    parsed = []
    changed = False

    def change_directory(step, root):
        nonlocal changed
        result = resolve(step, root)
        if result is not None and not changed:
            changed = True
            inside.rename(tmp_path / "parked-source")
            inside.symlink_to(outside, target_is_directory=True)
        return result

    def observe_graph(content, language):
        parsed.append(content)
        return graph(content, language)

    monkeypatch.setattr(sv, "_resolve_file", change_directory)
    monkeypatch.setattr(sv, "_extract_graph", observe_graph)
    result = sv.validate_structurally(path, repo, language="python")
    assert changed
    assert not parsed
    assert result.verdict == "inconclusive"
    assert all(not step["exists"] for step in result.evidence)


def test_rooted_reader_preserves_utf8_character_budget(tmp_path, monkeypatch):
    source = "# " + "\U0001f642" * 20 + "\r\n"
    file = tmp_path / "unicode.py"
    monkeypatch.setattr(sv, "DEFAULT_MAX_SOURCE_CHARS", len(source))
    file.write_bytes(source.encode())
    assert len(source.encode()) > len(source)
    assert sv._read_file_content(file, tmp_path) == source
    file.write_bytes((source + "x").encode())
    assert sv._read_file_content(file, tmp_path) is None

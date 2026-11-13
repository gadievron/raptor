"""Stopping at a whole-file boundary must disclose unexamined context."""

from core.dataflow import cvefix_bridge


def test_bridge_discloses_unexamined_changed_files(tmp_path, monkeypatch):
    files = ["a.py", "b.py"]
    calls = []
    monkeypatch.setattr(cvefix_bridge, "_git_touched_files", lambda *args, **kwargs: list(files))

    def diff(_repo, _parent, _fix, path, **kwargs):
        calls.append(path)
        return "+ " + path

    monkeypatch.setattr(cvefix_bridge, "_git_diff", diff)

    def context(cap):
        calls.clear()
        return cvefix_bridge._git_diff_other_files(tmp_path, "fixture-parent", "fixture-fix", "sink.py",
                                                  total_cap=cap, per_file_cap=50)

    limited = context(2)
    assert calls == ["a.py"]
    assert "remaining files not examined" in limited
    assert "# file: b.py" not in limited
    complete = context(10)
    assert calls == ["a.py", "b.py"]
    assert "truncated" not in complete.lower()
    files[:] = ["a.py"]
    assert "truncated" not in context(2).lower()
    files[:] = ["a.py", "sink.py", "tests/test_case.py"]
    assert "truncated" not in context(2).lower()
    assert calls == ["a.py"]
    assert context(0) == ""

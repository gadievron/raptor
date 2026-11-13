"""Line-capped diff context must disclose that change data is partial."""

from types import SimpleNamespace

from core.dataflow import cvefix_bridge


def test_bridge_diff_truncation_is_disclosed(tmp_path, monkeypatch):
    response = SimpleNamespace(returncode=0, stdout="first\nsecond\nthird\nfourth\n")
    monkeypatch.setattr(cvefix_bridge.subprocess, "run", lambda *args, **kwargs: response)
    clipped = cvefix_bridge._git_diff(tmp_path, "fixture-parent", "fixture-fix", "fixture.py", cap=2)
    assert clipped.startswith("first\nsecond")
    assert "diff truncated" in clipped.lower()
    assert "third" not in clipped and "fourth" not in clipped
    assert cvefix_bridge._git_diff(tmp_path, "fixture-parent", "fixture-fix", "fixture.py", cap=0) == ""
    response.stdout = "first\nsecond\n"
    exact = cvefix_bridge._git_diff(tmp_path, "fixture-parent", "fixture-fix", "fixture.py", cap=2)
    assert exact == "first\nsecond"
    response.returncode = 1
    assert cvefix_bridge._git_diff(tmp_path, "fixture-parent", "fixture-fix", "fixture.py", cap=2) == ""

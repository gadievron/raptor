"""Finding and dataflow source reads retain their repository boundary."""

from packages.llm_analysis import agent


def test_context_reads_refuse_owned_directory_substitution(tmp_path, monkeypatch):
    original = agent.read_text_line_window_capped
    for kind in ("finding", "dataflow"):
        root = tmp_path / kind / "repo"
        member = root / "member"
        member.mkdir(parents=True)
        outside = tmp_path / kind / "outside"
        outside.mkdir()
        (member / "owned.c").write_text("inside_marker\n")
        (outside / "owned.c").write_text("outside_marker\n")
        ctx = agent.VulnerabilityContext({"finding_id": "owned", "rule_id": "test",
            "file": "member/owned.c", "startLine": 1, "endLine": 1,
            "message": "owned", "tool": "semgrep"}, root)
        assert ctx.read_vulnerable_code(0)
        assert ctx.full_code == "inside_marker"
        assert "inside_marker" in ctx._read_code_at_location("member/owned.c", 1, 0)
        calls = []

        def swapping_window(path, start, end, **kwargs):
            assert path == member / "owned.c"
            calls.append(kwargs)
            if len(calls) == 1:
                member.rename(root / "saved_member")
                member.symlink_to(outside, target_is_directory=True)
            return original(path, start, end, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(agent, "read_text_line_window_capped", swapping_window)
            if kind == "finding":
                assert ctx.read_vulnerable_code(0) is False
                assert ctx.full_code == "inside_marker"
            else:
                assert ctx._read_code_at_location("member/owned.c", 1, 0) == (
                    "[Error reading code: member/owned.c]")
        assert len(calls) == 1
        assert calls[0].get("target_root") == root

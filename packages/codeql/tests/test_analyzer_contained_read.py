"""Autonomous source context refuses intermediate-directory substitution."""

import logging

from packages.codeql import autonomous_analyzer as module


def test_analyzer_source_read_refuses_owned_directory_swap(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    member = root / "member"
    member.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    source = member / "owned.c"
    source.write_text("inside_marker\n")
    (outside / "owned.c").write_text("outside_marker\n")
    (root / "alias").symlink_to(member, target_is_directory=True)
    analyzer = module.AutonomousCodeQLAnalyzer.__new__(module.AutonomousCodeQLAnalyzer)
    analyzer.logger = logging.getLogger("owned-analyzer-source")
    finding = module.CodeQLFinding("cpp/owned", "owned", "owned", "warning",
                                  "member/owned.c", 1, 1, "snippet_fallback")
    for path in ("member/owned.c", "alias/owned.c"):
        finding.file_path = path
        assert analyzer.read_vulnerable_code(finding, root, 0) == ">>>    1: inside_marker"
    finding.file_path = "member/owned.c"
    original = module.read_contained_text_capped
    calls = []

    def swapping_reader(repo_root, path, **kwargs):
        assert repo_root == root
        assert path == source
        calls.append(path)
        member.rename(root / "saved_member")
        member.symlink_to(outside, target_is_directory=True)
        return original(repo_root, path, **kwargs)

    monkeypatch.setattr(module, "read_contained_text_capped", swapping_reader)
    result = analyzer.read_vulnerable_code(finding, root, 0)
    assert len(calls) == 1
    assert result == "snippet_fallback"

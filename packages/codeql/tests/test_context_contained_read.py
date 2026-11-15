"""Rooted context reads refuse directory substitution after resolution."""

import logging
from pathlib import Path

from packages.codeql import dataflow_validator as module


def test_context_refuses_owned_intermediate_directory_swap(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    member = root / "member"
    member.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (member / "owned.c").write_text("inside_marker\n")
    (outside / "owned.c").write_text("outside_marker\n")
    (root / "alias").symlink_to(member, target_is_directory=True)
    validator = module.DataflowValidator.__new__(module.DataflowValidator)
    validator.logger = logging.getLogger("contained-codeql-context")
    for path in ("member/owned.c", "alias/owned.c"):
        assert validator.read_source_context(path, 1, 0, root) == ">>>    1: inside_marker"

    original = module.read_text_line_window_capped
    calls = []

    def swapping_window(path, start, end, **kwargs):
        assert Path(path) == member / "owned.c"
        calls.append(kwargs)
        if len(calls) == 1:
            member.rename(root / "saved_member")
            member.symlink_to(outside, target_is_directory=True)
        return original(path, start, end, **kwargs)

    monkeypatch.setattr(module, "read_text_line_window_capped", swapping_window)
    context = validator.read_source_context("member/owned.c", 1, 0, root)
    assert len(calls) == 1
    assert context == ""
    assert calls[0].get("target_root") == root

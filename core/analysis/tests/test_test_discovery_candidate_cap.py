"""Discarded discovery candidates do not need metadata reads."""

import os
from pathlib import Path

import pytest

from core.analysis.test_discovery import _find_test_files


@pytest.mark.parametrize("tree_count", [3, 506])
def test_full_candidate_buckets_preserve_priority_and_skipped_count(
    tmp_path, monkeypatch, tree_count,
):
    loose = tmp_path / "src"
    tree = tmp_path / "tests"
    loose.mkdir()
    tree.mkdir()
    for i in range(506):
        (loose / f"test_loose_{i}.py").write_text("# test\n")
    for i in range(tree_count):
        (tree / f"test_tree_{i}.py").write_text("# test\n")
    (tree / "unsupported.txt").write_text("not a supported test language\n")

    # Preserve the filesystem's actual walk order, including loose files
    # encountered before the recognised tree. No sorting contract is added.
    loose_order = []
    tree_order = []
    for root, _dirs, files in os.walk(tmp_path):
        bucket = tree_order if Path(root) == tree else loose_order
        bucket.extend(Path(root) / name for name in files if name.endswith(".py"))
    expected = (tree_order + loose_order)[:500]
    original_stat = Path.stat
    candidate_stats = []

    def record_stat(path, *args, **kwargs):
        if path.parent in (loose, tree) and path.suffix == ".py":
            candidate_stats.append(path)
        return original_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "stat", record_stat)
        files, skipped = _find_test_files(tmp_path)

    assert files == expected
    assert skipped == 1
    assert len(candidate_stats) == 500 + min(tree_count, 500)

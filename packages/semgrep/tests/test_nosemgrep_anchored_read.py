"""Suppression evidence stays beneath the annotation root at open time."""

import pytest

from core.source import contained
from packages.semgrep import nosemgrep


def document(uri):
    row = {"ruleId": "owned", "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}]}
    return {"runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [row]}]}, row


@pytest.mark.parametrize("mode", ["ordinary", "in-root-link", "outside-link", "intermediate-swap"])
def test_annotation_read_is_anchored(tmp_path, monkeypatch, mode):
    root, sibling = tmp_path / "root", tmp_path / "sibling"
    root.mkdir()
    sibling.mkdir()
    inner = root / "inner"
    inner.mkdir()
    (inner / "case.c").write_text("owned(); // nosemgrep: owned\n")
    (sibling / "case.c").write_text("owned(); // nosemgrep: owned\n")
    uri = "inner/case.c"
    if mode.endswith("link"):
        (root / "link").symlink_to(inner if mode == "in-root-link" else sibling,
                                   target_is_directory=True)
        uri = "link/case.c"
    opened = []
    original = contained.open_regular_beneath

    def open_after_check(base, relative, *args, **kwargs):
        opened.append((base, relative))
        if mode == "intermediate-swap":
            inner.rename(root / "preserved")
            inner.symlink_to(sibling, target_is_directory=True)
        return original(base, relative, *args, **kwargs)

    monkeypatch.setattr(contained, "open_regular_beneath", open_after_check)
    doc, row = document(uri)
    try:
        expected = int(mode in ("ordinary", "in-root-link"))
        assert nosemgrep.annotate_sarif(doc, root) == expected
        assert bool(row.get("properties", {}).get("nosemgrep")) is bool(expected)
        assert len(opened) == (0 if mode == "outside-link" else 1)
    finally:
        if mode == "intermediate-swap" and inner.is_symlink():
            inner.unlink()
            (root / "preserved").rename(inner)

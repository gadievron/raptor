"""Anchored text reads retain the ordinary reader's prefix semantics."""
import pytest

from core.source import read_contained, read_contained_text_capped, read_text_capped


@pytest.mark.parametrize("text,cap", [
    ("α😀\r\nsecond\n", 100),
    ("α😀\r\nsecond\n", 6),
    ("α😀long-line", 3),
    ("", 0),
    ("x", 0),
], ids=["exact", "line-prefix", "unicode-prefix", "empty", "zero-prefix"])
def test_contained_text_matches_capped_semantics(tmp_path, text, cap):
    path = tmp_path / "source.py"
    path.write_bytes(text.encode())
    expected = read_text_capped(path, cap, errors="strict", newline="")
    assert read_contained_text_capped(tmp_path, path, max_chars=cap, errors="strict", newline="") == expected
    assert read_contained(tmp_path, path, max_chars=cap, errors="strict", newline="") == expected[0]


def test_contained_text_refuses_escape_and_preserves_decode_error(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside")
    (root / "redirect").symlink_to(outside)
    assert read_contained_text_capped(root, "redirect") is None
    assert read_contained_text_capped(root, outside) is None
    assert read_contained_text_capped(root, "missing") is None
    path = root / "invalid.py"
    path.write_bytes(b"invalid: \xff")
    with pytest.raises(UnicodeDecodeError):
        read_contained_text_capped(root, path, errors="strict", newline="")

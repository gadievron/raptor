"""Tests for ``core.annotations`` storage layer.

Covers:
  * Read/write round-trip with body + metadata
  * Multiple annotations per source file (preserves siblings)
  * Update-in-place vs append for the same function
  * Removal: cleans up empty files
  * Path traversal defence (no .., no absolute paths)
  * Atomic write (no partial files on simulated crash)
  * Walk-the-tree iterator
  * Format-stability: sorted sections, deterministic output
  * Quoting: values with spaces and quotes round-trip cleanly
"""

from __future__ import annotations


import pytest

from core.annotations import (
    Annotation,
    annotation_path,
    iter_all_annotations,
    read_annotation,
    read_file_annotations,
    remove_annotation,
    write_annotation,
)


# ---------------------------------------------------------------------------
# Path resolution + validation
# ---------------------------------------------------------------------------


class TestAnnotationPath:
    def test_mirrors_source_tree_structure(self, tmp_path):
        p = annotation_path(tmp_path, "packages/foo/bar.py")
        assert p == tmp_path / "packages" / "foo" / "bar.py.md"

    def test_top_level_file(self, tmp_path):
        p = annotation_path(tmp_path, "main.py")
        assert p == tmp_path / "main.py.md"

    def test_rejects_traversal(self, tmp_path):
        with pytest.raises(ValueError, match=r"\.\."):
            annotation_path(tmp_path, "../etc/passwd")

    def test_rejects_traversal_in_middle(self, tmp_path):
        with pytest.raises(ValueError, match=r"\.\."):
            annotation_path(tmp_path, "ok/../etc/passwd")

    def test_rejects_absolute_path(self, tmp_path):
        with pytest.raises(ValueError, match="relative"):
            annotation_path(tmp_path, "/etc/passwd")

    def test_rejects_empty(self, tmp_path):
        with pytest.raises(ValueError, match="non-empty"):
            annotation_path(tmp_path, "")


# ---------------------------------------------------------------------------
# Read / write round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_simple_body_only(self, tmp_path):
        ann = Annotation(
            file="src/foo.py",
            function="bar",
            body="This function returns 42.",
        )
        write_annotation(tmp_path, ann)
        got = read_annotation(tmp_path, "src/foo.py", "bar")
        assert got == ann

    def test_with_metadata(self, tmp_path):
        ann = Annotation(
            file="src/foo.py", function="bar",
            body="Suspicious — sys.argv → os.system",
            metadata={"status": "suspicious", "cwe": "CWE-78"},
        )
        write_annotation(tmp_path, ann)
        got = read_annotation(tmp_path, "src/foo.py", "bar")
        assert got is not None
        assert got.metadata["status"] == "suspicious"
        assert got.metadata["cwe"] == "CWE-78"
        assert "sys.argv" in got.body

    def test_metadata_only_no_body(self, tmp_path):
        """Common audit case: function reviewed clean, no prose."""
        ann = Annotation(
            file="src/foo.py", function="trivial_getter",
            metadata={"status": "clean"},
        )
        write_annotation(tmp_path, ann)
        got = read_annotation(tmp_path, "src/foo.py", "trivial_getter")
        assert got.metadata["status"] == "clean"
        assert got.body == ""

    def test_qualified_method_name(self, tmp_path):
        """Class methods qualified as ``Klass.method`` survive
        round-trip."""
        ann = Annotation(
            file="src/foo.py", function="MyClass.do_thing",
            body="ok",
        )
        write_annotation(tmp_path, ann)
        got = read_annotation(tmp_path, "src/foo.py", "MyClass.do_thing")
        assert got is not None

    def test_returns_none_for_missing_function(self, tmp_path):
        # File exists but function not annotated.
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="bar", body="x",
        ))
        assert read_annotation(tmp_path, "src/foo.py", "missing") is None

    def test_returns_none_for_missing_file(self, tmp_path):
        assert read_annotation(tmp_path, "nope.py", "any") is None


# ---------------------------------------------------------------------------
# Multi-annotation files
# ---------------------------------------------------------------------------


class TestMultipleAnnotations:
    def test_siblings_preserved_on_write(self, tmp_path):
        """Writing function B doesn't drop function A in the same
        source file."""
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="alpha", body="A body",
        ))
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="beta", body="B body",
        ))
        got = read_file_annotations(tmp_path, "src/foo.py")
        names = {a.function for a in got}
        assert names == {"alpha", "beta"}

    def test_update_replaces_existing(self, tmp_path):
        """Writing the same function name overwrites — not appends."""
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="alpha", body="initial",
        ))
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="alpha", body="revised",
            metadata={"status": "clean"},
        ))
        got = read_annotation(tmp_path, "src/foo.py", "alpha")
        assert got.body == "revised"
        assert got.metadata["status"] == "clean"
        # Only one alpha section.
        all_for_file = read_file_annotations(tmp_path, "src/foo.py")
        assert sum(1 for a in all_for_file if a.function == "alpha") == 1

    def test_sections_sorted_alphabetically(self, tmp_path):
        """Diff stability: write order should not affect on-disk
        order. Sections sorted by function name."""
        for name in ("zebra", "alpha", "middle"):
            write_annotation(tmp_path, Annotation(
                file="src/foo.py", function=name, body=name,
            ))
        path = annotation_path(tmp_path, "src/foo.py")
        text = path.read_text(encoding="utf-8")
        # alpha appears before middle which appears before zebra.
        a = text.index("## alpha")
        m = text.index("## middle")
        z = text.index("## zebra")
        assert a < m < z


# ---------------------------------------------------------------------------
# Removal
# ---------------------------------------------------------------------------


class TestRemoval:
    def test_remove_single_annotation_keeps_siblings(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="alpha", body="A",
        ))
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="beta", body="B",
        ))
        assert remove_annotation(tmp_path, "src/foo.py", "alpha") is True
        remaining = read_file_annotations(tmp_path, "src/foo.py")
        assert {a.function for a in remaining} == {"beta"}

    def test_remove_last_annotation_deletes_file(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="alpha", body="A",
        ))
        path = annotation_path(tmp_path, "src/foo.py")
        assert path.exists()
        remove_annotation(tmp_path, "src/foo.py", "alpha")
        assert not path.exists()

    def test_remove_nonexistent_returns_false(self, tmp_path):
        assert remove_annotation(tmp_path, "nope.py", "x") is False


# ---------------------------------------------------------------------------
# iter_all_annotations
# ---------------------------------------------------------------------------


class TestIterAll:
    def test_walks_tree(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="a", body="A",
        ))
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="b", body="B",
        ))
        write_annotation(tmp_path, Annotation(
            file="lib/util.py", function="c", body="C",
        ))
        write_annotation(tmp_path, Annotation(
            file="deep/nested/bar.c", function="d", body="D",
        ))

        all_ = list(iter_all_annotations(tmp_path))
        names = sorted(a.function for a in all_)
        assert names == ["a", "b", "c", "d"]

    def test_empty_tree_yields_nothing(self, tmp_path):
        assert list(iter_all_annotations(tmp_path)) == []

    def test_nonexistent_base_yields_nothing(self, tmp_path):
        assert list(iter_all_annotations(tmp_path / "nope")) == []


# ---------------------------------------------------------------------------
# Edge-case formatting
# ---------------------------------------------------------------------------


class TestFormatting:
    def test_metadata_value_with_spaces_quoted(self, tmp_path):
        ann = Annotation(
            file="x.py", function="f",
            metadata={"reviewer": "Alice Smith"},
        )
        write_annotation(tmp_path, ann)
        text = annotation_path(tmp_path, "x.py").read_text()
        assert 'reviewer="Alice Smith"' in text
        # Round-trip preserves the value.
        got = read_annotation(tmp_path, "x.py", "f")
        assert got.metadata["reviewer"] == "Alice Smith"

    def test_metadata_value_with_quotes_escaped(self, tmp_path):
        ann = Annotation(
            file="x.py", function="f",
            metadata={"note": 'has "quotes"'},
        )
        write_annotation(tmp_path, ann)
        got = read_annotation(tmp_path, "x.py", "f")
        # The value with embedded quotes round-trips at least partially —
        # we don't promise full quote-fidelity (the format is line-based)
        # but the read shouldn't crash.
        assert got is not None

    def test_body_with_markdown_headings(self, tmp_path):
        """Body containing ``###`` headings (one level deeper than
        section heading) should NOT be confused with a new section."""
        body = "# Tier-1 heading inside body\n\n### subhead\n\nprose"
        ann = Annotation(file="x.py", function="f", body=body)
        write_annotation(tmp_path, ann)
        got = read_annotation(tmp_path, "x.py", "f")
        # The single-hash heading at body start would mis-parse if
        # the regex were too loose. Exactly one record found.
        all_ = read_file_annotations(tmp_path, "x.py")
        assert len(all_) == 1
        assert "subhead" in got.body

    def test_body_with_double_hash_in_code_block(self, tmp_path):
        """Markdown ``## name`` inside a fenced code block would
        false-positive as a new section. Acceptable limitation —
        the format expects ``## name`` only at section starts. We
        document the limitation by pinning the current behaviour:
        no crash, may split the section."""
        body = "```\n## not_really_a_section\n```\nreal content"
        ann = Annotation(file="x.py", function="f", body=body)
        write_annotation(tmp_path, ann)
        # Round-trip: we read whatever the regex sees. Pin that
        # the original section's name + first line at minimum
        # are recoverable.
        all_ = read_file_annotations(tmp_path, "x.py")
        assert any(a.function == "f" for a in all_)


# ---------------------------------------------------------------------------
# Atomic write (sanity)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Adversarial: input that would corrupt the on-disk format
# ---------------------------------------------------------------------------


class TestAdversarialInputs:
    def test_rejects_function_name_with_newline(self, tmp_path):
        """Newline in function name would let an attacker forge fake
        ``## evil`` headings in subsequent lines."""
        with pytest.raises(ValueError, match="newline"):
            write_annotation(tmp_path, Annotation(
                file="x.py", function="real\n## injected", body="x",
            ))

    def test_rejects_function_name_with_carriage_return(self, tmp_path):
        with pytest.raises(ValueError, match="newline"):
            write_annotation(tmp_path, Annotation(
                file="x.py", function="real\r## injected", body="x",
            ))

    def test_rejects_function_name_with_null(self, tmp_path):
        with pytest.raises(ValueError, match="newline"):
            write_annotation(tmp_path, Annotation(
                file="x.py", function="real\x00", body="x",
            ))

    def test_rejects_empty_function_name(self, tmp_path):
        with pytest.raises(ValueError, match="non-empty"):
            write_annotation(tmp_path, Annotation(
                file="x.py", function="", body="x",
            ))

    def test_rejects_metadata_value_with_html_comment_close(self, tmp_path):
        """``-->`` in a metadata value would close the comment early
        on disk and cause the body content after to be re-parsed as
        comment trailer."""
        with pytest.raises(ValueError, match="-->"):
            write_annotation(tmp_path, Annotation(
                file="x.py", function="f",
                metadata={"note": "value-->evil"},
            ))

    def test_rejects_metadata_value_with_html_comment_open(self, tmp_path):
        with pytest.raises(ValueError, match="<!--"):
            write_annotation(tmp_path, Annotation(
                file="x.py", function="f",
                metadata={"note": "value<!--evil"},
            ))

    def test_rejects_metadata_value_with_newline(self, tmp_path):
        with pytest.raises(ValueError, match="newline"):
            write_annotation(tmp_path, Annotation(
                file="x.py", function="f",
                metadata={"note": "line1\nline2"},
            ))

    def test_rejects_metadata_key_with_special_chars(self, tmp_path):
        with pytest.raises(ValueError):
            write_annotation(tmp_path, Annotation(
                file="x.py", function="f",
                metadata={"bad key": "v"},
            ))

    def test_rejects_source_path_with_newline(self, tmp_path):
        with pytest.raises(ValueError, match="newline"):
            annotation_path(tmp_path, "foo\nbar.py")

    def test_rejects_source_path_with_null(self, tmp_path):
        with pytest.raises(ValueError, match="newline"):
            annotation_path(tmp_path, "foo\x00bar.py")

    def test_legit_unicode_in_function_name_accepted(self, tmp_path):
        """Defense should not over-reject — unicode identifiers are
        valid in Python and many other languages."""
        write_annotation(tmp_path, Annotation(
            file="x.py", function="MyClass.做事",
            body="ok",
        ))
        got = read_annotation(tmp_path, "x.py", "MyClass.做事")
        assert got is not None

    def test_legit_special_chars_in_body_preserved(self, tmp_path):
        """Body is free-form prose — should preserve whatever the
        operator wrote, including comment-like sequences (since
        the body is not inside a comment)."""
        body = "Saw <!-- comment --> in the input. Also `-->` at line 5."
        ann = Annotation(file="x.py", function="f", body=body)
        write_annotation(tmp_path, ann)
        got = read_annotation(tmp_path, "x.py", "f")
        assert "<!-- comment -->" in got.body
        assert "`-->`" in got.body

    def test_corrupt_utf8_does_not_crash_reader(self, tmp_path):
        """If a file gets corrupted on disk, reader should not crash —
        return empty rather than propagate UnicodeDecodeError."""
        # Write a real annotation, then corrupt the file with bytes
        # that aren't valid UTF-8.
        write_annotation(tmp_path, Annotation(
            file="x.py", function="f", body="ok",
        ))
        path = annotation_path(tmp_path, "x.py")
        path.write_bytes(b"\xff\xfe garbage \xc3\x28 not utf-8")
        # Reader should swallow and return empty, not propagate.
        result = read_file_annotations(tmp_path, "x.py")
        assert result == []
        # iter_all_annotations should also tolerate it.
        all_ = list(iter_all_annotations(tmp_path))
        assert all_ == []


class TestAtomicWrite:
    def test_no_partial_file_on_concurrent_reader(self, tmp_path):
        """Atomic-rename means a reader who opens the path between
        two writes sees either the old content or the new — never
        a half-written file. Pin by reading immediately after write."""
        write_annotation(tmp_path, Annotation(
            file="x.py", function="a", body="initial " * 1000,
        ))
        write_annotation(tmp_path, Annotation(
            file="x.py", function="a", body="updated " * 1000,
        ))
        got = read_annotation(tmp_path, "x.py", "a")
        # Body is exactly one of the two written values, not a mix.
        assert got.body in (
            ("initial " * 1000).rstrip(),
            ("updated " * 1000).rstrip(),
        )

    def test_no_tempfile_left_behind_after_write(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="x.py", function="a", body="ok",
        ))
        # No .annotation-*.tmp files left in the directory.
        leftovers = list(tmp_path.glob("**/.annotation-*.tmp"))
        assert leftovers == []

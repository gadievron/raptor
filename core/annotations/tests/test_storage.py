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

import os

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

    def test_invalid_filename_in_tree_skipped_not_fatal(self, tmp_path):
        """One directory entry whose recovered source path fails
        validation (legal on Linux — planted, rsync artifact, or a
        tool bug) used to crash every whole-tree reader; the valid
        annotations after it were never yielded."""
        write_annotation(tmp_path, Annotation(
            file="good.py", function="f", body="x",
        ))
        (tmp_path / "evil\rname.py.md").write_text("## fn\n\nbody\n")
        got = list(iter_all_annotations(tmp_path))
        assert [a.file for a in got] == ["good.py"]

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

    def test_hand_edited_tab_value_round_trips_quoted(self, tmp_path):
        """The write path rejects tabs in values, so a quoted tab
        value only arrives by hand edit — it parsed fine, then the
        next rewrite re-emitted it UNQUOTED (quoting keyed on spaces
        only) and the re-parse stopped at the tab, silently dropping
        the remainder."""
        path = annotation_path(tmp_path, "a.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            '<!-- annotations-version: 1 -->\n# a.py\n\n'
            '## f\n<!-- meta: note="alpha\tbeta" source=agent -->\n'
            '\nbody\n',
        )
        assert read_annotation(tmp_path, "a.py", "f").metadata["note"] \
            == "alpha\tbeta"
        write_annotation(tmp_path, Annotation(
            file="a.py", function="g", body="x",
        ))
        assert read_annotation(tmp_path, "a.py", "f").metadata["note"] \
            == "alpha\tbeta"

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

    def test_body_with_double_hash_in_code_block_rejected(self, tmp_path):
        """Markdown ``## name`` at line start — even inside a fenced
        code block — would be re-parsed as a new section on read.
        Historically this "may split the section" behaviour was pinned
        as an acceptable limitation; it is now rejected at write time
        because the same shape is the section-forgery primitive (a
        crafted body fabricates a human-graded section). Operators
        keep ``###`` and indentation for structured prose."""
        body = "```\n## not_really_a_section\n```\nreal content"
        ann = Annotation(file="x.py", function="f", body=body)
        with pytest.raises(ValueError, match="section heading"):
            write_annotation(tmp_path, ann)
        assert read_file_annotations(tmp_path, "x.py") == []


# ---------------------------------------------------------------------------
# Atomic write (sanity)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Adversarial: input that would corrupt the on-disk format
# ---------------------------------------------------------------------------


class TestBodyRoundTripFraming:
    """models.py claims the body round-trips; pin exactly what that
    means: interior lines (whitespace-only included) are exact,
    edge newlines are trimmed by the section framing."""

    def test_whitespace_only_first_body_line_survives(self, tmp_path):
        # Regression: the MULTILINE meta regex's trailing \s*$ used
        # to swallow the whitespace-only line after the meta comment.
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="   \nfirst real line",
            metadata={"source": "agent"},
        ))
        ann = read_annotation(tmp_path, "a.py", "f")
        assert ann.body == "   \nfirst real line"
        # Stable across a sibling rewrite.
        write_annotation(tmp_path, Annotation(
            file="a.py", function="g", body="x",
        ))
        assert read_annotation(tmp_path, "a.py", "f").body == \
            "   \nfirst real line"

    def test_interior_blank_lines_exact(self, tmp_path):
        body = "para one\n\n  indented\n\npara two"
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body=body,
            metadata={"source": "agent"},
        ))
        assert read_annotation(tmp_path, "a.py", "f").body == body

    def test_edge_newlines_are_trimmed(self, tmp_path):
        # Documented framing loss (models.py): leading/trailing
        # newlines don't survive the on-disk section framing.
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="\n\nedges\n\n",
        ))
        assert read_annotation(tmp_path, "a.py", "f").body == "edges"

    def test_meta_less_section_keeps_leading_whitespace_line(
        self, tmp_path,
    ):
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="   \nreal",
        ))
        ann = read_annotation(tmp_path, "a.py", "f")
        assert ann.body == "   \nreal"


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


class TestRestamp:
    def test_restamp_updates_only_the_stamp(self, tmp_path):
        from core.annotations import restamp_annotation
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="the body",
            metadata={"source": "human", "status": "clean",
                      "provenance": "non-tty", "tty": "none"},
        ))
        assert restamp_annotation(tmp_path, "a.py", "f", {
            "provenance": "interactive-tty", "tty": "stdin",
            "sid": "inherited", "envm": "trusted", "parents": "bash",
        })
        ann = read_annotation(tmp_path, "a.py", "f")
        assert ann.body == "the body"
        assert ann.metadata["status"] == "clean"
        assert ann.metadata["source"] == "human"
        assert ann.metadata["provenance"] == "interactive-tty"

    def test_restamp_reads_current_state_under_the_lock(self, tmp_path):
        # The old edit flow read the file, then wrote the copy it had
        # read — a concurrent same-function write in between was
        # clobbered with stale content. restamp takes only the
        # function NAME, so the concurrent body survives.
        from core.annotations import restamp_annotation
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="original",
        ))
        # "concurrent" writer lands after the caller decided to
        # restamp but before the restamp executes:
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="concurrent update",
            metadata={"source": "agent"},
        ))
        assert restamp_annotation(tmp_path, "a.py", "f", {
            "provenance": "non-tty", "tty": "none",
            "sid": "inherited", "envm": "trusted", "parents": "bash",
        })
        assert read_annotation(tmp_path, "a.py", "f").body == \
            "concurrent update"

    def test_restamp_missing_function_returns_false(self, tmp_path):
        from core.annotations import restamp_annotation
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="x",
        ))
        assert not restamp_annotation(tmp_path, "a.py", "ghost", {
            "provenance": "non-tty", "tty": "none",
        })

    def test_restamp_drops_stale_corroboration_marker(self, tmp_path):
        from core.annotations import restamp_annotation
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="x",
            metadata={"source": "human", "provenance": "interactive-tty",
                      "tty": "stdin", "corroboration": "pre-era"},
        ))
        assert restamp_annotation(tmp_path, "a.py", "f", {
            "provenance": "interactive-tty", "tty": "stdin",
            "sid": "self", "envm": "trusted", "parents": "script",
        })
        meta = read_annotation(tmp_path, "a.py", "f").metadata
        assert "corroboration" not in meta
        from core.annotations import is_human_grade
        assert not is_human_grade(meta)

    def test_restamp_preserves_preamble(self, tmp_path):
        from core.annotations import restamp_annotation
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="x",
        ))
        path = annotation_path(tmp_path, "a.py")
        lines = path.read_text().splitlines(keepends=True)
        lines.insert(2, "file-level prose\n")
        path.write_text("".join(lines))
        assert restamp_annotation(tmp_path, "a.py", "f", {
            "provenance": "non-tty", "tty": "none",
        })
        assert "file-level prose" in path.read_text()

    def test_restamp_refuses_corrupt_file(self, tmp_path):
        from core.annotations import AnnotationFileError, restamp_annotation
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="x",
        ))
        path = annotation_path(tmp_path, "a.py")
        path.write_bytes(path.read_bytes() + b"\xff\xfe")
        with pytest.raises(AnnotationFileError):
            restamp_annotation(tmp_path, "a.py", "f", {
                "provenance": "non-tty", "tty": "none",
            })


class TestNitSweep:
    def test_remove_surfaces_unlink_failure(self, tmp_path):
        """remove_annotation swallowed the unlink OSError and still
        returned True — CLI printed 'removed' while every reader kept
        seeing the note."""
        import os
        from core.annotations import AnnotationFileError
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="x",
        ))
        path = annotation_path(tmp_path, "a.py")
        os.chmod(path.parent, 0o500)
        try:
            if os.geteuid() == 0:
                pytest.skip("root bypasses file permissions")
            with pytest.raises(AnnotationFileError, match="still on disk"):
                remove_annotation(tmp_path, "a.py", "f")
        finally:
            os.chmod(path.parent, 0o755)
        assert path.exists()

    def test_status_enum_validated_at_write(self, tmp_path):
        with pytest.raises(ValueError, match="invalid annotation status"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="f", body="x",
                metadata={"status": "cleaan"},
            ))
        for status in ("clean", "suspicious", "finding", "dormant",
                       "error", "sink", "entry_point",
                       "trust_boundary"):
            assert write_annotation(tmp_path, Annotation(
                file="a.py", function=f"f_{status}", body="x",
                metadata={"status": status},
            )) is not None

    def test_trailing_slash_and_dot_segments_rejected(self, tmp_path):
        """'a/b/' concatenated to 'a/b/.md' — a suffix-less hidden
        file iter_all_annotations skips: written yet invisible to
        every cross-run reader."""
        for bad in ("a/b/", "a//b", "a/./b", "./a"):
            with pytest.raises(ValueError, match="segments"):
                write_annotation(tmp_path, Annotation(
                    file=bad, function="f", body="x",
                ))

    def test_control_bytes_rejected_at_write(self, tmp_path):
        esc = "\x1b"
        with pytest.raises(ValueError, match="control"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function=f"fn{esc}[2Jx", body="x",
            ))
        with pytest.raises(ValueError, match="control"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="f", body=f"note {esc}[31mred",
            ))
        with pytest.raises(ValueError, match="control"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="f", body="x",
                metadata={"note": f"{esc}]0;title\x07"},
            ))
        # \t and \n stay legal where the field rules allow them.
        assert write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="line one\n\tindented",
        )) is not None


class TestSizeBudgets:
    """Two-direction pins for the churn-prone limits: at/below the
    cap is accepted, above is refused/skipped."""

    def test_body_at_cap_accepted(self, tmp_path):
        from core.annotations.storage import _MAX_BODY_LEN
        assert write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="A" * _MAX_BODY_LEN,
        )) is not None

    def test_body_over_cap_rejected(self, tmp_path):
        from core.annotations.storage import _MAX_BODY_LEN
        with pytest.raises(ValueError, match="body exceeds"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="f",
                body="A" * (_MAX_BODY_LEN + 1),
            ))
        assert not (tmp_path / "a.py.md").exists()

    def test_oversize_file_skipped_by_tolerant_read(self, tmp_path):
        import core.annotations.storage as storage
        path = annotation_path(tmp_path, "a.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("## f\n\n" + "x" * 64)
        original = path.read_bytes()
        # Budget shrunk for the test — writing a real >32 MiB file
        # per run would be wasteful.
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(storage, "_MAX_FILE_BYTES", 32)
            assert read_file_annotations(tmp_path, "a.py") == []
            assert list(iter_all_annotations(tmp_path)) == []
            # Strict path refuses, leaving the bytes untouched.
            from core.annotations import AnnotationFileError
            with pytest.raises(AnnotationFileError, match="budget"):
                write_annotation(tmp_path, Annotation(
                    file="a.py", function="g", body="y",
                ))
        assert path.read_bytes() == original
        # Back under the real budget everything reads again.
        assert len(read_file_annotations(tmp_path, "a.py")) == 1


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


# ---------------------------------------------------------------------------
# Resolve()-based containment + lock-file symlink defence
# ---------------------------------------------------------------------------


class TestPathContainment:
    def test_symlinked_subdir_escaping_base_rejected(self, tmp_path):
        """A symlinked intermediate directory INSIDE the tree passes
        the lexical checks but must not redirect writes outside it."""
        base = tmp_path / "annotations"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (base / "sub").symlink_to(outside)

        with pytest.raises(ValueError, match="escapes base dir"):
            annotation_path(base, "sub/foo.py")

    def test_symlinked_subdir_inside_base_accepted(self, tmp_path):
        """A symlink that stays under the base dir is fine."""
        base = tmp_path / "annotations"
        (base / "real").mkdir(parents=True)
        (base / "alias").symlink_to(base / "real")

        p = annotation_path(base, "alias/foo.py")
        assert p == base / "alias" / "foo.py.md"

    def test_write_annotation_refused_through_escaping_symlink(self, tmp_path):
        base = tmp_path / "annotations"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (base / "sub").symlink_to(outside)

        ann = Annotation(file="sub/foo.py", function="f", body="note")
        with pytest.raises(ValueError, match="escapes base dir"):
            write_annotation(base, ann)
        assert list(outside.iterdir()) == []

    def test_nonexistent_parents_still_resolve(self, tmp_path):
        """Deep paths whose parents don't exist yet must keep working —
        the resolve() check is lexical for missing components."""
        base = tmp_path / "annotations"
        ann = Annotation(file="a/b/c/foo.py", function="f", body="note")
        path = write_annotation(base, ann)
        assert path == base / "a" / "b" / "c" / "foo.py.md"
        assert path.is_file()


class TestFinalComponentSymlink:
    def _plant(self, tmp_path):
        import os
        base = tmp_path / "base"
        (base / "src").mkdir(parents=True)
        outside = tmp_path / "outside.md"
        outside.write_text("## fn\n\nOUTSIDE-BASE CONTENT\n")
        os.symlink(outside, base / "src" / "x.py.md")
        return base, outside

    def test_read_refuses_symlinked_annotation_file(self, tmp_path):
        # Static, no race: the parent resolve never inspected the
        # final component, so reads followed a planted link to any
        # reachable file and parsed its content into annotation
        # surfaces (/annotate show included).
        base, _ = self._plant(tmp_path)
        assert read_file_annotations(base, "src/x.py") == []
        assert list(iter_all_annotations(base)) == []

    def test_write_refuses_through_symlinked_annotation_file(
        self, tmp_path,
    ):
        from core.annotations import AnnotationFileError
        base, outside = self._plant(tmp_path)
        before = outside.read_text()
        with pytest.raises(AnnotationFileError, match="symlink"):
            write_annotation(base, Annotation(
                file="src/x.py", function="g", body="y",
            ))
        assert outside.read_text() == before

    def test_write_window_dir_swap_is_refused_under_lock(
        self, tmp_path, monkeypatch,
    ):
        """Deterministic injection at the exact check-to-use window:
        the attacker's dir->symlink swap lands after annotation_path's
        resolve check but before the write — emulated by swapping
        inside the lock acquisition. The under-lock re-verification
        must refuse; pre-fix the rename landed outside the base."""
        import os
        import shutil
        import core.annotations.storage as storage
        base = tmp_path / "base"
        (base / "src").mkdir(parents=True)
        redirect = tmp_path / "redirect_target"
        redirect.mkdir()
        real_lock = storage._file_lock

        from contextlib import contextmanager

        @contextmanager
        def swapping_lock(path):
            with real_lock(path):
                shutil.rmtree(base / "src")
                os.symlink(redirect, base / "src")
                yield

        monkeypatch.setattr(storage, "_file_lock", swapping_lock)
        with pytest.raises(ValueError, match="escaped base"):
            write_annotation(base, Annotation(
                file="src/y.py", function="f", body="x",
            ))
        assert not (redirect / "y.py.md").exists()


class TestLockSymlinkDefence:
    def test_lock_path_symlink_refused(self, tmp_path):
        """A symlink squatted at the predictable ``.md.lock`` sibling
        must fail loudly (ELOOP via O_NOFOLLOW), not be followed."""
        import sys
        if sys.platform == "win32":  # pragma: no cover
            pytest.skip("fcntl locking is POSIX-only")

        base = tmp_path / "annotations"
        base.mkdir()
        victim = tmp_path / "victim"
        victim.write_text("untouched")
        (base / "foo.py.md.lock").symlink_to(victim)

        ann = Annotation(file="foo.py", function="f", body="note")
        with pytest.raises(OSError):
            write_annotation(base, ann)
        assert victim.read_text() == "untouched"


# ---------------------------------------------------------------------------
# Body splice primitives (regression: \r body forged human-grade sections)
# ---------------------------------------------------------------------------


class TestLockPermissions:
    """flock needs no write permission; the lock open must not.
    (The genuine two-UID shared-group tree is not constructible in a
    single-uid test run; chmod on the caller's own lock file pins the
    open-mode mechanism and the failure shape.)"""

    def test_read_only_lock_file_does_not_block_writes(self, tmp_path):
        import os
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="x",
        ))
        lock = tmp_path / "a.py.md.lock"
        os.chmod(lock, 0o400)
        try:
            assert write_annotation(tmp_path, Annotation(
                file="a.py", function="g", body="y",
            )) is not None
        finally:
            os.chmod(lock, 0o600)
        assert len(read_file_annotations(tmp_path, "a.py")) == 2

    @pytest.mark.skipif(
        os.geteuid() == 0, reason="root bypasses file permissions",
    )
    def test_unreadable_lock_file_fails_with_clear_error(self, tmp_path):
        import os as _os
        from core.annotations import AnnotationFileError
        write_annotation(tmp_path, Annotation(
            file="a.py", function="f", body="x",
        ))
        lock = tmp_path / "a.py.md.lock"
        _os.chmod(lock, 0o000)
        try:
            with pytest.raises(AnnotationFileError, match="lock file"):
                write_annotation(tmp_path, Annotation(
                    file="a.py", function="g", body="y",
                ))
        finally:
            _os.chmod(lock, 0o600)

    def test_fresh_lock_file_is_group_and_world_readable(self, tmp_path):
        import os, stat
        old_umask = os.umask(0)
        try:
            write_annotation(tmp_path, Annotation(
                file="a.py", function="f", body="x",
            ))
        finally:
            os.umask(old_umask)
        mode = stat.S_IMODE((tmp_path / "a.py.md.lock").stat().st_mode)
        # Modulo the honoured umask, the creation mode must allow
        # other writers' read-open (the cross-UID two-operator
        # scenario the module documents).
        assert mode & 0o044 == 0o044


class TestBodySplicePrimitives:
    r"""A ``\r``-spliced body passed the ``\n``-anchored forged-structure
    regexes, landed raw on disk, and ``read_text()``'s universal-newline
    translation turned it into a real ``## victim`` section carrying
    ``source=human provenance=interactive-tty`` — a human-graded forgery
    through the sanctioned write path. Every character that any reader
    layer treats as a line break must be either normalised to ``\n``
    before validation (``\r``) or refused outright."""

    _FORGED_TAIL = (
        "## victim\n"
        "<!-- meta: source=human provenance=interactive-tty tty=stdin -->"
    )

    def test_cr_spliced_human_section_rejected(self, tmp_path):
        """The exact PoC: bare-\\r separators around a forged section."""
        payload = (
            "legit\r## victim\r"
            "<!-- meta: source=human provenance=interactive-tty tty=stdin -->"
        )
        with pytest.raises(ValueError):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="real", body=payload,
                metadata={"source": "agent"},
            ))
        # Nothing forged on disk, and no human-grade section parses back.
        from core.annotations import is_human_grade
        path = tmp_path / "a.py.md"
        assert not path.exists()
        for ann in read_file_annotations(tmp_path, "a.py"):
            assert not is_human_grade(ann.metadata)

    def test_crlf_spliced_section_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="section heading"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="real",
                body="x\r\n" + self._FORGED_TAIL,
            ))

    def test_cr_spliced_meta_comment_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="meta"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="real",
                body="x\r<!-- meta: source=human -->",
            ))

    @pytest.mark.parametrize("ch", [
        "\x00",     # NUL
        "\x0b",     # \v vertical tab       (str.splitlines boundary)
        "\x0c",     # \f form feed          (str.splitlines boundary)
        "\x1c",     # file separator        (str.splitlines boundary)
        "\x1d",     # group separator       (str.splitlines boundary)
        "\x1e",     # record separator      (str.splitlines boundary)
        "\x85",     # NEL                   (str.splitlines boundary)
        "\u2028",   # line separator        (str.splitlines boundary)
        "\u2029",   # paragraph separator   (str.splitlines boundary)
    ])
    def test_exotic_line_separator_in_body_rejected(self, tmp_path, ch):
        """Inert for today's regex parser, but a live splice for any
        splitlines()-based reader — refused outright (no legitimate
        prose contains them)."""
        with pytest.raises(ValueError, match="line-separator|control"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="real",
                body=f"x{ch}" + self._FORGED_TAIL.replace("\n", ch),
            ))
        with pytest.raises(ValueError, match="line-separator|control"):
            # The bare character is refused even without forged content.
            write_annotation(tmp_path, Annotation(
                file="a.py", function="real", body=f"a{ch}b",
            ))
        assert not (tmp_path / "a.py.md").exists()

    def test_body_starting_with_heading_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="section heading"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="real", body="## victim at pos 0",
            ))

    def test_meta_comment_split_across_lines_rejected(self, tmp_path):
        """``<!--`` at line start with ``meta:`` on the next line still
        matches the on-disk meta regex (its ``\\s*`` crosses newlines) —
        the write-side check must keep catching that shape."""
        with pytest.raises(ValueError, match="meta"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="real",
                body="x\n<!--\nmeta: source=human -->",
            ))

    def test_legit_crlf_prose_normalised_and_preserved(self, tmp_path):
        """Pasted CRLF prose is legitimate: stored with \\n line breaks
        (what read_text() would produce anyway), one section only."""
        write_annotation(tmp_path, Annotation(
            file="a.py", function="real",
            body="line one\r\nline two\r\n\r\nlast",
        ))
        anns = read_file_annotations(tmp_path, "a.py")
        assert len(anns) == 1
        assert anns[0].body == "line one\nline two\n\nlast"
        # No raw \r survives to disk — the read/parse layers would
        # otherwise disagree about where lines start.
        raw = annotation_path(tmp_path, "a.py").read_bytes()
        assert b"\r" not in raw

    @pytest.mark.parametrize("ch", ["\x0b", "\x85", "\u2028"])
    def test_exotic_separator_in_function_name_rejected(self, tmp_path, ch):
        with pytest.raises(ValueError, match="line-separator"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function=f"real{ch}## forged", body="x",
            ))

    @pytest.mark.parametrize("ch", ["\x0b", "\x85", "\u2028"])
    def test_exotic_separator_in_metadata_value_rejected(self, tmp_path, ch):
        with pytest.raises(ValueError, match="line-separator"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function="real",
                metadata={"note": f"v{ch}forged"},
            ))


class TestFunctionNameNormalisation:
    """NFC/NFD twin names are byte-distinct but visually identical:
    two sections no operator can tell apart, and byte-exact joins
    (respect-manual included) miss the twin."""

    def _twins(self):
        import unicodedata
        return (
            unicodedata.normalize("NFC", "caf\u00e9"),
            unicodedata.normalize("NFD", "caf\u00e9"),
        )

    def test_non_nfc_function_name_rejected(self, tmp_path):
        nfc, nfd = self._twins()
        assert nfc != nfd
        with pytest.raises(ValueError, match="NFC"):
            write_annotation(tmp_path, Annotation(
                file="a.py", function=nfd, body="x",
            ))
        assert not (tmp_path / "a.py.md").exists()

    def test_nfc_name_accepted_and_round_trips(self, tmp_path):
        nfc, _ = self._twins()
        write_annotation(tmp_path, Annotation(
            file="a.py", function=nfc, body="x",
        ))
        assert read_annotation(tmp_path, "a.py", nfc) is not None

    def test_respect_manual_covers_legacy_nfd_twin(self, tmp_path):
        # A hand-written (pre-validation) NFD section with a human
        # note: a scripted NFC add with respect-manual must treat the
        # visually identical twin as the prior record and skip.
        nfc, nfd = self._twins()
        path = annotation_path(tmp_path, "b.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"<!-- annotations-version: 1 -->\n# b.py\n\n"
            f"## {nfd}\n<!-- meta: source=human -->\n\noperator note\n",
        )
        res = write_annotation(tmp_path, Annotation(
            file="b.py", function=nfc, body="agent",
            metadata={"source": "agent"},
        ), overwrite="respect-manual")
        assert res is None
        text = path.read_text()
        assert "operator note" in text
        assert text.count("## ") == 1


class TestFunctionNameEdgeWhitespace:
    """``"victim "`` passes a containment-only validator, but the
    heading parser strips the captured name — the stored section
    re-parses as ``victim`` and collides with the real one, so a later
    rewrite (dict-keyed on parsed names) silently replaces the human
    record with the agent one. Edge whitespace must be rejected at
    validation: validated == parsed."""

    @pytest.mark.parametrize("name", [
        "victim ", " victim", "victim\t", "\tvictim", "  victim  ",
    ])
    def test_edge_whitespace_function_name_rejected(self, tmp_path, name):
        with pytest.raises(ValueError, match="whitespace"):
            write_annotation(tmp_path, Annotation(
                file="x.py", function=name, body="x",
            ))
        assert not (tmp_path / "x.py.md").exists()

    def test_respect_manual_not_bypassed_by_trailing_space(self, tmp_path):
        """The reviewer repro: human note for ``victim``; a
        respect-manual add for ``victim `` found no prior (names
        compared pre-strip), wrote a colliding section, and the next
        rewrite resolved the collision in the agent record's favour."""
        from core.annotations import is_human_grade
        write_annotation(tmp_path, Annotation(
            file="x.py", function="victim", body="operator note",
            metadata={"source": "human", "provenance": "interactive-tty",
                      "tty": "stdin", "sid": "inherited",
                      "envm": "trusted", "parents": "bash"},
        ))
        with pytest.raises(ValueError, match="whitespace"):
            write_annotation(tmp_path, Annotation(
                file="x.py", function="victim ", body="agent note",
                metadata={"source": "agent"},
            ), overwrite="respect-manual")
        # Human note intact and unique — and it survives a subsequent
        # legitimate rewrite of the file (the collision step of the
        # original repro).
        write_annotation(tmp_path, Annotation(
            file="x.py", function="unrelated", body="y",
        ))
        anns = read_file_annotations(tmp_path, "x.py")
        victims = [a for a in anns if a.function == "victim"]
        assert len(victims) == 1
        assert victims[0].body == "operator note"
        assert is_human_grade(victims[0].metadata)


# ---------------------------------------------------------------------------
# Corrupt existing file: writes fail closed (regression: silent data loss)
# ---------------------------------------------------------------------------


class TestOutOfSectionPreservation:
    """The format is advertised as operator-editable markdown, so
    hand-added file-level prose (outside ``##`` sections) is invited
    input. Every rewrite used to re-render from sections only and
    silently destroy it; it must round-trip instead."""

    def _seed_with_preamble(self, tmp_path, prose):
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="existing_fn", body="note",
            metadata={"source": "human"},
        ))
        path = annotation_path(tmp_path, "src/foo.py")
        lines = path.read_text().splitlines(keepends=True)
        lines.insert(2, prose + "\n")
        path.write_text("".join(lines))
        return path

    def test_preamble_survives_sibling_add(self, tmp_path):
        prose = "OPERATOR FILE-LEVEL NOTE: pentested; do not re-scan."
        path = self._seed_with_preamble(tmp_path, prose)
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="other_fn", body="agent note",
            metadata={"source": "agent"},
        ))
        text = path.read_text()
        assert prose in text
        assert "## existing_fn" in text and "## other_fn" in text
        # Round-trip is stable: another rewrite neither drops nor
        # duplicates the preserved prose.
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="third_fn", body="x",
        ))
        assert path.read_text().count(prose) == 1

    def test_multiline_preamble_with_blanks_round_trips(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="f", body="note",
        ))
        path = annotation_path(tmp_path, "src/foo.py")
        lines = path.read_text().splitlines(keepends=True)
        lines[3:3] = ["para one\n", "\n", "para two\n", "\n"]
        path.write_text("".join(lines))
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="g", body="x",
        ))
        text = path.read_text()
        assert "para one\n\npara two" in text

    def test_preamble_survives_remove(self, tmp_path):
        prose = "file-level operator paragraph"
        path = self._seed_with_preamble(tmp_path, prose)
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="other_fn", body="x",
        ))
        assert remove_annotation(tmp_path, "src/foo.py", "other_fn")
        assert prose in path.read_text()

    def test_remove_last_annotation_keeps_preserved_prose(self, tmp_path):
        prose = "keep me"
        path = self._seed_with_preamble(tmp_path, prose)
        assert remove_annotation(tmp_path, "src/foo.py", "existing_fn")
        assert path.exists()
        text = path.read_text()
        assert prose in text
        assert "## " not in text
        # No circularity: the marker-bearing section-less file takes
        # a subsequent add, still preserving the prose.
        assert write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="fresh", body="y",
        )) is not None
        text = path.read_text()
        assert prose in text and "## fresh" in text

    def test_remove_last_annotation_without_prose_still_unlinks(
        self, tmp_path,
    ):
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="f", body="x",
        ))
        path = annotation_path(tmp_path, "src/foo.py")
        assert remove_annotation(tmp_path, "src/foo.py", "f")
        assert not path.exists()

    def test_comment_between_sections_survives_as_body(self, tmp_path):
        path = annotation_path(tmp_path, "d.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "<!-- annotations-version: 1 -->\n# d.py\n\n"
            "## a\n\nbody a\n\n<!-- operator: checked -->\n\n"
            "## b\n\nbody b\n\ntrailing operator paragraph\n",
        )
        write_annotation(tmp_path, Annotation(
            file="d.py", function="c", body="x",
        ))
        text = path.read_text()
        assert "<!-- operator: checked -->" in text
        assert "trailing operator paragraph" in text

    def test_crlf_file_with_preamble_round_trips(self, tmp_path):
        path = annotation_path(tmp_path, "e.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            b"<!-- annotations-version: 1 -->\r\n# e.py\r\n\r\n"
            b"preamble prose\r\n\r\n## f\r\n\r\nthe body\r\n",
        )
        write_annotation(tmp_path, Annotation(
            file="e.py", function="g", body="y",
        ))
        text = path.read_text()
        assert "preamble prose" in text
        assert "the body" in text

    def test_zero_section_marker_bearing_file_content_preserved(
        self, tmp_path,
    ):
        # A marker attests writer ownership (a remove-last rewrite
        # leaves exactly this shape), so the content is preamble and
        # round-trips instead of refusing.
        path = annotation_path(tmp_path, "f.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "<!-- annotations-version: 1 -->\n# f.py\n\n"
            "hand-written operator prose\n",
        )
        assert write_annotation(tmp_path, Annotation(
            file="f.py", function="fn", body="x",
        )) is not None
        text = path.read_text()
        assert "hand-written operator prose" in text
        assert "## fn" in text

    def test_zero_section_hash_prose_file_refuses(self, tmp_path):
        """Arm B: '# '-prefixed prose used to be skipped by the
        accounting gate (any '# ' line counted as the label), so the
        file was judged empty and REPLACED. Only the exact
        '# <source_file>' label is renderer-owned; anything else in
        an unmarked zero-section file is unattributable."""
        from core.annotations import AnnotationFileError
        path = annotation_path(tmp_path, "src/bar.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (
            "# review notes for src/bar.py\n"
            "# check the auth flow again\n"
        )
        path.write_text(content)
        with pytest.raises(AnnotationFileError):
            write_annotation(tmp_path, Annotation(
                file="src/bar.py", function="fn", body="x",
            ))
        assert path.read_text() == content


class TestCorruptFileWritesFailClosed:
    """A corrupt/unreadable annotation file used to read as EMPTY
    inside the read-modify-write cycle, so the next add re-rendered
    only the new record and atomically replaced the file — one stray
    non-UTF-8 byte silently destroyed every operator note in it, and
    ``respect-manual`` failed open. Writes must refuse instead,
    leaving the original bytes untouched for inspection."""

    def _seed_human_note(self, tmp_path):
        from core.annotations import AnnotationFileError  # noqa: F401
        write_annotation(tmp_path, Annotation(
            file="b.py", function="op_note", body="operator note",
            metadata={"source": "human", "provenance": "interactive-tty",
                      "tty": "stdin"},
        ))
        return annotation_path(tmp_path, "b.py")

    def test_binary_garbage_refuses_add_and_preserves_bytes(self, tmp_path):
        from core.annotations import AnnotationFileError
        path = self._seed_human_note(tmp_path)
        corrupted = path.read_bytes() + b"\xff\xfe"
        path.write_bytes(corrupted)
        with pytest.raises(AnnotationFileError):
            write_annotation(tmp_path, Annotation(
                file="b.py", function="other_fn", body="agent note",
                metadata={"source": "agent"},
            ))
        assert path.read_bytes() == corrupted

    def test_respect_manual_fails_closed_on_corrupt_file(self, tmp_path):
        """The exact repro: one invalid byte, then a respect-manual add
        of a DIFFERENT function wiped the human note without warning."""
        from core.annotations import AnnotationFileError
        path = self._seed_human_note(tmp_path)
        corrupted = path.read_bytes() + b"\xff\xfe"
        path.write_bytes(corrupted)
        with pytest.raises(AnnotationFileError):
            write_annotation(tmp_path, Annotation(
                file="b.py", function="other_fn", body="agent note",
                metadata={"source": "agent"},
            ), overwrite="respect-manual")
        assert path.read_bytes() == corrupted

    def test_truncated_file_refuses_add(self, tmp_path):
        """ASCII-boundary truncation still decodes but parses to zero
        sections — content we cannot account for must not be replaced."""
        from core.annotations import AnnotationFileError
        path = self._seed_human_note(tmp_path)
        truncated = path.read_bytes()[:20]
        path.write_bytes(truncated)
        with pytest.raises(AnnotationFileError):
            write_annotation(tmp_path, Annotation(
                file="b.py", function="other_fn", body="x",
            ))
        assert path.read_bytes() == truncated

    @pytest.mark.skipif(
        os.geteuid() == 0, reason="root bypasses file permissions",
    )
    def test_permission_denied_refuses_add(self, tmp_path):
        from core.annotations import AnnotationFileError
        path = self._seed_human_note(tmp_path)
        original = path.read_bytes()
        path.chmod(0o000)
        try:
            with pytest.raises(AnnotationFileError):
                write_annotation(tmp_path, Annotation(
                    file="b.py", function="other_fn", body="x",
                ))
        finally:
            path.chmod(0o644)
        assert path.read_bytes() == original

    def test_future_format_version_refuses_add(self, tmp_path):
        """Rewriting a future-version file with this writer's renderer
        could destroy structure this parser cannot see."""
        from core.annotations import AnnotationFileError
        path = annotation_path(tmp_path, "b.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (
            "<!-- annotations-version: 99 -->\n# b.py\n\n"
            "## f\n<!-- meta: source=human -->\n\nnote\n"
        )
        path.write_text(content)
        with pytest.raises(AnnotationFileError):
            write_annotation(tmp_path, Annotation(
                file="b.py", function="g", body="x",
            ))
        assert path.read_text() == content
        # The permissive read path still parses it (warn-and-try).
        assert len(read_file_annotations(tmp_path, "b.py")) == 1

    def test_prose_only_file_refuses_add(self, tmp_path):
        """Decodable text with zero ## sections is unattributable —
        a rewrite would drop it wholesale."""
        from core.annotations import AnnotationFileError
        path = annotation_path(tmp_path, "b.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("hand-written operator prose, no sections\n")
        with pytest.raises(AnnotationFileError):
            write_annotation(tmp_path, Annotation(
                file="b.py", function="f", body="x",
            ))

    def test_remove_refuses_on_corrupt_file(self, tmp_path):
        from core.annotations import AnnotationFileError
        path = self._seed_human_note(tmp_path)
        corrupted = path.read_bytes() + b"\xff\xfe"
        path.write_bytes(corrupted)
        with pytest.raises(AnnotationFileError):
            remove_annotation(tmp_path, "b.py", "op_note")
        assert path.read_bytes() == corrupted

    def test_fresh_file_add_succeeds(self, tmp_path):
        assert write_annotation(tmp_path, Annotation(
            file="new.py", function="f", body="x",
        )) is not None

    def test_empty_file_add_succeeds(self, tmp_path):
        path = annotation_path(tmp_path, "b.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
        assert write_annotation(tmp_path, Annotation(
            file="b.py", function="f", body="x",
        )) is not None
        assert len(read_file_annotations(tmp_path, "b.py")) == 1

    def test_header_only_file_add_succeeds(self, tmp_path):
        """Version marker + label heading is fully accounted for —
        nothing an add could destroy."""
        path = annotation_path(tmp_path, "b.py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("<!-- annotations-version: 1 -->\n# b.py\n\n")
        assert write_annotation(tmp_path, Annotation(
            file="b.py", function="f", body="x",
        )) is not None

    def test_nonstrict_read_still_degrades_to_empty(self, tmp_path):
        """Read-only consumers keep the tolerant contract — one bad
        file must not block iter_all_annotations over the tree."""
        path = self._seed_human_note(tmp_path)
        path.write_bytes(b"\xff\xfe garbage")
        assert read_file_annotations(tmp_path, "b.py") == []
        assert list(iter_all_annotations(tmp_path)) == []


class TestMetaLineWhitespaceRun:
    def test_meta_line_whitespace_run_is_fast(self):
        """Hostile annotation-file line opening ``<!-- meta:`` and
        ending in a long whitespace run with no ``-->``: with the body
        spelled ``\\s*(.*?)\\s*-->`` three unbounded repeats overlap on
        horizontal whitespace and the engine tries every split of the
        run between them — cubic in the line length. The
        ``\\S``-delimited body spelling is linear. Both-direction
        bound: fast AND real meta lines still parse."""
        from core.annotations.storage import _META_RE
        from core.testing.wallclock import cpu_budget

        hostile = "<!-- meta:" + " " * (1 << 16) + "x"
        with cpu_budget(1.0, what="meta-line whitespace-run scan"):
            assert _META_RE.match(hostile) is None

    def test_meta_line_forms_still_parse(self):
        from core.annotations.storage import _META_RE, _parse_meta

        m = _META_RE.match('<!-- meta: status=clean cwe="CWE-78" -->')
        assert m is not None
        assert _parse_meta(m.group(1) or "") == {
            "status": "clean", "cwe": "CWE-78",
        }
        # Trimming semantics unchanged.
        m = _META_RE.match("<!--   meta:   status=clean   -->  ")
        assert m is not None
        assert m.group(1) == "status=clean"
        # All-whitespace body parses as empty metadata (group None).
        m = _META_RE.match("<!-- meta:   -->")
        assert m is not None
        assert _parse_meta(m.group(1) or "") == {}
        assert _META_RE.match("<!-- other: x -->") is None

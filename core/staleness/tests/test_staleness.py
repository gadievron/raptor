"""Tests for core.staleness — shared span-level staleness detection."""

from __future__ import annotations

import os
from pathlib import Path

from core.staleness import (
    CheckItem,
    Span,
    check_batch,
    check_spans,
    hash_span,
    hash_spans,
    norm_hash,
    normalize_source,
)


# -------------------------------------------------------------------
# hash_span (single)
# -------------------------------------------------------------------

class TestHashSpan:
    def test_basic(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("int x = 1;\nint y = 2;\nint z = 3;\n")
        h = hash_span(f, 1, 3)
        assert len(h) == 12
        assert h == hash_span(f, 1, 3)

    def test_different_range_different_hash(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("int x = 1;\nint y = 2;\nint z = 3;\n")
        assert hash_span(f, 1, 1) != hash_span(f, 2, 2)

    def test_missing_file(self, tmp_path: Path):
        assert hash_span(tmp_path / "gone.c", 1, 5) == ""

    def test_invalid_range_zero(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("line\n")
        assert hash_span(f, 0, 1) == ""

    def test_invalid_range_reversed(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("line\n")
        assert hash_span(f, 5, 2) == ""

    def test_range_past_eof_clamps(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("line1\nline2\n")
        h1 = hash_span(f, 1, 2)
        h2 = hash_span(f, 1, 999)
        assert h1 == h2

    def test_non_utf8_tolerated(self, tmp_path: Path):
        f = tmp_path / "bin.c"
        f.write_bytes(b"int x = 0xff\xff;\n")
        h = hash_span(f, 1, 1)
        assert len(h) == 12

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.c"
        f.write_text("")
        assert hash_span(f, 1, 1) == ""


# -------------------------------------------------------------------
# hash_spans (batched)
# -------------------------------------------------------------------

class TestHashSpans:
    def test_multiple_spans_single_read(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("int a;\nint b;\nint c;\nint d;\n")
        results = hash_spans(f, [(1, 2), (3, 4), (1, 4)])
        assert len(results) == 3
        assert all(len(h) == 12 for h in results)
        assert results[0] != results[1]

    def test_matches_individual_calls(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("int a;\nint b;\nint c;\n")
        batched = hash_spans(f, [(1, 1), (2, 2), (3, 3)])
        individual = [hash_span(f, s, e) for s, e in [(1, 1), (2, 2), (3, 3)]]
        assert batched == individual

    def test_missing_file_all_empty(self, tmp_path: Path):
        results = hash_spans(tmp_path / "gone.c", [(1, 2), (3, 4)])
        assert results == ["", ""]

    def test_invalid_span_in_batch(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("line1\nline2\n")
        results = hash_spans(f, [(1, 1), (0, 1), (5, 3)])
        assert len(results[0]) == 12
        assert results[1] == ""
        assert results[2] == ""

    def test_empty_spans_list(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("line\n")
        assert hash_spans(f, []) == []


# -------------------------------------------------------------------
# check_spans (single file)
# -------------------------------------------------------------------

class TestCheckSpans:
    def test_current(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("int x = 1;\n")
        h = hash_span(f, 1, 1)
        results = check_spans(f, [Span(1, 1, h, "x")])
        assert len(results) == 1
        assert results[0].status == "current"
        assert results[0].span.label == "x"

    def test_modified(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("int x = 1;\n")
        old_hash = hash_span(f, 1, 1)
        f.write_text("int x = 99;\n")
        results = check_spans(f, [Span(1, 1, old_hash)])
        assert results[0].status == "modified"
        assert results[0].current_hash != old_hash

    def test_deleted_file(self, tmp_path: Path):
        results = check_spans(
            tmp_path / "gone.c",
            [Span(1, 5, "abc123def456")],
        )
        assert results[0].status == "deleted"

    def test_no_stored_hash(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("int x;\n")
        results = check_spans(f, [Span(1, 1, "")])
        assert results[0].status == "unknown"
        assert results[0].current_hash != ""

    def test_multiple_spans_mixed(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("int a;\nint b;\nint c;\n")
        h_a = hash_span(f, 1, 1)
        h_b = hash_span(f, 2, 2)
        f.write_text("int a;\nint B;\nint c;\n")
        results = check_spans(f, [
            Span(1, 1, h_a, "a"),
            Span(2, 2, h_b, "b"),
        ])
        assert results[0].status == "current"
        assert results[1].status == "modified"


# -------------------------------------------------------------------
# check_batch (cross-file)
# -------------------------------------------------------------------

class TestCheckBatch:
    def test_groups_by_file(self, tmp_path: Path):
        f1 = tmp_path / "a.c"
        f2 = tmp_path / "b.c"
        f1.write_text("int a;\n")
        f2.write_text("int b;\n")
        h1 = hash_span(f1, 1, 1)
        h2 = hash_span(f2, 1, 1)
        results = check_batch([
            CheckItem(f1, 1, 1, h1, "a"),
            CheckItem(f2, 1, 1, h2, "b"),
        ])
        assert all(r.status == "current" for r in results)

    def test_order_preserved(self, tmp_path: Path):
        f = tmp_path / "a.c"
        f.write_text("line1\nline2\nline3\n")
        h1 = hash_span(f, 1, 1)
        h3 = hash_span(f, 3, 3)
        f.write_text("line1\nLINE2\nline3\n")
        results = check_batch([
            CheckItem(f, 1, 1, h1, "first"),
            CheckItem(f, 3, 3, h3, "third"),
        ])
        assert results[0].status == "current"
        assert results[0].span.label == "first"
        assert results[1].status == "current"
        assert results[1].span.label == "third"

    def test_deleted_and_current_mixed(self, tmp_path: Path):
        f1 = tmp_path / "exists.c"
        f1.write_text("int x;\n")
        h = hash_span(f1, 1, 1)
        results = check_batch([
            CheckItem(f1, 1, 1, h, "exists"),
            CheckItem(tmp_path / "gone.c", 1, 1, "abc", "gone"),
        ])
        assert results[0].status == "current"
        assert results[1].status == "deleted"

    def test_many_spans_same_file(self, tmp_path: Path):
        f = tmp_path / "big.c"
        lines = [f"int v{i} = {i};\n" for i in range(100)]
        f.write_text("".join(lines))
        hashes = hash_spans(f, [(i + 1, i + 1) for i in range(100)])
        items = [
            CheckItem(f, i + 1, i + 1, hashes[i], f"v{i}")
            for i in range(100)
        ]
        results = check_batch(items)
        assert all(r.status == "current" for r in results)

    def test_empty_batch(self):
        assert check_batch([]) == []

    def test_interleaved_files_order_preserved(self, tmp_path: Path):
        """Items from multiple files interleaved — results match input order."""
        f1 = tmp_path / "a.c"
        f2 = tmp_path / "b.c"
        f1.write_text("int a1;\nint a2;\n")
        f2.write_text("int b1;\nint b2;\n")
        h_a1 = hash_span(f1, 1, 1)
        h_b1 = hash_span(f2, 1, 1)
        h_a2 = hash_span(f1, 2, 2)
        items = [
            CheckItem(f1, 1, 1, h_a1, "a1"),
            CheckItem(f2, 1, 1, h_b1, "b1"),
            CheckItem(f1, 2, 2, h_a2, "a2"),
        ]
        results = check_batch(items)
        assert [r.span.label for r in results] == ["a1", "b1", "a2"]
        assert all(r.status == "current" for r in results)


# -------------------------------------------------------------------
# Cosmetic detection
# -------------------------------------------------------------------

class TestCosmeticDetection:
    def test_cosmetic_status_emitted(self, tmp_path: Path):
        """When stored_norm_hash matches current norm hash, status is 'cosmetic'."""
        f = tmp_path / "a.py"
        f.write_text("# old comment\ndef foo():\n    return 1\n")
        old_hash = hash_span(f, 1, 3)
        old_norm = norm_hash("# old comment\ndef foo():\n    return 1", "a.py")
        f.write_text("# new comment\ndef foo():\n    return 1\n")

        results = check_spans(
            f,
            [Span(1, 3, old_hash, "foo", stored_norm_hash=old_norm)],
            cosmetic=True,
        )
        assert results[0].status == "cosmetic"
        assert results[0].current_norm_hash == old_norm

    def test_real_change_stays_modified(self, tmp_path: Path):
        """Real code change: norm hashes differ, status is 'modified'."""
        f = tmp_path / "a.py"
        f.write_text("def foo():\n    return 1\n")
        old_hash = hash_span(f, 1, 2)
        old_norm = norm_hash("def foo():\n    return 1", "a.py")
        f.write_text("def foo():\n    return 2\n")

        results = check_spans(
            f,
            [Span(1, 2, old_hash, stored_norm_hash=old_norm)],
            cosmetic=True,
        )
        assert results[0].status == "modified"
        assert results[0].current_norm_hash != old_norm

    def test_no_stored_norm_hash_stays_modified(self, tmp_path: Path):
        """Without stored_norm_hash, cosmetic detection cannot fire."""
        f = tmp_path / "a.py"
        f.write_text("# comment\ndef foo():\n    return 1\n")
        old_hash = hash_span(f, 1, 3)
        f.write_text("# changed\ndef foo():\n    return 1\n")

        results = check_spans(
            f, [Span(1, 3, old_hash)], cosmetic=True,
        )
        assert results[0].status == "modified"
        assert results[0].current_norm_hash != ""

    def test_cosmetic_false_no_norm_hash_computed(self, tmp_path: Path):
        """With cosmetic=False, no norm hash is computed."""
        f = tmp_path / "a.py"
        f.write_text("# comment\ndef foo():\n    return 1\n")
        old_hash = hash_span(f, 1, 3)
        f.write_text("# changed\ndef foo():\n    return 1\n")

        results = check_spans(
            f, [Span(1, 3, old_hash)], cosmetic=False,
        )
        assert results[0].status == "modified"
        assert results[0].current_norm_hash == ""

    def test_cosmetic_via_check_batch(self, tmp_path: Path):
        """Cosmetic detection works through check_batch with stored_norm_hash."""
        f = tmp_path / "a.c"
        f.write_text("// old\nint x = 1;\n")
        old_hash = hash_span(f, 1, 2)
        old_norm = norm_hash("// old\nint x = 1;", "a.c")
        f.write_text("// new\nint x = 1;\n")

        results = check_batch(
            [CheckItem(f, 1, 2, old_hash, "x", stored_norm_hash=old_norm)],
            cosmetic=True,
        )
        assert results[0].status == "cosmetic"


# -------------------------------------------------------------------
# Path traversal protection
# -------------------------------------------------------------------

class TestPathTraversal:
    def test_root_rejects_escape(self, tmp_path: Path):
        """CheckItem outside root gets status 'unknown'."""
        root = tmp_path / "project"
        root.mkdir()
        outside = tmp_path / "outside.c"
        outside.write_text("int x;\n")

        results = check_batch(
            [CheckItem(outside, 1, 1, "abc", "escape")],
            root=root,
        )
        assert results[0].status == "unknown"

    def test_root_allows_inside(self, tmp_path: Path):
        """CheckItem inside root proceeds normally."""
        root = tmp_path / "project"
        root.mkdir()
        f = root / "a.c"
        f.write_text("int x;\n")
        h = hash_span(f, 1, 1)

        results = check_batch(
            [CheckItem(f, 1, 1, h, "inside")],
            root=root,
        )
        assert results[0].status == "current"

    def test_root_rejects_dotdot(self, tmp_path: Path):
        """Path with .. that escapes root is rejected."""
        root = tmp_path / "project"
        root.mkdir()
        f = root / ".." / "escape.c"

        results = check_batch(
            [CheckItem(f, 1, 1, "abc", "dotdot")],
            root=root,
        )
        assert results[0].status == "unknown"

    def test_no_root_allows_any_path(self, tmp_path: Path):
        """Without root, any path is accepted (backward compat)."""
        f = tmp_path / "a.c"
        f.write_text("int x;\n")
        h = hash_span(f, 1, 1)

        results = check_batch([CheckItem(f, 1, 1, h, "x")])
        assert results[0].status == "current"

    def test_root_via_check_spans(self, tmp_path: Path):
        """root parameter propagates through check_spans."""
        root = tmp_path / "project"
        root.mkdir()
        outside = tmp_path / "outside.c"
        outside.write_text("int x;\n")

        results = check_spans(
            outside, [Span(1, 1, "abc")], root=root,
        )
        assert results[0].status == "unknown"


# -------------------------------------------------------------------
# Permission / edge cases
# -------------------------------------------------------------------

class TestEdgeCases:
    def test_unreadable_file(self, tmp_path: Path):
        """File exists but is not readable."""
        f = tmp_path / "locked.c"
        f.write_text("int x;\n")
        os.chmod(f, 0o000)
        try:
            results = check_batch([CheckItem(f, 1, 1, "abc", "locked")])
            assert results[0].status == "unknown"
        finally:
            os.chmod(f, 0o644)

    def test_empty_file_check(self, tmp_path: Path):
        """Empty file: span 1-1 is unknown (no lines)."""
        f = tmp_path / "empty.c"
        f.write_text("")
        results = check_batch([CheckItem(f, 1, 1, "abc")])
        assert results[0].status == "unknown"

    def test_single_line_file(self, tmp_path: Path):
        f = tmp_path / "one.c"
        f.write_text("int x;\n")
        h = hash_span(f, 1, 1)
        results = check_batch([CheckItem(f, 1, 1, h)])
        assert results[0].status == "current"


# -------------------------------------------------------------------
# normalize_source
# -------------------------------------------------------------------

class TestNormalizeSource:
    def test_python_strips_comments(self):
        src = "# comment\ndef foo():\n    # another\n    return 1\n"
        norm = normalize_source(src, "foo.py")
        assert "comment" not in norm
        assert "def foo():" in norm
        assert "return 1" in norm

    def test_python_keeps_non_comment_hash(self):
        src = "x = d['key']\ny = x  # inline\n"
        norm = normalize_source(src, "foo.py")
        assert "x = d['key']" in norm

    def test_c_strips_line_comments(self):
        src = "int x = 1; // init\nreturn x;\n"
        norm = normalize_source(src, "foo.c")
        assert "init" not in norm
        assert "int x = 1;" in norm

    def test_c_strips_block_comments(self):
        src = "int x = 1;\n/* multi\n   line */\nreturn x;\n"
        norm = normalize_source(src, "foo.c")
        assert "multi" not in norm
        assert "int x = 1;" in norm

    def test_whitespace_collapse(self):
        src = "  def  foo( x ,  y ):  \n    return   x + y  \n\n\n"
        norm = normalize_source(src, "foo.py")
        lines = norm.splitlines()
        assert len(lines) == 2
        assert lines[0] == "def foo( x , y ):"
        assert lines[1] == "return x + y"

    def test_unknown_extension(self):
        src = "  hello  world  \n\n  foo  \n"
        norm = normalize_source(src, "foo.xyz")
        assert norm == "hello world\nfoo"

    def test_java_strips_comments(self):
        src = "// comment\npublic void m() { }\n"
        norm = normalize_source(src, "Foo.java")
        assert "comment" not in norm
        assert "public void m()" in norm

    def test_rust_strips_comments(self):
        src = "// comment\nfn main() { }\n"
        norm = normalize_source(src, "main.rs")
        assert "comment" not in norm
        assert "fn main()" in norm

    def test_hpp_strips_comments(self):
        src = "// comment\nclass Foo {};\n"
        norm = normalize_source(src, "foo.hpp")
        assert "comment" not in norm
        assert "class Foo" in norm

    def test_tsx_strips_comments(self):
        src = "// comment\nconst x = 1;\n"
        norm = normalize_source(src, "app.tsx")
        assert "comment" not in norm
        assert "const x = 1;" in norm

    def test_kotlin_strips_comments(self):
        src = "// comment\nfun main() { }\n"
        norm = normalize_source(src, "Main.kt")
        assert "comment" not in norm
        assert "fun main()" in norm

    def test_swift_strips_comments(self):
        src = "// comment\nfunc main() { }\n"
        norm = normalize_source(src, "main.swift")
        assert "comment" not in norm
        assert "func main()" in norm


class TestNormHash:
    def test_same_code_different_comments(self):
        src1 = "# old\ndef foo():\n    return 1\n"
        src2 = "# new\ndef foo():\n    return 1\n"
        assert norm_hash(src1, "f.py") == norm_hash(src2, "f.py")

    def test_different_code(self):
        src1 = "def foo():\n    return 1\n"
        src2 = "def foo():\n    return 2\n"
        assert norm_hash(src1, "f.py") != norm_hash(src2, "f.py")

    def test_whitespace_only_diff(self):
        src1 = "int x = 1;\nreturn x;\n"
        src2 = "  int  x  =  1;\n    return  x;\n"
        assert norm_hash(src1, "f.c") == norm_hash(src2, "f.c")


# -------------------------------------------------------------------
# Backward compatibility with compute_function_hash
# -------------------------------------------------------------------

class TestBackwardCompat:
    def test_matches_annotation_hash(self, tmp_path: Path):
        """hash_span produces same result as annotations.compute_function_hash."""
        from core.annotations.storage import compute_function_hash

        f = tmp_path / "a.c"
        f.write_text("int check() {\n    return 1;\n}\n")
        assert hash_span(f, 1, 3) == compute_function_hash(f, 1, 3)

    def test_matches_for_edge_cases(self, tmp_path: Path):
        from core.annotations.storage import compute_function_hash

        f = tmp_path / "a.c"
        f.write_text("line1\nline2\n")
        for s, e in [(1, 1), (2, 2), (1, 2), (0, 1), (5, 3), (1, 999)]:
            assert hash_span(f, s, e) == compute_function_hash(f, s, e)

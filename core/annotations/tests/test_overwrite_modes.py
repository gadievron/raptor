"""Tests for overwrite-mode policies on ``write_annotation`` and
the ``compute_function_hash`` staleness helper.

These exercise the substrate features that protect operator-written
annotations from being clobbered by LLM-driven re-runs:

  * ``overwrite="all"`` (default) — current behaviour, always writes.
  * ``overwrite="respect-manual"`` — skip if existing record has
    ``metadata.source == "human"``.

Plus the per-function source-line hash used by ``/annotate stale``:
  * Stable across identical content, distinct across changed content.
  * Tolerates missing files and non-UTF-8 bytes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.annotations import (
    Annotation,
    compute_function_hash,
    read_annotation,
    read_file_annotations,
    write_annotation,
)


# ---------------------------------------------------------------------------
# overwrite="all" (default)
# ---------------------------------------------------------------------------


class TestOverwriteAll:
    def test_default_overwrites_human_source(self, tmp_path):
        """Default mode does NOT inspect ``source`` — operator updating
        their own note expects the new content to land."""
        write_annotation(tmp_path, Annotation(
            file="x.py", function="f", body="manual note",
            metadata={"source": "human"},
        ))
        path = write_annotation(tmp_path, Annotation(
            file="x.py", function="f", body="updated",
            metadata={"source": "human"},
        ))
        assert path is not None
        got = read_annotation(tmp_path, "x.py", "f")
        assert got.body == "updated"

    def test_default_overwrites_llm_source(self, tmp_path):
        """LLM-over-LLM also fine in default mode — re-running
        analysis updates the prose."""
        write_annotation(tmp_path, Annotation(
            file="x.py", function="f", body="first run",
            metadata={"source": "llm"},
        ))
        write_annotation(tmp_path, Annotation(
            file="x.py", function="f", body="second run",
            metadata={"source": "llm"},
        ))
        got = read_annotation(tmp_path, "x.py", "f")
        assert got.body == "second run"

    def test_default_explicit_value_returns_path(self, tmp_path):
        path = write_annotation(
            tmp_path,
            Annotation(file="x.py", function="f", body="x"),
            overwrite="all",
        )
        assert path is not None
        assert path.exists()


# ---------------------------------------------------------------------------
# overwrite="respect-manual"
# ---------------------------------------------------------------------------


class TestRespectManual:
    def test_skips_when_existing_is_human(self, tmp_path):
        """LLM pass must not clobber a manual annotation."""
        write_annotation(tmp_path, Annotation(
            file="x.py", function="f",
            body="operator wrote this — important context",
            metadata={"source": "human", "status": "finding"},
        ))
        result = write_annotation(
            tmp_path,
            Annotation(
                file="x.py", function="f",
                body="LLM ran later and tried to overwrite",
                metadata={"source": "llm", "status": "clean"},
            ),
            overwrite="respect-manual",
        )
        assert result is None
        # Manual content is intact.
        got = read_annotation(tmp_path, "x.py", "f")
        assert "operator wrote this" in got.body
        assert got.metadata["status"] == "finding"

    def test_writes_when_existing_is_llm(self, tmp_path):
        """LLM-over-LLM proceeds — no operator content to protect."""
        write_annotation(tmp_path, Annotation(
            file="x.py", function="f", body="prior llm",
            metadata={"source": "llm"},
        ))
        result = write_annotation(
            tmp_path,
            Annotation(
                file="x.py", function="f", body="new llm",
                metadata={"source": "llm"},
            ),
            overwrite="respect-manual",
        )
        assert result is not None
        got = read_annotation(tmp_path, "x.py", "f")
        assert got.body == "new llm"

    def test_writes_when_no_existing(self, tmp_path):
        """First-time write proceeds even in respect-manual mode."""
        result = write_annotation(
            tmp_path,
            Annotation(
                file="x.py", function="brand_new", body="first record",
                metadata={"source": "llm"},
            ),
            overwrite="respect-manual",
        )
        assert result is not None

    def test_writes_when_existing_has_no_source_metadata(self, tmp_path):
        """Legacy annotations without ``source`` metadata aren't
        protected — they predate the convention. Only an explicit
        ``source=human`` triggers the skip."""
        write_annotation(tmp_path, Annotation(
            file="x.py", function="f", body="legacy", metadata={},
        ))
        result = write_annotation(
            tmp_path,
            Annotation(
                file="x.py", function="f", body="new content",
                metadata={"source": "llm"},
            ),
            overwrite="respect-manual",
        )
        assert result is not None
        got = read_annotation(tmp_path, "x.py", "f")
        assert got.body == "new content"

    def test_skip_does_not_affect_siblings(self, tmp_path):
        """Skipping one section's write must NOT touch other sections
        in the same file."""
        write_annotation(tmp_path, Annotation(
            file="x.py", function="alpha",
            body="manual alpha",
            metadata={"source": "human"},
        ))
        write_annotation(tmp_path, Annotation(
            file="x.py", function="beta",
            body="llm beta",
            metadata={"source": "llm"},
        ))
        # Try to overwrite alpha (should skip) and beta (should write)
        # in respect-manual mode.
        skipped = write_annotation(
            tmp_path,
            Annotation(
                file="x.py", function="alpha", body="llm overwrite",
                metadata={"source": "llm"},
            ),
            overwrite="respect-manual",
        )
        assert skipped is None
        wrote = write_annotation(
            tmp_path,
            Annotation(
                file="x.py", function="beta", body="llm beta v2",
                metadata={"source": "llm"},
            ),
            overwrite="respect-manual",
        )
        assert wrote is not None
        # Both annotations still in the file; alpha untouched, beta updated.
        all_ = read_file_annotations(tmp_path, "x.py")
        names = {a.function: a for a in all_}
        assert names["alpha"].body == "manual alpha"
        assert names["beta"].body == "llm beta v2"


# ---------------------------------------------------------------------------
# Invalid overwrite mode
# ---------------------------------------------------------------------------


class TestInvalidOverwriteMode:
    def test_rejects_unknown_mode(self, tmp_path):
        with pytest.raises(ValueError, match="invalid overwrite mode"):
            write_annotation(
                tmp_path,
                Annotation(file="x.py", function="f", body="x"),
                overwrite="bogus",
            )

    def test_rejects_empty_string(self, tmp_path):
        with pytest.raises(ValueError, match="invalid overwrite mode"):
            write_annotation(
                tmp_path,
                Annotation(file="x.py", function="f", body="x"),
                overwrite="",
            )


# ---------------------------------------------------------------------------
# compute_function_hash
# ---------------------------------------------------------------------------


class TestComputeFunctionHash:
    def test_stable_across_calls(self, tmp_path):
        src = tmp_path / "foo.py"
        src.write_text("def f():\n    return 1\n\ndef g():\n    return 2\n")
        h1 = compute_function_hash(src, 1, 2)
        h2 = compute_function_hash(src, 1, 2)
        assert h1 == h2
        assert len(h1) == 12  # short prefix
        assert all(c in "0123456789abcdef" for c in h1)

    def test_different_for_different_lines(self, tmp_path):
        src = tmp_path / "foo.py"
        src.write_text("def f():\n    return 1\n\ndef g():\n    return 2\n")
        h_f = compute_function_hash(src, 1, 2)
        h_g = compute_function_hash(src, 4, 5)
        assert h_f != h_g

    def test_changes_when_content_changes(self, tmp_path):
        src = tmp_path / "foo.py"
        src.write_text("def f():\n    return 1\n")
        h_before = compute_function_hash(src, 1, 2)
        src.write_text("def f():\n    return 99\n")
        h_after = compute_function_hash(src, 1, 2)
        assert h_before != h_after

    def test_missing_file_returns_empty(self, tmp_path):
        assert compute_function_hash(tmp_path / "nope.py", 1, 5) == ""

    def test_non_utf8_bytes_tolerated(self, tmp_path):
        """Non-UTF-8 source bytes shouldn't crash the hasher — the
        hash is for change-detection, not crypto. errors="replace"
        gives us a stable hash for whatever was on disk."""
        src = tmp_path / "weird.py"
        src.write_bytes(b"def f():\n    s = \"\xff\xfe\"\n")
        h = compute_function_hash(src, 1, 2)
        assert h != ""
        assert len(h) == 12

    def test_invalid_range_returns_empty(self, tmp_path):
        src = tmp_path / "foo.py"
        src.write_text("a\nb\nc\n")
        # start_line <= 0
        assert compute_function_hash(src, 0, 5) == ""
        assert compute_function_hash(src, -1, 5) == ""
        # end_line < start_line
        assert compute_function_hash(src, 5, 1) == ""

    def test_range_past_eof_clamps(self, tmp_path):
        """Asking for lines past EOF doesn't crash — clamp to file
        length and hash whatever's there."""
        src = tmp_path / "foo.py"
        src.write_text("only one line\n")
        h = compute_function_hash(src, 1, 1000)
        assert h != ""

    def test_empty_file_returns_empty(self, tmp_path):
        src = tmp_path / "empty.py"
        src.write_text("")
        assert compute_function_hash(src, 1, 5) == ""

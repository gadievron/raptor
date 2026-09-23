"""Tests for the package-shared sanitized source view.

``_source_view`` is the lexical substrate every verdict-relevant
text reader in source_intel must consume — comment/string content is
blanked (hostile-repo forgery defence) and reads are byte-capped (a
planted multi-GB "source file" must degrade, not sink memory).
"""

from __future__ import annotations

from pathlib import Path

from packages.source_intel._source_view import (
    MAX_SOURCE_BYTES,
    sanitized_lines,
    sanitized_source,
)


class TestSanitizedView:
    def test_comments_and_strings_blanked_lines_preserved(
        self, tmp_path: Path,
    ) -> None:
        src = tmp_path / "t.c"
        src.write_text(
            'int f(void)\n{\n\t/*\n}\n\t*/\n\tputs("}{");\n\treturn 0;\n}\n',
        )
        text = sanitized_source(str(src))
        assert text is not None
        lines = text.splitlines()
        assert len(lines) == 8, "line structure must map 1:1"
        # The comment-interior forged brace and the string braces are
        # blanked; the real braces survive.
        assert "}" not in lines[3]
        assert "}{" not in lines[5]
        assert lines[1] == "{"
        assert lines[7] == "}"

    def test_lines_view_matches_source_view(self, tmp_path: Path) -> None:
        src = tmp_path / "t.c"
        src.write_text("int x; // }\nint y;\n")
        text = sanitized_source(str(src))
        lines = sanitized_lines(str(src))
        assert text is not None and lines is not None
        assert "".join(lines) == text

    def test_unreadable_returns_none(self, tmp_path: Path) -> None:
        assert sanitized_source(str(tmp_path / "absent.c")) is None
        assert sanitized_lines(str(tmp_path / "absent.c")) is None

    def test_oversized_file_refused(self, tmp_path: Path) -> None:
        """Consumers' None path is their conservative direction — an
        oversized (planted) file degrades instead of being read
        whole."""
        big = tmp_path / "big.c"
        with big.open("w") as f:
            f.write("int aa;\n" * (MAX_SOURCE_BYTES // 8 + 16))
        assert sanitized_source(str(big)) is None
        assert sanitized_lines(str(big)) is None

    def test_mtime_size_keyed_cache_sees_rewrites(
        self, tmp_path: Path,
    ) -> None:
        import os

        src = tmp_path / "t.c"
        src.write_text("int first;\n")
        first = sanitized_source(str(src))
        src.write_text("int second_longer;\n")
        # Force a distinct mtime even on coarse-granularity filesystems.
        st = src.stat()
        os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
        second = sanitized_source(str(src))
        assert first is not None and second is not None
        assert first != second

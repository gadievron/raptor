"""Tests for core.source.contained — containment-checked, capped reads."""

import os
import sys

import pytest

from core.source import (
    read_bytes_capped,
    read_contained,
    read_text_capped,
)


class TestReadTextCapped:
    def test_full_read_within_cap(self, tmp_path):
        p = tmp_path / "a.txt"
        p.write_text("one\ntwo\n", encoding="utf-8")
        assert read_text_capped(p, 100) == ("one\ntwo\n", False)

    def test_over_cap_truncates_and_flags(self, tmp_path):
        p = tmp_path / "big.txt"
        p.write_text("aaaa\nbbbb\ncccc\n", encoding="utf-8")
        text, truncated = read_text_capped(p, 7)
        assert truncated is True
        # 7 chars = "aaaa\nbb" — the trailing partial line is dropped.
        assert text == "aaaa\n"

    def test_cap_boundary_exact_is_not_truncated(self, tmp_path):
        p = tmp_path / "exact.txt"
        p.write_text("abcde", encoding="utf-8")
        assert read_text_capped(p, 5) == ("abcde", False)

    def test_single_line_over_cap_keeps_prefix(self, tmp_path):
        # No newline in the capped read: keep the raw prefix rather
        # than degrade to "" (a pathological one-line file must not
        # read as empty).
        p = tmp_path / "oneline.txt"
        p.write_text("x" * 50, encoding="utf-8")
        text, truncated = read_text_capped(p, 10)
        assert truncated is True
        assert text == "x" * 10

    def test_missing_file_returns_none(self, tmp_path):
        assert read_text_capped(tmp_path / "nope.txt", 10) is None

    def test_non_utf8_bytes_replaced(self, tmp_path):
        p = tmp_path / "bin.txt"
        p.write_bytes(b"ok\n\xff\xfe\n")
        got = read_text_capped(p, 100)
        assert got is not None
        text, truncated = got
        assert truncated is False
        assert text.startswith("ok\n")


class TestReadBytesCapped:
    def test_full_read_within_cap(self, tmp_path):
        p = tmp_path / "a.bin"
        p.write_bytes(b"\x00\x01\x02")
        assert read_bytes_capped(p, 10) == (b"\x00\x01\x02", False)

    def test_over_cap_flags_truncated(self, tmp_path):
        p = tmp_path / "big.bin"
        p.write_bytes(b"abcdef")
        assert read_bytes_capped(p, 4) == (b"abcd", True)

    def test_exact_cap_not_truncated(self, tmp_path):
        p = tmp_path / "exact.bin"
        p.write_bytes(b"abcd")
        assert read_bytes_capped(p, 4) == (b"abcd", False)

    def test_missing_file_returns_none(self, tmp_path):
        assert read_bytes_capped(tmp_path / "nope.bin", 4) is None


class TestReadContained:
    def test_relative_path_reads(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.c").write_text("int x;\n", encoding="utf-8")
        assert read_contained(tmp_path, "src/a.c") == "int x;\n"

    def test_traversal_refused(self, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        root = tmp_path / "repo"
        root.mkdir()
        assert read_contained(root, "../outside.txt") is None

    def test_absolute_path_outside_root_refused(self, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        root = tmp_path / "repo"
        root.mkdir()
        assert read_contained(root, str(outside)) is None

    def test_absolute_path_inside_root_allowed(self, tmp_path):
        inside = tmp_path / "a.c"
        inside.write_text("ok", encoding="utf-8")
        assert read_contained(tmp_path, str(inside)) == "ok"

    @pytest.mark.skipif(
        sys.platform == "win32", reason="POSIX symlinks required")
    def test_symlink_escape_refused(self, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        root = tmp_path / "repo"
        root.mkdir()
        os.symlink(outside, root / "link.txt")
        assert read_contained(root, "link.txt") is None

    def test_directory_refused(self, tmp_path):
        (tmp_path / "d").mkdir()
        assert read_contained(tmp_path, "d") is None

    def test_missing_file_returns_none(self, tmp_path):
        assert read_contained(tmp_path, "nope.c") is None

    def test_over_cap_returns_capped_prefix(self, tmp_path):
        p = tmp_path / "big.c"
        p.write_text("line1\nline2\nline3\n", encoding="utf-8")
        assert read_contained(tmp_path, "big.c", max_chars=8) == "line1\n"


class TestRegularFileGuard:
    """The capped readers are the load-bearing chokepoint for
    hostile-repo-derived paths: a planted reader-less FIFO must not
    hang the analyser, and the regularity check must live on the
    OPENED fd (a by-name check races a swap)."""

    def test_fifo_refused_promptly(self, tmp_path):
        if not hasattr(os, "mkfifo"):
            pytest.skip("no mkfifo on this platform")
        fifo = tmp_path / "plant.c"
        os.mkfifo(fifo)
        # Pre-fix this open blocked forever (reader-less FIFO).
        assert read_text_capped(fifo) is None
        assert read_bytes_capped(fifo, 100) is None

    def test_final_component_symlink_refused(self, tmp_path):
        target = tmp_path / "real.c"
        target.write_text("int x;")
        link = tmp_path / "link.c"
        link.symlink_to(target)
        assert read_text_capped(link) is None
        assert read_bytes_capped(link, 100) is None

    def test_read_contained_still_reads_in_root_symlink(self, tmp_path):
        # read_contained resolves via confine() before the open, so a
        # legitimate in-root symlink keeps working — only the raw
        # capped readers refuse final-component symlinks.
        target = tmp_path / "real.c"
        target.write_text("int x;")
        link = tmp_path / "link.c"
        link.symlink_to(target)
        assert read_contained(tmp_path, "link.c") == "int x;"

    def test_directory_refused(self, tmp_path):
        assert read_text_capped(tmp_path) is None
        assert read_bytes_capped(tmp_path, 100) is None

    def test_regular_file_still_reads(self, tmp_path):
        p = tmp_path / "ok.c"
        p.write_text("int y;")
        assert read_text_capped(p) == ("int y;", False)
        assert read_bytes_capped(p, 100) == (b"int y;", False)


class TestReadContainedBytes:
    def test_reads_binary(self, tmp_path):
        from core.source.contained import read_contained_bytes
        (tmp_path / "a.bin").write_bytes(b"\x00\x01\x02")
        assert read_contained_bytes(tmp_path, "a.bin", 16) == (
            b"\x00\x01\x02", False)

    def test_over_cap_flags_truncated(self, tmp_path):
        from core.source.contained import read_contained_bytes
        (tmp_path / "a.bin").write_bytes(b"abcdef")
        assert read_contained_bytes(tmp_path, "a.bin", 4) == (b"abcd", True)

    def test_escape_refused(self, tmp_path):
        from core.source.contained import read_contained_bytes
        root = tmp_path / "root"
        root.mkdir()
        (tmp_path / "secret.bin").write_bytes(b"SECRET")
        assert read_contained_bytes(root, "../secret.bin", 64) is None
        assert read_contained_bytes(
            root, tmp_path / "secret.bin", 64) is None

    def test_fifo_refused(self, tmp_path):
        from core.source.contained import read_contained_bytes
        os.mkfifo(tmp_path / "wedge.bin")
        assert read_contained_bytes(tmp_path, "wedge.bin", 64) is None


class TestReadContainedEncoding:
    def test_utf8_decoding_is_locale_independent(self, tmp_path):
        """read_contained decodes utf-8 explicitly — under a C locale
        the fdopen default would mojibake multibyte content into
        prompts/reports. Exercised in a child forced to the C locale
        with UTF-8 mode off (the parent's locale can't prove it)."""
        import os
        import subprocess
        import sys
        from pathlib import Path

        (tmp_path / "u.c").write_bytes("// héllo\n".encode())
        repo = Path(__file__).resolve().parents[3]
        code = (
            "import sys; sys.path.insert(0, sys.argv[1])\n"
            "from core.source.contained import read_contained\n"
            "got = read_contained(sys.argv[2], 'u.c')\n"
            "assert got == '// h\\xe9llo\\n', repr(got)\n"
        )
        env = {**os.environ, "LC_ALL": "C",
               "PYTHONCOERCECLOCALE": "0", "PYTHONUTF8": "0"}
        env.pop("PYTHONIOENCODING", None)
        proc = subprocess.run(
            [sys.executable, "-c", code, str(repo), str(tmp_path)],
            env=env, capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, proc.stderr


class TestAnchoredContainment:
    """The intermediate-swap residual is CLOSED: a directory swapped
    for an out-of-tree symlink between confine()'s resolve and the
    open refuses instead of steering the read out of root."""

    def _swap_tree(self, tmp_path):
        root = tmp_path / "root"
        (root / "mid").mkdir(parents=True)
        (root / "mid" / "leaf.txt").write_text("benign")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "leaf.txt").write_text("SECRET")
        return root, outside

    def test_swap_between_confine_and_open_refuses(
            self, tmp_path, monkeypatch):
        """Deterministic race: perform the swap INSIDE the confine
        seam, after resolution succeeds and before the open runs —
        the exact interleaving the docstring previously documented
        as an open residual. The by-name open this replaced read
        the out-of-tree SECRET here."""
        from core.source import contained
        root, outside = self._swap_tree(tmp_path)
        real_confine = contained.confine

        def confine_then_swap(base, candidate):
            resolved = real_confine(base, candidate)
            if resolved is not None:
                (root / "mid").rename(tmp_path / "mid-evicted")
                (root / "mid").symlink_to(outside)
            return resolved

        monkeypatch.setattr(contained, "confine", confine_then_swap)
        assert contained.read_contained(root, "mid/leaf.txt") is None

    def test_swap_refuses_bytes_flavor_too(self, tmp_path, monkeypatch):
        from core.source import contained
        root, outside = self._swap_tree(tmp_path)
        real_confine = contained.confine

        def confine_then_swap(base, candidate):
            resolved = real_confine(base, candidate)
            if resolved is not None:
                (root / "mid").rename(tmp_path / "mid-evicted")
                (root / "mid").symlink_to(outside)
            return resolved

        monkeypatch.setattr(contained, "confine", confine_then_swap)
        assert contained.read_contained_bytes(
            root, "mid/leaf.txt", 64) is None

    def test_benign_nested_read_still_works(self, tmp_path):
        from core.source.contained import read_contained
        root, _ = self._swap_tree(tmp_path)
        assert read_contained(root, "mid/leaf.txt") == "benign"

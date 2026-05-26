"""Tests for the core.archive facade — detection, Tier-1 extraction, hardening."""

import bz2
import gzip
import io
import lzma
import tarfile
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from core.archive import (
    DecompressionLimitExceeded,
    UnsupportedArchive,
    detect_format,
    extract_to_dir,
    is_archive,
)
from core.archive.errors import ArchiveError


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)


def _tar(path, entries, mode="w"):
    with tarfile.open(path, mode) as t:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))


def _files(root: Path):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


class TestDetect(unittest.TestCase):

    def test_each_format_by_magic_not_extension(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            _zip(d / "a.zip", {"f": b"x"})
            _tar(d / "a.tar", {"f": b"x"}, mode="w")
            _tar(d / "a.tgz", {"f": b"x"}, mode="w:gz")
            with gzip.open(d / "f.gz", "wb") as f:
                f.write(b"x")
            with lzma.open(d / "f.xz", "wb") as f:
                f.write(b"x")
            with bz2.open(d / "f.bz2", "wb") as f:
                f.write(b"x")
            self.assertEqual(detect_format(d / "a.zip"), "zip")
            self.assertEqual(detect_format(d / "a.tar"), "tar")
            self.assertEqual(detect_format(d / "a.tgz"), "gz")   # outer compressor
            self.assertEqual(detect_format(d / "f.gz"), "gz")
            self.assertEqual(detect_format(d / "f.xz"), "xz")
            self.assertEqual(detect_format(d / "f.bz2"), "bz2")

    def test_extension_lies_content_wins(self):
        # A plain text file named .zip is NOT detected as zip.
        with TemporaryDirectory() as d:
            p = Path(d) / "fake.zip"
            p.write_text("not actually a zip")
            self.assertIsNone(detect_format(p))
            self.assertFalse(is_archive(p))

    def test_missing_and_empty(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(detect_format(Path(d) / "nope"))
            empty = Path(d) / "e"
            empty.write_bytes(b"")
            self.assertIsNone(detect_format(empty))


class TestExtract(unittest.TestCase):

    def test_zip_extracts_files_skips_dirs(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            _zip(d / "a.zip", {"src/x.py": b"print()\n", "dir/": b""})
            out = d / "out"
            stats = extract_to_dir(d / "a.zip", out)
            self.assertEqual(stats["format"], "zip")
            self.assertEqual(_files(out), ["src/x.py"])

    def test_plain_tar(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            _tar(d / "a.tar", {"a/b.txt": b"hi"}, mode="w")
            out = d / "out"
            extract_to_dir(d / "a.tar", out)
            self.assertEqual(_files(out), ["a/b.txt"])

    def test_compressed_tar_routes_to_tar_not_single_file(self):
        # A .tar.gz must extract its members, NOT write one "a.tar" blob.
        with TemporaryDirectory() as d:
            d = Path(d)
            _tar(d / "a.tar.gz", {"src/y.py": b"y\n"}, mode="w:gz")
            out = d / "out"
            extract_to_dir(d / "a.tar.gz", out)
            self.assertEqual(_files(out), ["src/y.py"])

    def test_single_gz_strips_suffix(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            with gzip.open(d / "notes.txt.gz", "wb") as f:
                f.write(b"hello\n")
            out = d / "out"
            extract_to_dir(d / "notes.txt.gz", out)
            self.assertEqual(_files(out), ["notes.txt"])
            self.assertEqual((out / "notes.txt").read_bytes(), b"hello\n")

    def test_non_archive_raises(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "plain.txt"
            p.write_text("nope")
            with self.assertRaises(UnsupportedArchive):
                extract_to_dir(p, Path(d) / "out")


class TestHardening(unittest.TestCase):

    def test_zip_slip_member_not_written_outside_dest(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            zp = d / "evil.zip"
            with zipfile.ZipFile(zp, "w") as z:
                z.writestr(zipfile.ZipInfo("../../escape.txt"), b"pwned")
                z.writestr("safe.txt", b"ok")
            out = d / "out"
            extract_to_dir(zp, out)
            # The traversal member is dropped; nothing escapes dest.
            self.assertFalse((d / "escape.txt").exists())
            self.assertFalse((out.parent / "escape.txt").exists())
            self.assertEqual(_files(out), ["safe.txt"])

    def test_file_count_cap(self):
        # tar has no built-in entry cap, so _write_members enforces it.
        with TemporaryDirectory() as d:
            d = Path(d)
            _tar(d / "many.tar", {f"f{i}": b"x" for i in range(5)}, mode="w")
            with self.assertRaises(DecompressionLimitExceeded):
                extract_to_dir(d / "many.tar", d / "out", max_files=2)

    def test_total_size_cap(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            _zip(d / "big.zip", {"f": b"x" * 100})
            with self.assertRaises(DecompressionLimitExceeded):
                extract_to_dir(d / "big.zip", d / "out", max_total_bytes=10)

    def test_single_file_decompression_bomb_capped(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            with gzip.open(d / "bomb.gz", "wb") as f:
                f.write(b"A" * 10000)
            with self.assertRaises(DecompressionLimitExceeded):
                extract_to_dir(d / "bomb.gz", d / "out", max_total_bytes=100)

    def test_corrupt_stream_raises_archive_error(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            # Valid gzip magic, garbage body.
            (d / "broken.gz").write_bytes(b"\x1f\x8b\x08" + b"\x00\xff\xab\xcd" * 4)
            with self.assertRaises(ArchiveError):
                extract_to_dir(d / "broken.gz", d / "out")

    def test_nul_byte_member_dropped_not_crash(self):
        # A NUL byte in a name makes resolve()/open() raise ValueError; the
        # member must be DROPPED (not crash extraction), with good members
        # still written. (Real zip/tar parsers strip NUL, but defend anyway.)
        from core.archive.extract import _safe_dest_path, _write_members
        with TemporaryDirectory() as d:
            out = Path(d)
            self.assertIsNone(_safe_dest_path(out, "a\x00b"))
            stats = _write_members({"a\x00b": b"x", "good.txt": b"ok"}, out, 1 << 20, 100)
            self.assertEqual(stats["files"], 1)
            self.assertTrue((out / "good.txt").exists())


if __name__ == "__main__":
    unittest.main()

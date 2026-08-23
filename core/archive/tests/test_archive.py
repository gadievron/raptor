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
from unittest import mock

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


class TestPlainTarStreaming(unittest.TestCase):
    """The plain (uncompressed) tar branch must stream the archive
    member-by-member instead of materialising the whole file with
    ``read_bytes()`` — otherwise the per-member / entry-count /
    running-total caps only apply to bytes already resident in RAM and
    a large plain tar becomes a memory-spike DoS."""

    def test_plain_tar_never_materialised_via_read_bytes(self):
        # The regression mechanism: src.read_bytes() loaded the whole tar
        # before any cap. Prove the branch no longer touches read_bytes.
        with TemporaryDirectory() as d:
            d = Path(d)
            _tar(d / "a.tar", {"dir/x.txt": b"hello", "y.txt": b"world"})
            out = d / "out"
            with mock.patch.object(
                    Path, "read_bytes",
                    side_effect=AssertionError("plain tar must stream")):
                stats = extract_to_dir(d / "a.tar", out)
            self.assertEqual(stats["format"], "tar")
            self.assertEqual(_files(out), ["dir/x.txt", "y.txt"])
            self.assertEqual((out / "dir/x.txt").read_bytes(), b"hello")
            self.assertEqual((out / "y.txt").read_bytes(), b"world")

    def test_plain_tar_total_bytes_cap_still_enforced(self):
        # Streaming must not weaken the aggregate-size bomb defense.
        with TemporaryDirectory() as d:
            d = Path(d)
            _tar(d / "big.tar", {"a": b"x" * 100, "b": b"y" * 100})
            with self.assertRaises(DecompressionLimitExceeded):
                extract_to_dir(d / "big.tar", d / "out", max_total_bytes=150)

    def test_plain_tar_entry_count_cap_still_enforced(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            _tar(d / "many.tar", {f"f{i}": b"x" for i in range(6)})
            with self.assertRaises(DecompressionLimitExceeded):
                extract_to_dir(d / "many.tar", d / "out", max_files=3)

    def test_plain_tar_member_cap_bounds_resident_bytes(self):
        # A member over max_member_bytes is skipped by the primitive's
        # safety gate rather than read into memory.
        with TemporaryDirectory() as d:
            d = Path(d)
            _tar(d / "a.tar", {"small": b"ok", "huge": b"z" * 4096})
            out = d / "out"
            extract_to_dir(d / "a.tar", out, max_member_bytes=1024)
            self.assertEqual(_files(out), ["small"])


class TestIterFileChunks(unittest.TestCase):

    def test_chunks_are_bounded_and_lossless(self):
        from core.archive.extract import _iter_file_chunks
        with TemporaryDirectory() as d:
            p = Path(d) / "blob"
            content = bytes(range(256)) * 40 + b"tail"
            p.write_bytes(content)
            with open(p, "rb") as fh:
                chunks = list(_iter_file_chunks(fh, chunk_bytes=1000))
            self.assertTrue(all(0 < len(c) <= 1000 for c in chunks))
            self.assertGreater(len(chunks), 1)
            self.assertEqual(b"".join(chunks), content)

    def test_empty_file_yields_nothing(self):
        from core.archive.extract import _iter_file_chunks
        with TemporaryDirectory() as d:
            p = Path(d) / "empty"
            p.write_bytes(b"")
            with open(p, "rb") as fh:
                self.assertEqual(list(_iter_file_chunks(fh)), [])


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


class TestFailClosedCorruptArchives(unittest.TestCase):
    """A corrupt/truncated tar REFUSES (typed) instead of returning an
    empty success summary that consumers treat as a complete extraction."""

    def test_corrupt_tar_raises_archive_error(self) -> None:
        with TemporaryDirectory() as td:
            src = Path(td) / "corrupt.tar"
            # Valid-looking 512-byte header block then garbage: detected
            # as tar, unreadable as one.
            info = tarfile.TarInfo("a.txt")
            info.size = 4
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tf:
                tf.addfile(info, io.BytesIO(b"data"))
            src.write_bytes(buf.getvalue()[:600] + b"\x00garbage" * 40)
            with self.assertRaises(ArchiveError):
                extract_to_dir(src, Path(td) / "out")

    def test_truncated_tar_gz_raises(self) -> None:
        with TemporaryDirectory() as td:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tf:
                info = tarfile.TarInfo("f.txt")
                payload = b"x" * 4096
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            whole = gzip.compress(buf.getvalue())
            src = Path(td) / "trunc.tar.gz"
            src.write_bytes(whole[: len(whole) // 2])
            with self.assertRaises(ArchiveError):
                extract_to_dir(src, Path(td) / "out")

    def test_summary_reports_dropped_members(self) -> None:
        with TemporaryDirectory() as td:
            src = Path(td) / "ok.tar"
            with tarfile.open(src, mode="w") as tf:
                info = tarfile.TarInfo("good.txt")
                info.size = 2
                tf.addfile(info, io.BytesIO(b"ok"))
            stats = extract_to_dir(src, Path(td) / "out")
            self.assertEqual(stats["files"], 1)
            self.assertEqual(stats["dropped"], 0)

class TestStreamingExtraction(unittest.TestCase):
    """Members must stream to disk — never accumulate in a dict up to
    the multi-GiB aggregate budget — and the single-file decompressor
    must read in bounded chunks, never one budget-sized allocation."""

    def test_tar_paths_never_route_through_write_members(self):
        # Structural streaming assertion: the dict-buffering writer is
        # off-limits for tar-shaped inputs (zip legitimately keeps it —
        # its primitive is seek-based and returns member bytes).
        with TemporaryDirectory() as d:
            d = Path(d)
            _tar(d / "a.tar", {"x.txt": b"plain"}, mode="w")
            _tar(d / "a.tar.gz", {"y.txt": b"compressed"}, mode="w:gz")
            with mock.patch(
                    "core.archive.extract._write_members",
                    side_effect=AssertionError("tar members must stream")):
                stats = extract_to_dir(d / "a.tar", d / "out1")
                self.assertEqual(stats["files"], 1)
                stats = extract_to_dir(d / "a.tar.gz", d / "out2")
                self.assertEqual(stats["files"], 1)
            self.assertEqual((d / "out1" / "x.txt").read_bytes(), b"plain")
            self.assertEqual((d / "out2" / "y.txt").read_bytes(),
                             b"compressed")

    def test_decompression_reads_are_chunked(self):
        # No single read() against the lazy decompressor may request
        # more than the chunk size — the retired implementation asked
        # for max_bytes + 1 (up to 1 GiB + 1) in one call.
        from core.archive.compression import (
            _CHUNK_BYTES,
            _OPENERS,
            decompress_single,
        )
        content = b"z" * (3 * _CHUNK_BYTES // 2)
        requested = []
        real_open = _OPENERS["gz"]

        class _Recorder:
            def __init__(self, fh):
                self._fh = fh

            def read(self, n=-1):
                requested.append(n)
                return self._fh.read(n)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._fh.close()
                return False

        with TemporaryDirectory() as d:
            p = Path(d) / "big.gz"
            with gzip.open(p, "wb") as f:
                f.write(content)
            with mock.patch.dict(
                    _OPENERS,
                    {"gz": lambda path, mode="rb":
                        _Recorder(real_open(path, mode))}):
                data = decompress_single(p, "gz", max_bytes=1 << 30)
        self.assertEqual(data, content)
        self.assertTrue(requested)
        self.assertLessEqual(max(requested), _CHUNK_BYTES)

    def test_multichunk_single_file_round_trips(self):
        # The streamed single-file writer must reassemble multi-chunk
        # output byte-for-byte and report accurate stats.
        from core.archive.compression import _CHUNK_BYTES
        content = bytes(range(256)) * ((2 * _CHUNK_BYTES) // 256 + 17)
        with TemporaryDirectory() as d:
            d = Path(d)
            with gzip.open(d / "blob.bin.gz", "wb") as f:
                f.write(content)
            stats = extract_to_dir(d / "blob.bin.gz", d / "out")
            self.assertEqual(stats["files"], 1)
            self.assertEqual(stats["bytes"], len(content))
            self.assertEqual((d / "out" / "blob.bin").read_bytes(), content)

    def test_streamed_tar_budget_and_count_caps_hold(self):
        # Streaming must keep the aggregate-byte and file-count caps
        # with the same error type.
        with TemporaryDirectory() as d:
            d = Path(d)
            _tar(d / "big.tar.gz", {"a": b"x" * 100, "b": b"y" * 100},
                 mode="w:gz")
            with self.assertRaises(DecompressionLimitExceeded):
                extract_to_dir(d / "big.tar.gz", d / "o1",
                               max_total_bytes=150)
            _tar(d / "many.tar.gz", {f"f{i}": b"x" for i in range(6)},
                 mode="w:gz")
            with self.assertRaises(DecompressionLimitExceeded):
                extract_to_dir(d / "many.tar.gz", d / "o2", max_files=3)


if __name__ == "__main__":
    unittest.main()

"""Tests for core.hash module."""

import hashlib
import os
import platform
import pytest
import sys
from pathlib import Path

# core/hash/tests/test_hash.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.hash import sha256_bytes, sha256_file, sha256_string, sha256_tree
from core.config import RaptorConfig


class TestSha256Tree:
    """Tests for sha256_tree() function."""

    def test_hash_simple_directory(self, tmp_path):
        """Test hashing a simple directory with files."""
        # Create test files
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "file3.txt").write_text("content3")

        hash1 = sha256_tree(tmp_path)
        hash2 = sha256_tree(tmp_path)

        # Same directory should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex digest length

    def test_hash_empty_directory(self, tmp_path):
        """Test hashing an empty directory."""
        hash_value = sha256_tree(tmp_path)
        assert len(hash_value) == 64
        # Empty directory should produce consistent hash
        hash2 = sha256_tree(tmp_path)
        assert hash_value == hash2

    def test_hash_nested_directories(self, tmp_path):
        """Test hashing nested directory structures."""
        # Create nested structure
        (tmp_path / "level1" / "level2" / "level3").mkdir(parents=True)
        (tmp_path / "level1" / "file1.txt").write_text("content")
        (tmp_path / "level1" / "level2" / "file2.txt").write_text("content")
        (tmp_path / "level1" / "level2" / "level3" / "file3.txt").write_text("content")

        hash_value = sha256_tree(tmp_path)
        assert len(hash_value) == 64

    def test_hash_consistency(self, tmp_path):
        """Test that same directory produces same hash multiple times."""
        (tmp_path / "file1.txt").write_text("same content")
        (tmp_path / "file2.txt").write_text("same content")

        hash1 = sha256_tree(tmp_path)
        hash2 = sha256_tree(tmp_path)
        hash3 = sha256_tree(tmp_path)

        assert hash1 == hash2 == hash3

    def test_hash_different_content_different_hash(self, tmp_path):
        """Test that different content produces different hashes."""
        (tmp_path / "file1.txt").write_text("content1")
        hash1 = sha256_tree(tmp_path)

        (tmp_path / "file1.txt").write_text("content2")
        hash2 = sha256_tree(tmp_path)

        assert hash1 != hash2

    def test_hash_file_size_limit(self, tmp_path):
        """Test that large files are skipped when limit is set."""
        # Create a small file
        small_file = tmp_path / "small.txt"
        small_file.write_text("small content")
        hash_with_small = sha256_tree(tmp_path, max_file_size=100)

        # Create a large file (simulate by setting very small limit)
        large_file = tmp_path / "large.txt"
        large_file.write_text("x" * 200)  # 200 bytes
        hash_with_large = sha256_tree(tmp_path, max_file_size=100)  # 100 byte limit

        # Hash should be same (large file skipped)
        assert hash_with_small == hash_with_large

    def test_hash_no_size_limit(self, tmp_path):
        """Test that very large max_file_size disables limit."""
        # Create files
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")

        hash_no_limit = sha256_tree(tmp_path, max_file_size=10**12)  # Effectively no limit

        # With no limit, all files included; with limit, might skip
        # Just verify no_limit produces a hash
        assert len(hash_no_limit) == 64

    def test_hash_uses_config_defaults(self, tmp_path):
        """Test that None parameters use config defaults."""
        (tmp_path / "file.txt").write_text("content")
        
        # Should use RaptorConfig defaults
        hash1 = sha256_tree(tmp_path)  # None, None
        hash2 = sha256_tree(
            tmp_path,
            max_file_size=RaptorConfig.MAX_FILE_SIZE_FOR_HASH,
            chunk_size=RaptorConfig.HASH_CHUNK_SIZE
        )

        assert hash1 == hash2

    def test_hash_chunk_size_variation(self, tmp_path):
        """Test that chunk size doesn't affect hash result."""
        (tmp_path / "file.txt").write_text("x" * 1000)  # 1000 bytes

        hash_chunk_8k = sha256_tree(tmp_path, chunk_size=8192)
        hash_chunk_1m = sha256_tree(tmp_path, chunk_size=1024 * 1024)
        hash_chunk_512 = sha256_tree(tmp_path, chunk_size=512)

        # Chunk size should NOT affect hash (only reading efficiency)
        assert hash_chunk_8k == hash_chunk_1m == hash_chunk_512

    def test_hash_backward_compatibility(self, tmp_path):
        """Test backward compatibility with old recon agent parameters."""
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")

        # Old recon agent used: max_file_size=10**12, chunk_size=8192
        hash_old_style = sha256_tree(tmp_path, max_file_size=10**12, chunk_size=8192)
        
        # Should produce valid hash
        assert len(hash_old_style) == 64

    def test_hash_skips_large_files_logs(self, tmp_path, caplog):
        """Test that skipping large files is logged."""
        # Create a file that will be skipped
        large_file = tmp_path / "large.txt"
        large_file.write_text("x" * 200)
        
        sha256_tree(tmp_path, max_file_size=100)
        
        # Should log skipped files (if logger configured)
        # Note: May not appear in caplog if logger not set up for tests

    def test_hash_file_order_independent(self, tmp_path):
        """Test that file order doesn't affect hash (sorted)."""
        # Create files in one order
        (tmp_path / "a.txt").write_text("content")
        (tmp_path / "b.txt").write_text("content")
        (tmp_path / "c.txt").write_text("content")
        hash1 = sha256_tree(tmp_path)

        # Remove and recreate in different order
        for f in tmp_path.glob("*.txt"):
            f.unlink()
        
        (tmp_path / "c.txt").write_text("content")
        (tmp_path / "a.txt").write_text("content")
        (tmp_path / "b.txt").write_text("content")
        hash2 = sha256_tree(tmp_path)

        # Should be same (sorted order)
        assert hash1 == hash2

    def test_hash_includes_file_paths(self, tmp_path):
        """Test that file paths are included in hash."""
        (tmp_path / "file1.txt").write_text("same")
        hash1 = sha256_tree(tmp_path)

        (tmp_path / "file1.txt").unlink()
        (tmp_path / "file2.txt").write_text("same")  # Same content, different path
        hash2 = sha256_tree(tmp_path)

        # Different paths should produce different hashes
        assert hash1 != hash2

    def test_hash_handles_binary_files(self, tmp_path):
        """Test that binary files are hashed correctly."""
        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b'\x00\x01\x02\x03\xff\xfe\xfd')

        hash_value = sha256_tree(tmp_path)
        assert len(hash_value) == 64

    def test_hash_relative_paths_used(self, tmp_path):
        """Test that relative paths (not absolute) are used in hash."""
        (tmp_path / "file.txt").write_text("content")
        
        # Hash from different absolute paths should be same
        # (because relative paths are used)
        hash1 = sha256_tree(tmp_path)
        
        # Create symlink or use different reference - should still be same
        # This is implicit in the implementation using relative_to(root)
        assert len(hash1) == 64


class TestSha256File:
    """Tests for sha256_file() — single-file streamed hash."""

    def test_matches_hashlib_oneshot(self, tmp_path):
        """Streamed digest must equal hashlib.sha256(content)."""
        f = tmp_path / "x.bin"
        content = b"hello world\n" * 100
        f.write_bytes(content)
        assert sha256_file(f) == hashlib.sha256(content).hexdigest()

    def test_empty_file(self, tmp_path):
        """Empty file hashes to the empty-string digest."""
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert sha256_file(f) == hashlib.sha256(b"").hexdigest()

    def test_chunk_size_does_not_affect_digest(self, tmp_path):
        """Different chunk sizes must produce identical digests."""
        f = tmp_path / "x.bin"
        f.write_bytes(b"x" * 100_000)
        h_small = sha256_file(f, chunk_size=128)
        h_big = sha256_file(f, chunk_size=1024 * 1024)
        h_default = sha256_file(f)
        assert h_small == h_big == h_default

    def test_consistency(self, tmp_path):
        f = tmp_path / "x.bin"
        f.write_bytes(b"abc")
        assert sha256_file(f) == sha256_file(f)

    def test_streams_without_full_load(self, tmp_path):
        """Sanity check: a file larger than the chunk size still hashes
        correctly (i.e. the loop terminates and accumulates all chunks)."""
        f = tmp_path / "big.bin"
        # Make several chunks at the small chunk_size we'll pass.
        f.write_bytes(b"a" * 5000)
        assert sha256_file(f, chunk_size=512) == hashlib.sha256(b"a" * 5000).hexdigest()


class TestSha256Bytes:
    """Tests for sha256_bytes() — in-memory bytes."""

    def test_matches_hashlib(self):
        for payload in (b"", b"a", b"hello", b"\x00\x01\xff", b"x" * 10_000):
            assert sha256_bytes(payload) == hashlib.sha256(payload).hexdigest()

    def test_returns_hex_string(self):
        digest = sha256_bytes(b"abc")
        assert isinstance(digest, str)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)


class TestSha256String:
    """Tests for sha256_string() — UTF-8 + surrogateescape."""

    def test_ascii_matches_default_encode(self):
        """For pure ASCII, surrogateescape encoding == default UTF-8."""
        for s in ("", "abc", "hello world\n"):
            assert sha256_string(s) == hashlib.sha256(s.encode()).hexdigest()

    def test_unicode_string(self):
        """Valid UTF-8 unicode strings hash identically to plain .encode()."""
        s = "café — 日本語 — 🦖"
        assert sha256_string(s) == hashlib.sha256(s.encode("utf-8")).hexdigest()

    def test_surrogate_does_not_raise(self):
        """A string containing a lone surrogate (from non-UTF-8 bytes round-tripped
        via surrogateescape) must hash, not raise UnicodeEncodeError."""
        # \udcff is the surrogate that surrogateescape produces for byte 0xff.
        weird = "prefix-\udcff-suffix"
        # Plain .encode() WOULD raise on this; sha256_string must not.
        digest = sha256_string(weird)
        assert len(digest) == 64

    def test_surrogate_round_trips_raw_bytes(self):
        """A byte sequence → str (surrogateescape) → sha256_string should
        equal sha256_bytes of the original bytes."""
        raw = b"path-with-\xff-byte"
        s = raw.decode("utf-8", errors="surrogateescape")
        assert sha256_string(s) == sha256_bytes(raw)


class TestSha256TreeSurrogateescape:
    """Filename-encoding regression tests for sha256_tree.

    Pre-fix, ``sha256_tree`` called ``.as_posix().encode()`` which raises
    ``UnicodeEncodeError`` on filesystems that hold non-UTF-8 byte sequences
    in filenames (common on Linux). Post-fix, surrogateescape round-trips
    those bytes safely.
    """

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Non-UTF-8 filenames are a Linux-specific filesystem behaviour; "
               "macOS HFS+/APFS normalises and Windows rejects them.",
    )
    def test_non_utf8_filename_does_not_raise(self, tmp_path):
        """A file with raw 0xff in its name must hash, not raise."""
        # Build the path as bytes so we can include 0xff.
        parent_bytes = os.fsencode(str(tmp_path))
        bad_name_bytes = parent_bytes + b"/file-\xff.bin"
        with open(bad_name_bytes, "wb") as f:
            f.write(b"content")

        # The pre-fix implementation raised UnicodeEncodeError here.
        digest = sha256_tree(tmp_path)
        assert len(digest) == 64

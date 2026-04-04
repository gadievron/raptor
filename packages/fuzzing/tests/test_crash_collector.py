"""Tests for packages/fuzzing/crash_collector.py."""

import hashlib
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.fuzzing.crash_collector import Crash, CrashCollector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_crash_file(directory: Path, name: str, content: bytes = b"crash data") -> Path:
    p = directory / name
    p.write_bytes(content)
    return p


# ---------------------------------------------------------------------------
# Crash dataclass
# ---------------------------------------------------------------------------

class TestCrashDataclass:

    def test_repr_contains_id_signal_size(self, tmp_path):
        f = _make_crash_file(tmp_path, "id:000001,sig:11")
        c = Crash(crash_id="000001", input_file=f, signal="11", size=10)
        r = repr(c)
        assert "000001" in r
        assert "11" in r
        assert "10" in r

    def test_optional_fields_default_to_none(self, tmp_path):
        f = _make_crash_file(tmp_path, "id:000000")
        c = Crash(crash_id="000000", input_file=f)
        assert c.signal is None
        assert c.stack_hash is None
        assert c.timestamp is None


# ---------------------------------------------------------------------------
# CrashCollector.__init__
# ---------------------------------------------------------------------------

class TestCrashCollectorInit:

    def test_raises_if_directory_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            CrashCollector(tmp_path / "nonexistent")

    def test_accepts_existing_directory(self, tmp_path):
        collector = CrashCollector(tmp_path)
        assert collector.crashes_dir == tmp_path


# ---------------------------------------------------------------------------
# collect_crashes()
# ---------------------------------------------------------------------------

class TestCollectCrashes:

    def test_empty_directory_returns_empty_list(self, tmp_path):
        collector = CrashCollector(tmp_path)
        assert collector.collect_crashes() == []

    def test_ignores_non_crash_files(self, tmp_path):
        (tmp_path / "README").write_text("not a crash")
        (tmp_path / "fuzzer_stats").write_text("stats")
        collector = CrashCollector(tmp_path)
        assert collector.collect_crashes() == []

    def test_collects_afl_crash_files(self, tmp_path):
        _make_crash_file(tmp_path, "id:000000,sig:11,src:000000,op:havoc,rep:4")
        _make_crash_file(tmp_path, "id:000001,sig:06,src:000000,op:havoc,rep:2", b"different")
        collector = CrashCollector(tmp_path)
        crashes = collector.collect_crashes()
        assert len(crashes) == 2

    def test_deduplicates_identical_content(self, tmp_path):
        content = b"identical crash content"
        _make_crash_file(tmp_path, "id:000000,sig:11", content)
        _make_crash_file(tmp_path, "id:000001,sig:11", content)
        collector = CrashCollector(tmp_path)
        crashes = collector.collect_crashes()
        # Both files have identical content → deduplicated to 1
        assert len(crashes) == 1

    def test_max_crashes_limits_collection(self, tmp_path):
        for i in range(5):
            _make_crash_file(tmp_path, f"id:{i:06d},sig:11", f"crash {i}".encode())
        collector = CrashCollector(tmp_path)
        crashes = collector.collect_crashes(max_crashes=2)
        assert len(crashes) <= 2

    def test_parses_crash_id_from_filename(self, tmp_path):
        _make_crash_file(tmp_path, "id:000042,sig:11,src:000000,op:havoc,rep:4")
        collector = CrashCollector(tmp_path)
        crashes = collector.collect_crashes()
        assert crashes[0].crash_id == "000042"

    def test_parses_signal_from_filename(self, tmp_path):
        _make_crash_file(tmp_path, "id:000000,sig:11,src:000000")
        collector = CrashCollector(tmp_path)
        crashes = collector.collect_crashes()
        assert crashes[0].signal == "11"

    def test_crash_has_size(self, tmp_path):
        _make_crash_file(tmp_path, "id:000000,sig:11", b"AAAA")
        collector = CrashCollector(tmp_path)
        crashes = collector.collect_crashes()
        assert crashes[0].size == 4

    def test_crash_has_timestamp(self, tmp_path):
        _make_crash_file(tmp_path, "id:000000,sig:11")
        collector = CrashCollector(tmp_path)
        crashes = collector.collect_crashes()
        assert crashes[0].timestamp is not None

    def test_crash_input_file_is_path(self, tmp_path):
        _make_crash_file(tmp_path, "id:000000,sig:11")
        collector = CrashCollector(tmp_path)
        crashes = collector.collect_crashes()
        assert isinstance(crashes[0].input_file, Path)


# ---------------------------------------------------------------------------
# rank_crashes_by_exploitability()
# ---------------------------------------------------------------------------

class TestRankCrashes:

    def _make_crash(self, tmp_path, crash_id, signal, content=None):
        f = _make_crash_file(tmp_path, f"id:{crash_id},sig:{signal}",
                              content or crash_id.encode())
        return Crash(crash_id=crash_id, input_file=f, signal=signal, size=len(content or crash_id))

    def test_sigsegv_ranked_first(self, tmp_path):
        crashes = [
            self._make_crash(tmp_path, "001", "06"),   # SIGABRT
            self._make_crash(tmp_path, "002", "11"),   # SIGSEGV
            self._make_crash(tmp_path, "003", "04"),   # SIGILL
        ]
        collector = CrashCollector(tmp_path)
        ranked = collector.rank_crashes_by_exploitability(crashes)
        assert ranked[0].signal == "11"

    def test_unknown_signal_ranked_last(self, tmp_path):
        crashes = [
            self._make_crash(tmp_path, "001", "99"),   # unknown
            self._make_crash(tmp_path, "002", "11"),   # SIGSEGV
        ]
        collector = CrashCollector(tmp_path)
        ranked = collector.rank_crashes_by_exploitability(crashes)
        assert ranked[-1].signal == "99"

    def test_empty_list_returns_empty(self, tmp_path):
        collector = CrashCollector(tmp_path)
        assert collector.rank_crashes_by_exploitability([]) == []

    def test_preserves_all_crashes(self, tmp_path):
        crashes = [
            self._make_crash(tmp_path, "001", "11"),
            self._make_crash(tmp_path, "002", "06"),
            self._make_crash(tmp_path, "003", "04"),
        ]
        collector = CrashCollector(tmp_path)
        ranked = collector.rank_crashes_by_exploitability(crashes)
        assert len(ranked) == 3

    def test_signal_name_known_signals(self, tmp_path):
        collector = CrashCollector(tmp_path)
        assert "SIGSEGV" in collector._signal_name("11")
        assert "SIGABRT" in collector._signal_name("06")
        assert "SIGILL" in collector._signal_name("04")
        assert "SIGFPE" in collector._signal_name("08")

    def test_signal_name_unknown_signal(self, tmp_path):
        collector = CrashCollector(tmp_path)
        result = collector._signal_name("99")
        assert "99" in result

    def test_signal_name_none(self, tmp_path):
        collector = CrashCollector(tmp_path)
        result = collector._signal_name(None)
        assert "Unknown" in result


# ---------------------------------------------------------------------------
# _hash_file()
# ---------------------------------------------------------------------------

class TestHashFile:

    def test_returns_hex_string(self, tmp_path):
        f = tmp_path / "data"
        f.write_bytes(b"hello")
        collector = CrashCollector(tmp_path)
        h = collector._hash_file(f)
        assert isinstance(h, str)
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic(self, tmp_path):
        f = tmp_path / "data"
        f.write_bytes(b"hello world")
        collector = CrashCollector(tmp_path)
        assert collector._hash_file(f) == collector._hash_file(f)

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a"
        f2 = tmp_path / "b"
        f1.write_bytes(b"content a")
        f2.write_bytes(b"content b")
        collector = CrashCollector(tmp_path)
        assert collector._hash_file(f1) != collector._hash_file(f2)

    def test_returns_16_char_prefix(self, tmp_path):
        f = tmp_path / "data"
        f.write_bytes(b"test")
        collector = CrashCollector(tmp_path)
        assert len(collector._hash_file(f)) == 16

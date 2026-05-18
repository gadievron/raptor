"""Tests for packages/fuzzing/afl_runner.py."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.fuzzing.afl_runner import AFLRunner


class TestAFLRunnerStatsParsing(unittest.TestCase):

    def test_parse_afl_int_tolerates_stale_stats_formats(self):
        self.assertEqual(AFLRunner._parse_afl_int("56269"), 56269)
        self.assertEqual(AFLRunner._parse_afl_int("51000.00"), 51000)
        self.assertEqual(AFLRunner._parse_afl_int("100.00%"), 100)
        self.assertEqual(AFLRunner._parse_afl_int("N/A"), 0)

    def test_max_crash_execs_uses_afl_filename_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            crashes = Path(tmpdir)
            (crashes / "README.txt").write_text("ignored")
            (crashes / "id:000000,sig:11,src:000000,time:284,execs:562,op:havoc,rep:3").write_bytes(b"a")
            (crashes / "id:000001,sig:06,src:000020,time:31644,execs:56269,op:havoc,rep:6").write_bytes(b"b")

            self.assertEqual(AFLRunner._max_crash_execs(crashes), 56269)

    def test_paths_found_falls_back_to_current_afl_corpus_fields(self):
        self.assertEqual(AFLRunner._afl_paths_found({"paths_found": "3"}), 3)
        self.assertEqual(AFLRunner._afl_paths_found({"corpus_found": "7"}), 7)
        self.assertEqual(AFLRunner._afl_paths_found({"corpus_count": "8"}), 8)

    def test_sanitizer_detection_ignores_afl_weak_asan_symbol(self):
        self.assertFalse(AFLRunner._has_runtime_sanitizer("__asan_region_is_poisoned", "asan"))
        self.assertTrue(AFLRunner._has_runtime_sanitizer("__asan_init\n__asan_report_store1", "asan"))
        self.assertTrue(AFLRunner._has_runtime_sanitizer("__ubsan_handle_add_overflow", "ubsan"))


# ---------------------------------------------------------------------------
# _create_default_corpus()
# ---------------------------------------------------------------------------

class TestCreateDefaultCorpus:
    """The default-corpus path must be anchored to ``self.output_dir``,
    NOT to the current working directory.

    Regression: previously ``Path("out/corpus_default")`` was CWD-relative,
    so running ``/fuzz`` from inside a target tree planted seed files in
    ``<target>/out/corpus_default/``.
    """

    def _make_runner(self, output_dir: Path) -> AFLRunner:
        # Bypass __init__ — we don't need a real binary or AFL on PATH
        # for this unit test. Only output_dir matters for the method
        # under test.
        runner = AFLRunner.__new__(AFLRunner)
        runner.output_dir = output_dir
        return runner

    def test_corpus_anchored_to_output_dir_not_cwd(self, tmp_path):
        # Two distinct directories: where the runner lives vs the
        # operator's CWD when they invoke /fuzz.
        output_dir = tmp_path / "fuzz_run"
        output_dir.mkdir()
        cwd = tmp_path / "operator_cwd"
        cwd.mkdir()

        # Plain os.chdir + try/finally instead of monkeypatch.chdir():
        # monkeypatch.chdir calls os.getcwd() to remember the original
        # cwd, which fails in CI when a prior test left cwd dangling.
        # Anchor restoration to Path(__file__) (always absolute, no
        # cwd dependency).
        safe_restore = Path(__file__).resolve().parent
        os.chdir(cwd)
        try:
            runner = self._make_runner(output_dir)
            result = runner._create_default_corpus()
        finally:
            os.chdir(safe_restore)

        # Seeds land under output_dir.
        expected = output_dir / "corpus_default"
        assert result == expected
        assert expected.is_dir()
        for idx in range(4):
            seed = expected / f"seed{idx}"
            assert seed.is_file(), f"missing {seed}"

        # CWD is NOT polluted.
        assert not (cwd / "out").exists()
        assert not (cwd / "out" / "corpus_default").exists()

    def test_corpus_returns_absolute_path_under_output_dir(self, tmp_path):
        output_dir = tmp_path / "fuzz_run"
        output_dir.mkdir()

        runner = self._make_runner(output_dir)
        result = runner._create_default_corpus()

        # Path must be absolute and a child of output_dir (not
        # interpreted relative to CWD by some downstream consumer).
        assert result.is_absolute()
        assert output_dir in result.parents or result.parent == output_dir

    def test_seeds_have_expected_content(self, tmp_path):
        output_dir = tmp_path / "fuzz_run"
        output_dir.mkdir()

        runner = self._make_runner(output_dir)
        corpus = runner._create_default_corpus()

        assert (corpus / "seed0").read_bytes() == b"A" * 10
        assert (corpus / "seed1").read_bytes() == b"test\n"
        assert (corpus / "seed2").read_bytes() == b"\x00\x01\x02\x03"
        assert (corpus / "seed3").read_bytes() == b"GET / HTTP/1.0\r\n\r\n"

if __name__ == "__main__":
    unittest.main()
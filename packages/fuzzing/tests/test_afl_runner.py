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
        assert (expected / "manifest.json").is_file()
        assert (expected / "seed-0006-http-get").is_file()

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

        assert (corpus / "seed-0001-text-small").read_bytes() == b"test\n"
        assert b"GET /search" in (corpus / "seed-0006-http-get").read_bytes()
        assert b"STACK:" in (corpus / "seed-0014-command-prefixes").read_bytes()
        assert (corpus / "manifest.json").is_file()


# ---------------------------------------------------------------------------
# _merge_crash_files()
# ---------------------------------------------------------------------------

class TestMergeCrashFiles:
    """Crashes found by secondary instances must reach the returned
    crashes dir.

    Regression: run_fuzzing counted crashes across all parallel
    instances but returned only ``main/crashes``, so secondary-instance
    crashes were reported in the total yet never analysed.
    """

    def _make_runner(self, output_dir: Path) -> AFLRunner:
        runner = AFLRunner.__new__(AFLRunner)
        runner.output_dir = output_dir
        return runner

    def _plant_crash(self, output_dir: Path, instance: str, name: str,
                     payload: bytes) -> Path:
        crashes = output_dir / instance / "crashes"
        crashes.mkdir(parents=True, exist_ok=True)
        f = crashes / name
        f.write_bytes(payload)
        return f

    def test_main_only_crashes_keep_main_dir(self, tmp_path):
        runner = self._make_runner(tmp_path)
        self._plant_crash(tmp_path, "main",
                          "id:000000,sig:11,src:000000,op:havoc,rep:1", b"a")

        crash_files = runner._collect_all_crash_files()
        result = runner._merge_crash_files(crash_files)

        assert result == tmp_path / "main" / "crashes"
        assert not (tmp_path / "merged_crashes").exists()

    def test_secondary_crashes_are_merged(self, tmp_path):
        runner = self._make_runner(tmp_path)
        self._plant_crash(tmp_path, "main",
                          "id:000000,sig:11,src:000000,op:havoc,rep:1", b"a")
        # Same AFL id in a secondary — must not collide away.
        self._plant_crash(tmp_path, "secondary1",
                          "id:000000,sig:11,src:000000,op:havoc,rep:1", b"b")
        self._plant_crash(tmp_path, "secondary1",
                          "id:000001,sig:06,src:000002,op:havoc,rep:2", b"c")

        crash_files = runner._collect_all_crash_files()
        assert len(crash_files) == 3

        result = runner._merge_crash_files(crash_files)
        assert result == tmp_path / "merged_crashes"

        merged = sorted(result.iterdir())
        assert len(merged) == 3
        # CrashCollector filters on the id: prefix — every merged file
        # must keep it.
        assert all(f.name.startswith("id:") for f in merged)
        assert sorted(f.read_bytes() for f in merged) == [b"a", b"b", b"c"]

    def test_merge_is_idempotent(self, tmp_path):
        runner = self._make_runner(tmp_path)
        self._plant_crash(tmp_path, "main",
                          "id:000000,sig:11,src:000000,op:havoc,rep:1", b"a")
        self._plant_crash(tmp_path, "secondary1",
                          "id:000001,sig:06,src:000002,op:havoc,rep:2", b"b")

        crash_files = runner._collect_all_crash_files()
        first = runner._merge_crash_files(crash_files)
        second = runner._merge_crash_files(crash_files)

        assert first == second
        assert len(list(second.iterdir())) == 2


if __name__ == "__main__":
    unittest.main()

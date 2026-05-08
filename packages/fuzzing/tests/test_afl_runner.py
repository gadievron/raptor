"""Tests for packages/fuzzing/afl_runner.py."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.fuzzing.afl_runner import AFLRunner


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

    def test_corpus_anchored_to_output_dir_not_cwd(self, tmp_path, monkeypatch):
        # Two distinct directories: where the runner lives vs the
        # operator's CWD when they invoke /fuzz.
        output_dir = tmp_path / "fuzz_run"
        output_dir.mkdir()
        cwd = tmp_path / "operator_cwd"
        cwd.mkdir()

        monkeypatch.chdir(cwd)

        runner = self._make_runner(output_dir)
        result = runner._create_default_corpus()

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

    def test_corpus_returns_absolute_path_under_output_dir(self, tmp_path, monkeypatch):
        output_dir = tmp_path / "fuzz_run"
        output_dir.mkdir()
        monkeypatch.chdir(tmp_path)

        runner = self._make_runner(output_dir)
        result = runner._create_default_corpus()

        # Path must be a child of output_dir (not interpreted relative
        # to CWD by some downstream consumer).
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

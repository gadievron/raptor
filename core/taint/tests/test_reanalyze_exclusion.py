"""--reanalyze intake vs the taint engine's SARIF artifact.

The reanalyze fallback glob (``*.sarif`` over the previous run dir)
would pull ``crossfile-taint.sarif`` into the SARIF import lane —
re-ingesting engine findings as imported scanner findings, outside
their producer channel. The selection helper excludes the artifact by
exact filename on the glob lane; a run-recorded ``extra.sarif_files``
list is honoured verbatim.
"""

from __future__ import annotations

import sys
from pathlib import Path

# core/taint/tests/... -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from raptor_agentic import (  # noqa: E402
    _TAINT_SARIF_FILENAME,
    _reanalyze_sarif_selection,
)


def _run_dir(tmp_path: Path, names: list[str]) -> Path:
    d = tmp_path / "prev-run"
    d.mkdir()
    for name in names:
        (d / name).write_text("{}", encoding="utf-8")
    return d


class TestFallbackGlobShape:
    """No extra.sarif_files recorded — the glob lane."""

    def test_taint_artifact_excluded_from_glob(self, tmp_path):
        d = _run_dir(tmp_path, [
            "semgrep_results.sarif", _TAINT_SARIF_FILENAME,
            "codeql_python.sarif",
        ])
        selected = _reanalyze_sarif_selection(d, {})
        names = [Path(s).name for s in selected]
        assert _TAINT_SARIF_FILENAME not in names
        assert names == ["codeql_python.sarif", "semgrep_results.sarif"]

    def test_taint_only_run_dir_selects_nothing(self, tmp_path):
        # The caller's "no SARIF files found" error is the right
        # outcome for a taint-only dir: rerun with --taint-crossfile,
        # don't import the producer artifact.
        d = _run_dir(tmp_path, [_TAINT_SARIF_FILENAME])
        assert _reanalyze_sarif_selection(d, {}) == []

    def test_exact_name_only_no_pattern_widening(self, tmp_path):
        # Operator-imported artifacts with similar names must NOT be
        # dropped — the exclusion is by exact filename.
        d = _run_dir(tmp_path, [
            "my-crossfile-taint.sarif", "crossfile-taint-2.sarif",
        ])
        selected = _reanalyze_sarif_selection(d, {})
        assert len(selected) == 2

    def test_glob_sorted_and_complete_otherwise(self, tmp_path):
        d = _run_dir(tmp_path, ["b.sarif", "a.sarif"])
        selected = _reanalyze_sarif_selection(d, {})
        assert [Path(s).name for s in selected] == ["a.sarif", "b.sarif"]


class TestMetadataListShape:
    """extra.sarif_files recorded — honoured verbatim, glob never
    runs."""

    def test_recorded_list_wins_and_taint_artifact_ignored(
            self, tmp_path):
        d = _run_dir(tmp_path, [
            "semgrep_results.sarif", _TAINT_SARIF_FILENAME,
        ])
        meta = {"extra": {"sarif_files": ["semgrep_results.sarif"]}}
        selected = _reanalyze_sarif_selection(d, meta)
        assert [Path(s).name for s in selected] == [
            "semgrep_results.sarif"]

    def test_recorded_taint_name_is_honoured_verbatim(self, tmp_path):
        # The exclusion is a glob-lane defense only: a run that
        # explicitly RECORDED the artifact in its metadata said what
        # it meant, and the selection follows the record.
        d = _run_dir(tmp_path, [_TAINT_SARIF_FILENAME])
        meta = {"extra": {"sarif_files": [_TAINT_SARIF_FILENAME]}}
        selected = _reanalyze_sarif_selection(d, meta)
        assert [Path(s).name for s in selected] == [_TAINT_SARIF_FILENAME]

    def test_missing_recorded_files_fall_back_to_glob(self, tmp_path):
        # Every recorded file vanished → the glob fallback runs, with
        # the taint exclusion live.
        d = _run_dir(tmp_path, ["a.sarif", _TAINT_SARIF_FILENAME])
        meta = {"extra": {"sarif_files": ["gone.sarif"]}}
        selected = _reanalyze_sarif_selection(d, meta)
        assert [Path(s).name for s in selected] == ["a.sarif"]


class TestVocabularyPin:
    def test_filename_constant_matches_run_module(self):
        from core.taint.run import SARIF_FILENAME
        assert _TAINT_SARIF_FILENAME == SARIF_FILENAME
